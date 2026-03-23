//! Log event processor with multithreaded matching support.
//!
//! This module provides the LogProcessor which ingests log events in various formats
//! and matches them against compiled Sigma rules using multiple threads.
//!
//! # Example
//!
//! ```rust
//! use sigma_engine::{SigmaCollection, SigmaDocument, LogProcessor, LogEvent, LogSource};
//! use std::collections::HashMap;
//!
//! let yaml = r#"
//! title: Process Creation
//! logsource:
//!     product: windows
//!     category: process_creation
//! detection:
//!     selection:
//!         EventID: 4688
//!     condition: selection
//! "#;
//!
//! let collection = SigmaCollection::from_yaml(yaml).unwrap();
//! let rule = match &collection.documents[0] {
//!     SigmaDocument::Rule(r) => r.clone(),
//!     _ => panic!("Expected rule"),
//! };
//!
//! // Create processor
//! let processor = LogProcessor::new(vec![rule]).unwrap();
//!
//! // Start processing
//! let (event_tx, detection_rx) = processor.start();
//!
//! // Send events
//! let log_source = LogSource {
//!     category: Some("process_creation".to_string()),
//!     product: Some("windows".to_string()),
//!     service: None,
//!     
//! };
//!
//! let json = r#"{"EventID": 4688, "Image": "cmd.exe"}"#;
//! let event = LogEvent::from_json(log_source, json).unwrap();
//! event_tx.send(event).unwrap();
//! drop(event_tx);
//!
//! // Receive detections
//! while let Ok(result) = detection_rx.recv() {
//!     use sigma_engine::DetectionResult;
//!     match result {
//!         DetectionResult::Rule(d) => println!("Matched: {}", d.rule.title),
//!         DetectionResult::Correlation(cd) => println!("Correlation: {}", cd.rule.title),
//!     }
//! }
//! ```
//!
//! # Supported Input Formats
//!
//! The LogProcessor supports multiple input formats:
//! - **JSON**: Structured JSON objects with field-value pairs
//! - **Plain text**: Unstructured log strings
//! - **Field="Value"**: Key-value pairs in Field="Value" format
//!
//! # Threading Model
//!
//! By default, the processor uses (CPU count - 1) worker threads. Each worker
//! processes events from a shared channel and outputs detections to another channel.
//! This allows for efficient parallel processing of high-volume log streams.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use chrono::{DateTime, Utc};
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use serde_json::Value as JsonValue;

use crate::matcher::SigmaRuleMatcher;
use crate::types::{
    CorrelationCondition, CorrelationType, LogSource, SigmaCorrelationRule, SigmaDocument,
    SigmaRule,
};

/// A log event that can be matched against Sigma rules.
#[derive(Debug, Clone)]
pub struct LogEvent {
    /// The log source this event belongs to
    pub log_source: LogSource,
    /// The event data as field-value pairs
    pub data: HashMap<String, String>,
    /// The raw event string (if available)
    pub raw: Option<String>,
    /// The time at which this event occurred.
    pub timestamp: DateTime<Utc>,
}

impl LogEvent {
    /// Create a new log event from structured field-value pairs.
    ///
    /// The event timestamp is set to the current UTC time. Use
    /// [`LogEvent::with_timestamp`] to override it.
    pub fn from_fields(log_source: LogSource, data: HashMap<String, String>) -> Self {
        Self {
            log_source,
            data,
            raw: None,
            timestamp: Utc::now(),
        }
    }

    /// Create a new log event from a JSON string.
    ///
    /// # Errors
    /// Returns an error if the JSON cannot be parsed.
    pub fn from_json(log_source: LogSource, json: &str) -> Result<Self, serde_json::Error> {
        let parsed: JsonValue = serde_json::from_str(json)?;
        let data = Self::json_to_fields(&parsed);
        Ok(Self {
            log_source,
            data,
            raw: Some(json.to_string()),
            timestamp: Utc::now(),
        })
    }

    /// Create a new log event from a plain unstructured string.
    pub fn from_plain(log_source: LogSource, text: String) -> Self {
        let mut data = HashMap::new();
        data.insert("_raw".to_string(), text.clone());
        Self {
            log_source,
            data,
            raw: Some(text),
            timestamp: Utc::now(),
        }
    }

    /// Create a new log event from Field="Value" format.
    ///
    /// This parses a string like: `EventID="4688" User="SYSTEM" CommandLine="cmd.exe"`
    pub fn from_field_value_format(log_source: LogSource, text: &str) -> Self {
        let data = Self::parse_field_value_format(text);
        Self {
            log_source,
            data,
            raw: Some(text.to_string()),
            timestamp: Utc::now(),
        }
    }

    /// Set the timestamp of this event, consuming and returning the modified event.
    ///
    /// Use this to assign a specific timestamp rather than the default (current UTC time).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::{LogEvent, LogSource};
    /// use chrono::{DateTime, Utc, TimeZone};
    /// use std::collections::HashMap;
    ///
    /// let log_source = LogSource { category: None, product: None, service: None };
    /// let ts: DateTime<Utc> = Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap();
    /// let event = LogEvent::from_fields(log_source, HashMap::new())
    ///     .with_timestamp(ts);
    ///
    /// assert_eq!(event.get_time(), ts);
    /// ```
    pub fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Returns the event's timestamp.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::{LogEvent, LogSource};
    /// use std::collections::HashMap;
    ///
    /// let log_source = LogSource { category: None, product: None, service: None };
    /// let event = LogEvent::from_fields(log_source, HashMap::new());
    /// let _ts = event.get_time(); // returns DateTime<Utc>
    /// ```
    pub fn get_time(&self) -> DateTime<Utc> {
        self.timestamp
    }

    /// Convert a JSON value to a flat field-value map.
    fn json_to_fields(value: &JsonValue) -> HashMap<String, String> {
        let mut fields = HashMap::new();
        Self::flatten_json(value, String::new(), &mut fields);
        fields
    }

    /// Recursively flatten a JSON object into field-value pairs.
    fn flatten_json(value: &JsonValue, prefix: String, fields: &mut HashMap<String, String>) {
        match value {
            JsonValue::Object(map) => {
                for (key, val) in map {
                    let new_prefix = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", prefix, key)
                    };
                    Self::flatten_json(val, new_prefix, fields);
                }
            }
            JsonValue::Array(arr) => {
                // Convert arrays to comma-separated strings
                let values: Vec<String> = arr.iter()
                    .map(Self::json_value_to_string)
                    .collect();
                fields.insert(prefix, values.join(","));
            }
            _ => {
                fields.insert(prefix, Self::json_value_to_string(value));
            }
        }
    }

    /// Convert a JSON value to a string.
    fn json_value_to_string(value: &JsonValue) -> String {
        match value {
            JsonValue::String(s) => s.clone(),
            JsonValue::Number(n) => n.to_string(),
            JsonValue::Bool(b) => b.to_string(),
            JsonValue::Null => String::new(),
            _ => value.to_string(),
        }
    }

    /// Parse Field="Value" format into field-value pairs.
    /// 
    /// Note: Field names cannot contain '=' characters. The first '=' encountered
    /// is treated as the separator between field name and value.
    fn parse_field_value_format(text: &str) -> HashMap<String, String> {
        let mut fields = HashMap::new();
        let mut chars = text.chars().peekable();
        
        while chars.peek().is_some() {
            // Skip whitespace
            while chars.peek().is_some_and(|c| c.is_whitespace()) {
                chars.next();
            }
            
            if chars.peek().is_none() {
                break;
            }
            
            // Parse field name
            let mut field = String::new();
            while let Some(&ch) = chars.peek() {
                if ch == '=' {
                    chars.next(); // consume '='
                    break;
                }
                field.push(ch);
                chars.next();
            }
            
            // Skip whitespace after '='
            while chars.peek().is_some_and(|c| c.is_whitespace()) {
                chars.next();
            }
            
            // Parse value
            let mut value = String::new();
            if chars.peek() == Some(&'"') {
                // Quoted value
                chars.next(); // skip opening quote
                while let Some(ch) = chars.next() {
                    if ch == '"' {
                        // Check for escaped quote
                        if chars.peek() != Some(&'"') {
                            break;
                        }
                        chars.next(); // consume second quote
                        value.push('"');
                    } else if ch == '\\' {
                        // Handle escape sequences
                        if let Some(escaped) = chars.next() {
                            match escaped {
                                'n' => value.push('\n'),
                                't' => value.push('\t'),
                                'r' => value.push('\r'),
                                '\\' => value.push('\\'),
                                '"' => value.push('"'),
                                _ => {
                                    value.push('\\');
                                    value.push(escaped);
                                }
                            }
                        }
                    } else {
                        value.push(ch);
                    }
                }
            } else {
                // Unquoted value (until whitespace or end)
                while let Some(&ch) = chars.peek() {
                    if ch.is_whitespace() {
                        break;
                    }
                    value.push(ch);
                    chars.next();
                }
            }
            
            if !field.is_empty() {
                fields.insert(field.trim().to_string(), value);
            }
        }
        
        fields
    }
}

/// A detection result when a Sigma rule matches an event.
#[derive(Debug, Clone)]
pub struct Detection {
    /// The rule that matched
    pub rule: Arc<SigmaRule>,
    /// The event that was matched
    pub event: LogEvent,
}

/// A detection result produced when a correlation rule's condition is satisfied.
///
/// A correlation detection is triggered when a set of individual rule detections
/// satisfies the correlation rule's condition (e.g. event count threshold, all
/// temporal rules fired, etc.) within the configured time window.
#[derive(Debug, Clone)]
pub struct CorrelationDetection {
    /// The correlation rule whose condition was satisfied.
    pub rule: Arc<SigmaCorrelationRule>,
    /// The group-by field values that identify this correlation group.
    /// Keys are `group_by` field names; values are the shared field values.
    pub group_key: HashMap<String, String>,
    /// All events within the time window that contributed to this detection.
    pub contributing_events: Vec<LogEvent>,
}

/// Unified output from the log processor — either a plain rule match or a correlation match.
///
/// Received from the channel returned by [`LogProcessor::start`].
#[derive(Debug, Clone)]
pub enum DetectionResult {
    /// A standard Sigma detection rule matched an event.
    Rule(Detection),
    /// A Sigma correlation rule's condition was satisfied.
    Correlation(CorrelationDetection),
}

/// Configuration for the log processor.
#[derive(Debug, Clone)]
pub struct ProcessorConfig {
    /// Number of worker threads for matching (default: CPU count - 1, minimum 1)
    pub num_threads: usize,
    /// Size of the event input channel buffer (0 = unbounded)
    pub event_buffer_size: usize,
    /// Size of the detection output channel buffer (0 = unbounded)
    pub detection_buffer_size: usize,
    /// Maximum age (in seconds) of an event relative to the newest event seen
    /// before it is treated as a late-arriving event and discarded from the
    /// correlation time window.  Defaults to 3600 (one hour).
    pub late_event_threshold_secs: u64,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        let num_cpus = num_cpus::get();
        Self {
            num_threads: if num_cpus > 1 { num_cpus - 1 } else { 1 },
            event_buffer_size: 1000,
            detection_buffer_size: 1000,
            late_event_threshold_secs: 3600,
        }
    }
}

/// A multithreaded log processor that matches events against Sigma rules and
/// evaluates Sigma correlation rules over streams of detections.
///
/// The processor uses message passing to ingest log events and output detections.
/// It dispatches events to matchers based on log source matching.
pub struct LogProcessor {
    /// Compiled matchers for all detection rules
    matchers: Vec<Arc<SigmaRuleMatcher>>,
    /// Correlation rules to evaluate
    correlation_rules: Vec<Arc<SigmaCorrelationRule>>,
    /// Configuration
    config: ProcessorConfig,
}

impl LogProcessor {
    /// Create a new log processor with the given detection rules.
    ///
    /// No correlation rules are loaded; use [`LogProcessor::from_collection`] or
    /// [`LogProcessor::with_config`] together with [`LogProcessor::with_correlation_rules`]
    /// when correlation rules are needed.
    ///
    /// # Errors
    /// Returns an error if any rule cannot be compiled into a matcher.
    pub fn new(rules: Vec<SigmaRule>) -> Result<Self, crate::error::Error> {
        Self::with_config(rules, ProcessorConfig::default())
    }

    /// Create a new log processor with custom configuration.
    ///
    /// # Errors
    /// Returns an error if any rule cannot be compiled into a matcher.
    pub fn with_config(
        rules: Vec<SigmaRule>,
        config: ProcessorConfig,
    ) -> Result<Self, crate::error::Error> {
        let mut matchers = Vec::new();
        for rule in rules {
            matchers.push(Arc::new(SigmaRuleMatcher::new(rule)?));
        }

        Ok(Self {
            matchers,
            correlation_rules: Vec::new(),
            config,
        })
    }

    /// Create a log processor from a [`crate::types::SigmaCollection`], loading all
    /// detection rules and correlation rules found in the collection.
    ///
    /// # Errors
    /// Returns an error if any detection rule cannot be compiled into a matcher.
    pub fn from_collection(
        collection: &crate::types::SigmaCollection,
    ) -> Result<Self, crate::error::Error> {
        Self::from_collection_with_config(collection, ProcessorConfig::default())
    }

    /// Create a log processor from a [`crate::types::SigmaCollection`] with custom
    /// configuration, loading all detection rules and correlation rules found in the
    /// collection.
    ///
    /// # Errors
    /// Returns an error if any detection rule cannot be compiled into a matcher.
    pub fn from_collection_with_config(
        collection: &crate::types::SigmaCollection,
        config: ProcessorConfig,
    ) -> Result<Self, crate::error::Error> {
        let mut matchers = Vec::new();
        let mut correlation_rules = Vec::new();

        for doc in &collection.documents {
            match doc {
                SigmaDocument::Rule(rule) => {
                    matchers.push(Arc::new(SigmaRuleMatcher::new(rule.clone())?));
                }
                SigmaDocument::Correlation(corr) => {
                    correlation_rules.push(Arc::new(corr.clone()));
                }
            }
        }

        Ok(Self {
            matchers,
            correlation_rules,
            config,
        })
    }

    /// Add correlation rules to an existing processor, consuming and returning it.
    pub fn with_correlation_rules(
        mut self,
        correlation_rules: Vec<SigmaCorrelationRule>,
    ) -> Self {
        self.correlation_rules
            .extend(correlation_rules.into_iter().map(Arc::new));
        self
    }

    /// Start processing events.
    ///
    /// Returns a tuple of `(event_sender, detection_receiver)` for message passing.
    ///
    /// - Send [`LogEvent`]s to `event_sender`.
    /// - Receive [`DetectionResult`]s from `detection_receiver`.  Each result is
    ///   either a [`DetectionResult::Rule`] (a plain detection rule matched) or a
    ///   [`DetectionResult::Correlation`] (a correlation rule condition was satisfied).
    /// - Drop `event_sender` to signal all workers to shut down.
    pub fn start(&self) -> (Sender<LogEvent>, Receiver<DetectionResult>) {
        let (event_tx, event_rx) = if self.config.event_buffer_size == 0 {
            unbounded()
        } else {
            bounded(self.config.event_buffer_size)
        };

        // Internal channel: worker threads → correlation worker
        let (raw_detection_tx, raw_detection_rx) = unbounded::<Detection>();

        let (output_tx, output_rx) = if self.config.detection_buffer_size == 0 {
            unbounded()
        } else {
            bounded(self.config.detection_buffer_size)
        };

        // Spawn worker threads
        for _ in 0..self.config.num_threads {
            let event_rx_clone = event_rx.clone();
            let raw_detection_tx_clone = raw_detection_tx.clone();
            let matchers = self.matchers.clone();

            thread::spawn(move || {
                Self::worker_thread(event_rx_clone, raw_detection_tx_clone, matchers);
            });
        }

        // Drop the processor's copy of the sender/receiver so they close when workers finish
        drop(event_rx);
        drop(raw_detection_tx);

        // Spawn the correlation worker
        let correlation_rules = self.correlation_rules.clone();
        let late_threshold = Duration::from_secs(self.config.late_event_threshold_secs);
        let output_tx_clone = output_tx.clone();

        thread::spawn(move || {
            Self::correlation_worker(
                raw_detection_rx,
                output_tx_clone,
                correlation_rules,
                late_threshold,
            );
        });

        drop(output_tx);

        (event_tx, output_rx)
    }

    /// Worker thread: match incoming events against compiled rule matchers and
    /// forward resulting [`Detection`]s to the internal detection channel.
    fn worker_thread(
        event_rx: Receiver<LogEvent>,
        detection_tx: Sender<Detection>,
        matchers: Vec<Arc<SigmaRuleMatcher>>,
    ) {
        while let Ok(event) = event_rx.recv() {
            for matcher in &matchers {
                if Self::log_source_matches(&event.log_source, &matcher.rule.logsource)
                    && matcher.matches(&event.data)
                {
                    let detection = Detection {
                        rule: matcher.rule.clone(),
                        event: event.clone(),
                    };
                    if detection_tx.send(detection).is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Correlation worker: forward plain detections to the output channel and
    /// update correlation state, emitting [`CorrelationDetection`]s when a
    /// correlation rule's condition is satisfied.
    fn correlation_worker(
        raw_detection_rx: Receiver<Detection>,
        output_tx: Sender<DetectionResult>,
        correlation_rules: Vec<Arc<SigmaCorrelationRule>>,
        late_event_threshold: Duration,
    ) {
        let mut engine = CorrelationEngine::new(correlation_rules, late_event_threshold);

        while let Ok(detection) = raw_detection_rx.recv() {
            // Process for correlation first (borrows detection)
            let corr_detections = engine.process(&detection);

            // Forward the plain detection result
            if output_tx
                .send(DetectionResult::Rule(detection))
                .is_err()
            {
                return;
            }

            // Forward any triggered correlation detections
            for cd in corr_detections {
                if output_tx.send(DetectionResult::Correlation(cd)).is_err() {
                    return;
                }
            }
        }
    }

    /// Check if an event's log source matches a rule's log source.
    ///
    /// Matching follows the Sigma specification:
    /// - An empty field in the rule matches any value in the event
    /// - A field value in the rule must match the corresponding event field value
    pub(crate) fn log_source_matches(
        event_source: &LogSource,
        rule_source: &LogSource,
    ) -> bool {
        // Check category
        if let Some(rule_category) = &rule_source.category {
            match &event_source.category {
                Some(event_category) => {
                    if !event_category.eq_ignore_ascii_case(rule_category) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Check product
        if let Some(rule_product) = &rule_source.product {
            match &event_source.product {
                Some(event_product) => {
                    if !event_product.eq_ignore_ascii_case(rule_product) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Check service
        if let Some(rule_service) = &rule_source.service {
            match &event_source.service {
                Some(event_service) => {
                    if !event_service.eq_ignore_ascii_case(rule_service) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

// ─── Timespan parsing ────────────────────────────────────────────────────────

/// Parse a Sigma timespan string (e.g. `"1h"`, `"5m"`, `"30s"`, `"2d"`, `"1w"`)
/// into a [`Duration`].
///
/// Supported unit suffixes: `s` (seconds), `m` (minutes), `h` (hours),
/// `d` (days), `w` (weeks).  Returns `None` if the string cannot be parsed.
///
/// # Examples
///
/// ```rust
/// use sigma_engine::processor::parse_timespan;
/// use std::time::Duration;
///
/// assert_eq!(parse_timespan("30s"), Some(Duration::from_secs(30)));
/// assert_eq!(parse_timespan("5m"),  Some(Duration::from_secs(300)));
/// assert_eq!(parse_timespan("1h"),  Some(Duration::from_secs(3600)));
/// assert_eq!(parse_timespan("2d"),  Some(Duration::from_secs(172800)));
/// assert_eq!(parse_timespan("1w"),  Some(Duration::from_secs(604800)));
/// assert_eq!(parse_timespan("bad"), None);
/// ```
pub fn parse_timespan(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = s.split_at(s.len() - 1);
    let count: u64 = num_str.parse().ok()?;
    let secs = match unit {
        "s" => count,
        "m" => count * 60,
        "h" => count * 3600,
        "d" => count * 86_400,
        "w" => count * 604_800,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

// ─── Correlation engine ──────────────────────────────────────────────────────

/// A single event stored in a correlation window.
struct TimedEvent {
    timestamp: DateTime<Utc>,
    /// The name or id of the Sigma rule that produced this detection.
    rule_ref: String,
    event: LogEvent,
}

/// Sliding-window state for a single (correlation rule index, group key) pair.
#[derive(Default)]
struct CorrelationWindowState {
    /// Events currently inside the time window, ordered by ascending timestamp.
    events: VecDeque<TimedEvent>,
}

/// Engine that maintains per-group sliding windows for every correlation rule
/// and checks their conditions each time a new detection arrives.
struct CorrelationEngine {
    rules: Vec<Arc<SigmaCorrelationRule>>,
    /// Pre-parsed timespan for each rule (same index as `rules`).
    timespans: Vec<Duration>,
    /// State keyed by `(rule_index, group_key_pairs)`.
    state: HashMap<(usize, Vec<(String, String)>), CorrelationWindowState>,
    late_event_threshold: Duration,
}

impl CorrelationEngine {
    fn new(rules: Vec<Arc<SigmaCorrelationRule>>, late_event_threshold: Duration) -> Self {
        let timespans = rules
            .iter()
            .map(|r| {
                r.correlation
                    .timespan
                    .as_deref()
                    .and_then(parse_timespan)
                    .unwrap_or(Duration::from_secs(300)) // 5 minute default when no timespan is specified
            })
            .collect();

        Self {
            rules,
            timespans,
            state: HashMap::new(),
            late_event_threshold,
        }
    }

    /// Process a new detection.  Returns any correlation detections that are now triggered.
    fn process(&mut self, detection: &Detection) -> Vec<CorrelationDetection> {
        let rule = &detection.rule;
        let event = &detection.event;
        let event_time = event.timestamp;

        let mut results = Vec::new();

        for rule_idx in 0..self.rules.len() {
            let corr_rule = Arc::clone(&self.rules[rule_idx]);

            // Check whether this detection's rule is referenced by the correlation rule
            let rule_ref = match rule_ref_for(rule, &corr_rule.correlation.rules) {
                Some(r) => r,
                None => continue,
            };

            // Compute the group key (a sorted list of (alias/field, value) pairs)
            let group_key =
                compute_group_key(event, &rule_ref, &corr_rule);

            let timespan = self.timespans[rule_idx];

            // Reject late-arriving events that are older than the late-event threshold
            // relative to the most recent event in the window.
            let state = self
                .state
                .entry((rule_idx, group_key.clone()))
                .or_default();

            if let Some(newest) = state.events.back() {
                let late_cutoff = newest.timestamp
                    - chrono::Duration::from_std(self.late_event_threshold)
                        .unwrap_or(chrono::Duration::zero());
                if event_time < late_cutoff {
                    // Too old — discard
                    continue;
                }
            }

            // Evict events that have fallen outside the sliding window
            let window_cutoff = event_time
                - chrono::Duration::from_std(timespan).unwrap_or(chrono::Duration::zero());
            while state
                .events
                .front()
                .is_some_and(|e| e.timestamp < window_cutoff)
            {
                state.events.pop_front();
            }

            // Insert the new event (maintain ascending timestamp order)
            let insert_pos = state
                .events
                .iter()
                .rposition(|e| e.timestamp <= event_time)
                .map(|p| p + 1)
                .unwrap_or(0);
            state.events.insert(
                insert_pos,
                TimedEvent {
                    timestamp: event_time,
                    rule_ref,
                    event: event.clone(),
                },
            );

            // Check the correlation condition
            if let Some(cd) =
                check_correlation_condition(&corr_rule, group_key, &state.events)
            {
                results.push(cd);
            }
        }

        results
    }
}

/// Determine whether a fired rule is referenced by a correlation rule.
///
/// Returns the canonical reference string (name or id) on a match, or `None`.
fn rule_ref_for(rule: &SigmaRule, corr_refs: &[String]) -> Option<String> {
    for r in corr_refs {
        if let Some(name) = &rule.name
            && name.eq_ignore_ascii_case(r)
        {
            return Some(r.clone());
        }
        if let Some(id) = &rule.id
            && id.eq_ignore_ascii_case(r)
        {
            return Some(r.clone());
        }
    }
    None
}

/// Build the sorted group-key vector for a detection, resolving field aliases
/// defined in the correlation rule.
fn compute_group_key(
    event: &LogEvent,
    rule_ref: &str,
    corr_rule: &SigmaCorrelationRule,
) -> Vec<(String, String)> {
    corr_rule
        .correlation
        .group_by
        .iter()
        .map(|field| {
            // Resolve alias: if there is an alias entry for `field` that maps this
            // rule_ref to an actual field name, use that instead.
            let resolved_field = corr_rule
                .correlation
                .aliases
                .get(field)
                .and_then(|rule_map| rule_map.get(rule_ref))
                .map(|s| s.as_str())
                .unwrap_or(field.as_str());

            let value = event
                .data
                .get(resolved_field)
                .cloned()
                .unwrap_or_default();

            (field.clone(), value)
        })
        .collect()
}

/// Evaluate the correlation rule's condition against the current window state.
///
/// Returns a [`CorrelationDetection`] when the condition is satisfied, or `None`
/// when it is not.
fn check_correlation_condition(
    corr_rule: &Arc<SigmaCorrelationRule>,
    group_key: Vec<(String, String)>,
    events: &VecDeque<TimedEvent>,
) -> Option<CorrelationDetection> {
    let group_map: HashMap<String, String> = group_key.into_iter().collect();

    let satisfied = match corr_rule.correlation.correlation_type {
        CorrelationType::EventCount => {
            let count = events.len() as i64;
            corr_rule
                .correlation
                .condition
                .as_ref()
                .map(|c| eval_simple_condition(c, count))
                .unwrap_or(false)
        }

        CorrelationType::ValueCount => {
            let field = match &corr_rule.correlation.condition {
                Some(CorrelationCondition::Simple(sc)) => sc.field.as_deref(),
                _ => None,
            };
            let distinct: HashSet<&str> = events
                .iter()
                .filter_map(|te| {
                    field.and_then(|f| te.event.data.get(f).map(|s| s.as_str()))
                })
                .collect();
            let count = distinct.len() as i64;
            corr_rule
                .correlation
                .condition
                .as_ref()
                .map(|c| eval_simple_condition(c, count))
                .unwrap_or(false)
        }

        CorrelationType::ValueSum => {
            let field = match &corr_rule.correlation.condition {
                Some(CorrelationCondition::Simple(sc)) => sc.field.as_deref(),
                _ => None,
            };
            let sum: f64 = events
                .iter()
                .filter_map(|te| {
                    field.and_then(|f| {
                        te.event.data.get(f).and_then(|v| v.parse::<f64>().ok())
                    })
                })
                .sum();
            corr_rule
                .correlation
                .condition
                .as_ref()
                .map(|c| eval_simple_condition(c, sum as i64))
                .unwrap_or(false)
        }

        CorrelationType::ValueAvg => {
            let field = match &corr_rule.correlation.condition {
                Some(CorrelationCondition::Simple(sc)) => sc.field.as_deref(),
                _ => None,
            };
            let values: Vec<f64> = events
                .iter()
                .filter_map(|te| {
                    field.and_then(|f| {
                        te.event.data.get(f).and_then(|v| v.parse::<f64>().ok())
                    })
                })
                .collect();
            if values.is_empty() {
                false
            } else {
                let avg = values.iter().sum::<f64>() / values.len() as f64;
                corr_rule
                    .correlation
                    .condition
                    .as_ref()
                    .map(|c| eval_simple_condition(c, avg as i64))
                    .unwrap_or(false)
            }
        }

        CorrelationType::ValuePercentile => {
            let field = match &corr_rule.correlation.condition {
                Some(CorrelationCondition::Simple(sc)) => sc.field.as_deref(),
                _ => None,
            };
            let mut values: Vec<f64> = events
                .iter()
                .filter_map(|te| {
                    field.and_then(|f| {
                        te.event.data.get(f).and_then(|v| v.parse::<f64>().ok())
                    })
                })
                .collect();
            if values.is_empty() {
                false
            } else {
                // Compute the 95th percentile of field values.
                // NOTE: The Sigma spec's value_percentile correlation type requires a
                // percentile rank in the condition, but the current SimpleCondition type
                // does not carry one.  Until the type system is extended to support an
                // explicit rank, the engine uses the 95th percentile (P95) as the
                // default, which is the most common operational threshold.
                values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let idx = ((0.95 * values.len() as f64).ceil() as usize).saturating_sub(1);
                let percentile_val = values[idx.min(values.len() - 1)];
                corr_rule
                    .correlation
                    .condition
                    .as_ref()
                    .map(|c| eval_simple_condition(c, percentile_val as i64))
                    .unwrap_or(false)
            }
        }

        CorrelationType::Temporal => {
            let required_refs: HashSet<&str> = corr_rule
                .correlation
                .rules
                .iter()
                .map(|s| s.as_str())
                .collect();

            let fired: HashSet<&str> = events
                .iter()
                .map(|te| te.rule_ref.as_str())
                .collect();

            let all_fired = required_refs.iter().all(|r| fired.contains(r));

            if !all_fired {
                false
            } else {
                // Evaluate optional extended boolean condition
                match &corr_rule.correlation.condition {
                    None => true,
                    Some(CorrelationCondition::Extended(expr)) => {
                        eval_temporal_condition(expr, &fired)
                    }
                    Some(CorrelationCondition::Simple(_)) => true,
                }
            }
        }

        CorrelationType::TemporalOrdered => {
            check_temporal_ordered(&corr_rule.correlation.rules, events)
        }
    };

    if satisfied {
        Some(CorrelationDetection {
            rule: Arc::clone(corr_rule),
            group_key: group_map,
            contributing_events: events.iter().map(|te| te.event.clone()).collect(),
        })
    } else {
        None
    }
}

/// Evaluate a [`CorrelationCondition`] with a numeric value.
fn eval_simple_condition(condition: &CorrelationCondition, value: i64) -> bool {
    let sc = match condition {
        CorrelationCondition::Simple(sc) => sc,
        CorrelationCondition::Extended(_) => return false,
    };
    if sc.gt.is_some_and(|gt| value <= gt) {
        return false;
    }
    if sc.gte.is_some_and(|gte| value < gte) {
        return false;
    }
    if sc.lt.is_some_and(|lt| value >= lt) {
        return false;
    }
    if sc.lte.is_some_and(|lte| value > lte) {
        return false;
    }
    if sc.eq.is_some_and(|eq| value != eq) {
        return false;
    }
    if sc.neq.is_some_and(|neq| value == neq) {
        return false;
    }
    true
}

/// Evaluate a temporal extended boolean condition expression against the set of
/// rule references that have fired within the current window.
fn eval_temporal_condition(
    expr: &crate::types::ConditionExpression,
    fired: &HashSet<&str>,
) -> bool {
    use crate::types::ConditionExpression;
    match expr {
        ConditionExpression::Identifier(name) => fired.contains(name.as_str()),
        ConditionExpression::And(l, r) => {
            eval_temporal_condition(l, fired) && eval_temporal_condition(r, fired)
        }
        ConditionExpression::Or(l, r) => {
            eval_temporal_condition(l, fired) || eval_temporal_condition(r, fired)
        }
        ConditionExpression::Not(e) => !eval_temporal_condition(e, fired),
        ConditionExpression::OneOfThem => !fired.is_empty(),
        // `all of them` in a temporal extended condition is reached only after the
        // outer `all_fired` pre-check already confirmed every required rule has fired,
        // so this is always satisfied here.
        ConditionExpression::AllOfThem => true,
        ConditionExpression::OneOfPattern(pat) => {
            let pat_lower = pat.to_lowercase();
            fired.iter().any(|r| glob_matches(&pat_lower, r))
        }
        ConditionExpression::AllOfPattern(pat) => {
            let pat_lower = pat.to_lowercase();
            fired.iter().all(|r| glob_matches(&pat_lower, r))
        }
    }
}

/// Check whether a `temporal_ordered` correlation rule's conditions are met.
///
/// All rules in `ordered_refs` must have fired in order: the earliest event
/// from `ordered_refs[i+1]` must not predate the earliest event from
/// `ordered_refs[i]`.
fn check_temporal_ordered(
    ordered_refs: &[String],
    events: &VecDeque<TimedEvent>,
) -> bool {
    if ordered_refs.is_empty() {
        return true;
    }

    // Collect the earliest timestamp for each required rule reference
    let mut first_times: Vec<Option<DateTime<Utc>>> = vec![None; ordered_refs.len()];

    for te in events {
        for (i, r) in ordered_refs.iter().enumerate() {
            if te.rule_ref.eq_ignore_ascii_case(r) {
                let entry = &mut first_times[i];
                if entry.is_none_or(|t| te.timestamp < t) {
                    *entry = Some(te.timestamp);
                }
            }
        }
    }

    // All rules must have fired
    let times: Vec<DateTime<Utc>> = match first_times.into_iter().collect::<Option<Vec<_>>>() {
        Some(v) => v,
        None => return false,
    };

    // Each rule must have fired no earlier than the rule before it
    times.windows(2).all(|w| w[0] <= w[1])
}

/// Simple glob matching: `*` matches any sequence of characters.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let text = text.to_lowercase();
    if pattern == "*" {
        return true;
    }
    // Split on `*` and match each part in order
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    if !text.starts_with(first) {
        return false;
    }
    let mut pos = first.len();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(idx) => pos += idx + part.len(),
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_event_from_json() {
        let log_source = LogSource {
            category: Some("process_creation".to_string()),
            product: Some("windows".to_string()),
            service: None,
            
        };

        let json = r#"{"EventID": 4688, "Image": "C:\\Windows\\System32\\cmd.exe"}"#;
        let event = LogEvent::from_json(log_source, json).unwrap();

        assert_eq!(event.data.get("EventID"), Some(&"4688".to_string()));
        assert_eq!(event.data.get("Image"), Some(&"C:\\Windows\\System32\\cmd.exe".to_string()));
    }

    #[test]
    fn test_log_event_from_plain() {
        let log_source = LogSource {
            category: Some("test".to_string()),
            product: None,
            service: None,
            
        };

        let text = "This is a plain log message".to_string();
        let event = LogEvent::from_plain(log_source, text.clone());

        assert_eq!(event.data.get("_raw"), Some(&text));
    }

    #[test]
    fn test_log_event_from_field_value_format() {
        let log_source = LogSource {
            category: Some("test".to_string()),
            product: None,
            service: None,
            
        };

        let text = r#"EventID="4688" User="SYSTEM" CommandLine="cmd.exe /c echo test""#;
        let event = LogEvent::from_field_value_format(log_source, text);

        assert_eq!(event.data.get("EventID"), Some(&"4688".to_string()));
        assert_eq!(event.data.get("User"), Some(&"SYSTEM".to_string()));
        assert_eq!(event.data.get("CommandLine"), Some(&"cmd.exe /c echo test".to_string()));
    }

    #[test]
    fn test_log_source_matching() {
        let rule_source = LogSource {
            category: Some("process_creation".to_string()),
            product: Some("windows".to_string()),
            service: None,
            
        };

        // Exact match
        let event_source1 = LogSource {
            category: Some("process_creation".to_string()),
            product: Some("windows".to_string()),
            service: None,
            
        };
        assert!(LogProcessor::log_source_matches(&event_source1, &rule_source));

        // Extra fields in event should still match
        let event_source2 = LogSource {
            category: Some("process_creation".to_string()),
            product: Some("windows".to_string()),
            service: Some("security".to_string()),
            
        };
        assert!(LogProcessor::log_source_matches(&event_source2, &rule_source));

        // Missing required field should not match
        let event_source3 = LogSource {
            category: Some("process_creation".to_string()),
            product: None,
            service: None,
            
        };
        assert!(!LogProcessor::log_source_matches(&event_source3, &rule_source));

        // Different value should not match
        let event_source4 = LogSource {
            category: Some("network_connection".to_string()),
            product: Some("windows".to_string()),
            service: None,
            
        };
        assert!(!LogProcessor::log_source_matches(&event_source4, &rule_source));
    }

    #[test]
    fn test_processor_basic_matching() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventID: 4688
        Image|endswith: '\cmd.exe'
    condition: selection
"#;
        let collection = crate::SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            crate::SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let processor = LogProcessor::new(vec![rule]).unwrap();
        let (event_tx, detection_rx) = processor.start();

        // Send a matching event
        let log_source = LogSource {
            category: Some("process_creation".to_string()),
            product: Some("windows".to_string()),
            service: None,
            
        };

        let mut data = HashMap::new();
        data.insert("EventID".to_string(), "4688".to_string());
        data.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());

        let event = LogEvent::from_fields(log_source, data);
        event_tx.send(event).unwrap();
        drop(event_tx); // Signal completion

        // Receive detection
        let result = detection_rx.recv().unwrap();
        let detection = match result {
            DetectionResult::Rule(d) => d,
            _ => panic!("Expected rule detection"),
        };
        assert_eq!(detection.rule.title, "Test Rule");
        assert_eq!(detection.event.data.get("EventID"), Some(&"4688".to_string()));
    }

    #[test]
    fn test_parse_field_value_with_spaces() {
        let text = r#"Field1="value with spaces" Field2="another value""#;
        let fields = LogEvent::parse_field_value_format(text);
        
        assert_eq!(fields.get("Field1"), Some(&"value with spaces".to_string()));
        assert_eq!(fields.get("Field2"), Some(&"another value".to_string()));
    }

    #[test]
    fn test_parse_field_value_unquoted() {
        let text = "EventID=4688 User=SYSTEM";
        let fields = LogEvent::parse_field_value_format(text);
        
        assert_eq!(fields.get("EventID"), Some(&"4688".to_string()));
        assert_eq!(fields.get("User"), Some(&"SYSTEM".to_string()));
    }

    #[test]
    fn test_log_event_from_json_nested() {
        let log_source = LogSource {
            category: Some("test".to_string()),
            product: None,
            service: None,
        };

        let json = r#"{"outer": {"inner": "value"}, "arr": [1, 2, 3]}"#;
        let event = LogEvent::from_json(log_source, json).unwrap();

        assert_eq!(event.data.get("outer.inner"), Some(&"value".to_string()));
        assert_eq!(event.data.get("arr"), Some(&"1,2,3".to_string()));
    }

    #[test]
    fn test_json_value_to_string_types() {
        // Bool
        assert_eq!(
            LogEvent::json_value_to_string(&serde_json::json!(true)),
            "true"
        );
        // Null
        assert_eq!(
            LogEvent::json_value_to_string(&serde_json::json!(null)),
            ""
        );
        // Number
        assert_eq!(
            LogEvent::json_value_to_string(&serde_json::json!(42)),
            "42"
        );
        // Array (other)
        let arr = serde_json::json!([1, 2]);
        let result = LogEvent::json_value_to_string(&arr);
        assert!(result.contains('1'));
    }

    #[test]
    fn test_parse_field_value_escape_sequences() {
        let text = r#"Field="line1\nline2\ttab\\backslash\rcarriage\"quote"#;
        let fields = LogEvent::parse_field_value_format(text);
        assert_eq!(
            fields.get("Field"),
            Some(&"line1\nline2\ttab\\backslash\rcarriage\"quote".to_string())
        );
    }

    #[test]
    fn test_parse_field_value_unknown_escape() {
        let text = r#"Field="test\xvalue""#;
        let fields = LogEvent::parse_field_value_format(text);
        assert_eq!(fields.get("Field"), Some(&"test\\xvalue".to_string()));
    }

    #[test]
    fn test_parse_field_value_double_quote_in_value() {
        let text = r#"Field="value""quoted""#;
        let fields = LogEvent::parse_field_value_format(text);
        assert_eq!(fields.get("Field"), Some(&"value\"quoted".to_string()));
    }

    #[test]
    fn test_parse_field_value_whitespace_after_equals() {
        let text = r#"Field= value"#;
        let fields = LogEvent::parse_field_value_format(text);
        assert_eq!(fields.get("Field"), Some(&"value".to_string()));
    }

    #[test]
    fn test_log_source_matches_service() {
        let rule_source = LogSource {
            category: None,
            product: None,
            service: Some("security".to_string()),
        };

        let event_source1 = LogSource {
            category: None,
            product: None,
            service: Some("security".to_string()),
        };
        assert!(LogProcessor::log_source_matches(&event_source1, &rule_source));

        let event_source2 = LogSource {
            category: None,
            product: None,
            service: Some("application".to_string()),
        };
        assert!(!LogProcessor::log_source_matches(&event_source2, &rule_source));

        let event_source3 = LogSource {
            category: None,
            product: None,
            service: None,
        };
        assert!(!LogProcessor::log_source_matches(&event_source3, &rule_source));
    }

    #[test]
    fn test_log_source_matches_category_none() {
        let rule_source = LogSource {
            category: Some("process_creation".to_string()),
            product: None,
            service: None,
        };

        let event_source = LogSource {
            category: None,
            product: None,
            service: None,
        };
        assert!(!LogProcessor::log_source_matches(&event_source, &rule_source));
    }

    #[test]
    fn test_processor_with_config() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        EventID: 1234
    condition: selection
"#;
        let collection = crate::SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            crate::SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let config = ProcessorConfig {
            num_threads: 1,
            event_buffer_size: 0,
            detection_buffer_size: 0,
            late_event_threshold_secs: 3600,
        };

        let processor = LogProcessor::with_config(vec![rule], config).unwrap();
        let (event_tx, detection_rx) = processor.start();

        let log_source = LogSource {
            category: None,
            product: Some("test".to_string()),
            service: None,
        };
        let mut data = HashMap::new();
        data.insert("EventID".to_string(), "1234".to_string());
        let event = LogEvent::from_fields(log_source, data);
        event_tx.send(event).unwrap();
        drop(event_tx);

        let result = detection_rx.recv().unwrap();
        let detection = match result {
            DetectionResult::Rule(d) => d,
            _ => panic!("Expected rule detection"),
        };
        assert_eq!(detection.rule.title, "Test Rule");
    }

    // ─── Timestamp tests ──────────────────────────────────────────────────────

    #[test]
    fn test_log_event_timestamp_default() {
        let before = Utc::now();
        let event = LogEvent::from_fields(
            LogSource { category: None, product: None, service: None },
            HashMap::new(),
        );
        let after = Utc::now();
        assert!(event.get_time() >= before);
        assert!(event.get_time() <= after);
    }

    #[test]
    fn test_log_event_with_timestamp() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2024, 6, 1, 10, 0, 0).unwrap();
        let event = LogEvent::from_fields(
            LogSource { category: None, product: None, service: None },
            HashMap::new(),
        )
        .with_timestamp(ts);
        assert_eq!(event.get_time(), ts);
    }

    #[test]
    fn test_log_event_from_json_has_timestamp() {
        let ls = LogSource { category: None, product: None, service: None };
        let event = LogEvent::from_json(ls, "{}").unwrap();
        // timestamp should be close to now
        let diff = (Utc::now() - event.get_time()).num_seconds().abs();
        assert!(diff < 5);
    }

    #[test]
    fn test_log_event_from_plain_has_timestamp() {
        let ls = LogSource { category: None, product: None, service: None };
        let event = LogEvent::from_plain(ls, "hello".to_string());
        let diff = (Utc::now() - event.get_time()).num_seconds().abs();
        assert!(diff < 5);
    }

    #[test]
    fn test_log_event_from_field_value_has_timestamp() {
        let ls = LogSource { category: None, product: None, service: None };
        let event = LogEvent::from_field_value_format(ls, r#"K="V""#);
        let diff = (Utc::now() - event.get_time()).num_seconds().abs();
        assert!(diff < 5);
    }

    // ─── parse_timespan tests ─────────────────────────────────────────────────

    #[test]
    fn test_parse_timespan_seconds() {
        assert_eq!(parse_timespan("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_timespan("1s"), Some(Duration::from_secs(1)));
    }

    #[test]
    fn test_parse_timespan_minutes() {
        assert_eq!(parse_timespan("5m"), Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_parse_timespan_hours() {
        assert_eq!(parse_timespan("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_timespan("2h"), Some(Duration::from_secs(7200)));
    }

    #[test]
    fn test_parse_timespan_days() {
        assert_eq!(parse_timespan("2d"), Some(Duration::from_secs(172_800)));
    }

    #[test]
    fn test_parse_timespan_weeks() {
        assert_eq!(parse_timespan("1w"), Some(Duration::from_secs(604_800)));
    }

    #[test]
    fn test_parse_timespan_invalid() {
        assert_eq!(parse_timespan(""), None);
        assert_eq!(parse_timespan("bad"), None);
        assert_eq!(parse_timespan("5x"), None);
        assert_eq!(parse_timespan("abc"), None);
    }

    // ─── event_count correlation tests ────────────────────────────────────────

    fn make_detection_rule_yaml(name: &str, title: &str) -> String {
        format!(
            r#"
title: {title}
name: {name}
logsource:
    product: test
detection:
    sel:
        EventID: 1
    condition: sel
"#
        )
    }

    fn make_corr_yaml(
        corr_type: &str,
        rule_refs: &[&str],
        group_by: &[&str],
        timespan: &str,
        condition: &str,
    ) -> String {
        let refs = rule_refs
            .iter()
            .map(|r| format!("        - {}", r))
            .collect::<Vec<_>>()
            .join("\n");
        let groups = if group_by.is_empty() {
            "        []".to_string()
        } else {
            group_by
                .iter()
                .map(|g| format!("        - {}", g))
                .collect::<Vec<_>>()
                .join("\n")
        };
        format!(
            r#"
title: Correlation Rule
type: correlation
correlation:
    type: {corr_type}
    rules:
{refs}
    group-by:
{groups}
    timespan: {timespan}
    condition:
        {condition}
"#
        )
    }

    fn make_test_event(event_id: &str) -> LogEvent {
        let mut data = HashMap::new();
        data.insert("EventID".to_string(), event_id.to_string());
        LogEvent::from_fields(
            LogSource {
                category: None,
                product: Some("test".to_string()),
                service: None,
            },
            data,
        )
    }

    #[test]
    fn test_event_count_correlation_fires() {
        let det_yaml = make_detection_rule_yaml("login_fail", "Login Failure");
        let corr_yaml = make_corr_yaml(
            "event_count",
            &["login_fail"],
            &[],
            "5m",
            "gte: 3",
        );
        let combined = format!("{}\n---\n{}", det_yaml, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let processor = LogProcessor::from_collection(&collection).unwrap();
        let (event_tx, detection_rx) = processor.start();

        // Send 3 matching events — correlation should fire on the 3rd
        for _ in 0..3 {
            event_tx.send(make_test_event("1")).unwrap();
        }
        drop(event_tx);

        let mut rule_hits = 0u32;
        let mut corr_hits = 0u32;
        while let Ok(result) = detection_rx.recv() {
            match result {
                DetectionResult::Rule(_) => rule_hits += 1,
                DetectionResult::Correlation(cd) => {
                    corr_hits += 1;
                    assert_eq!(cd.rule.title, "Correlation Rule");
                    assert!(!cd.contributing_events.is_empty());
                }
            }
        }
        assert_eq!(rule_hits, 3);
        // Correlation fires at count==3, then again for every subsequent event;
        // since we sent exactly 3 events it fires exactly once.
        assert_eq!(corr_hits, 1);
    }

    #[test]
    fn test_event_count_correlation_does_not_fire_below_threshold() {
        let det_yaml = make_detection_rule_yaml("login_fail", "Login Failure");
        let corr_yaml = make_corr_yaml(
            "event_count",
            &["login_fail"],
            &[],
            "5m",
            "gte: 5",
        );
        let combined = format!("{}\n---\n{}", det_yaml, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let processor = LogProcessor::from_collection(&collection).unwrap();
        let (event_tx, detection_rx) = processor.start();

        // Only 2 events — below the threshold of 5
        for _ in 0..2 {
            event_tx.send(make_test_event("1")).unwrap();
        }
        drop(event_tx);

        let corr_hits: Vec<_> = detection_rx
            .iter()
            .filter(|r| matches!(r, DetectionResult::Correlation(_)))
            .collect();
        assert!(corr_hits.is_empty());
    }

    // ─── value_count correlation tests ────────────────────────────────────────

    #[test]
    fn test_value_count_correlation_fires() {
        // Build a custom YAML with a field in the correlation condition
        let det_yaml = r#"
title: DNS Query
name: dns_query
logsource:
    product: test
detection:
    sel:
        EventID: 1
    condition: sel
"#;
        let corr_yaml = r#"
title: Many Unique DNS Destinations
type: correlation
correlation:
    type: value_count
    rules:
        - dns_query
    group-by: []
    timespan: 5m
    condition:
        field: Destination
        gte: 3
"#;
        let combined = format!("{}\n---\n{}", det_yaml, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let processor = LogProcessor::from_collection(&collection).unwrap();
        let (event_tx, detection_rx) = processor.start();

        // 4 events with 4 distinct destinations
        for dest in &["a.com", "b.com", "c.com", "d.com"] {
            let mut data = HashMap::new();
            data.insert("EventID".to_string(), "1".to_string());
            data.insert("Destination".to_string(), dest.to_string());
            let event = LogEvent::from_fields(
                LogSource { category: None, product: Some("test".to_string()), service: None },
                data,
            );
            event_tx.send(event).unwrap();
        }
        drop(event_tx);

        let corr_hits: u32 = detection_rx
            .iter()
            .filter(|r| matches!(r, DetectionResult::Correlation(_)))
            .count() as u32;
        // Should fire at 3 distinct values (count==3) and again at 4 (count==4)
        assert!(corr_hits >= 1);
    }

    // ─── temporal correlation tests ───────────────────────────────────────────

    #[test]
    fn test_temporal_correlation_fires_when_all_rules_match() {
        let yaml_a = r#"
title: Rule A
name: rule_a
logsource:
    product: test
detection:
    sel:
        EventID: 1
    condition: sel
"#;
        let yaml_b = r#"
title: Rule B
name: rule_b
logsource:
    product: test
detection:
    sel:
        EventID: 2
    condition: sel
"#;
        let corr_yaml = r#"
title: Temporal Corr
type: correlation
correlation:
    type: temporal
    rules:
        - rule_a
        - rule_b
    group-by: []
    timespan: 5m
"#;
        let combined = format!("{}\n---\n{}\n---\n{}", yaml_a, yaml_b, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let processor = LogProcessor::from_collection(&collection).unwrap();
        let (event_tx, detection_rx) = processor.start();

        event_tx.send(make_test_event("1")).unwrap();
        event_tx.send(make_test_event("2")).unwrap();
        drop(event_tx);

        let corr_hits: u32 = detection_rx
            .iter()
            .filter(|r| matches!(r, DetectionResult::Correlation(_)))
            .count() as u32;
        assert!(corr_hits >= 1);
    }

    #[test]
    fn test_temporal_correlation_does_not_fire_with_only_one_rule() {
        let yaml_a = r#"
title: Rule A
name: rule_a
logsource:
    product: test
detection:
    sel:
        EventID: 1
    condition: sel
"#;
        let corr_yaml = r#"
title: Temporal Corr
type: correlation
correlation:
    type: temporal
    rules:
        - rule_a
        - rule_b
    group-by: []
    timespan: 5m
"#;
        let combined = format!("{}\n---\n{}", yaml_a, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let processor = LogProcessor::from_collection(&collection).unwrap();
        let (event_tx, detection_rx) = processor.start();

        // Only rule_a fires — rule_b never does
        event_tx.send(make_test_event("1")).unwrap();
        drop(event_tx);

        let corr_hits: u32 = detection_rx
            .iter()
            .filter(|r| matches!(r, DetectionResult::Correlation(_)))
            .count() as u32;
        assert_eq!(corr_hits, 0);
    }

    // ─── temporal_ordered correlation tests ───────────────────────────────────

    #[test]
    fn test_temporal_ordered_fires_in_correct_order() {
        use chrono::TimeZone;

        let yaml_a = r#"
title: Rule A
name: rule_a
logsource:
    product: test
detection:
    sel:
        EventID: 10
    condition: sel
"#;
        let yaml_b = r#"
title: Rule B
name: rule_b
logsource:
    product: test
detection:
    sel:
        EventID: 20
    condition: sel
"#;
        let corr_yaml = r#"
title: Ordered Temporal
type: correlation
correlation:
    type: temporal_ordered
    rules:
        - rule_a
        - rule_b
    group-by: []
    timespan: 10m
"#;
        let combined = format!("{}\n---\n{}\n---\n{}", yaml_a, yaml_b, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let processor = LogProcessor::from_collection(&collection).unwrap();
        let (event_tx, detection_rx) = processor.start();

        // a fires at t=0, b fires at t=1 — correct order
        let t0 = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let t1 = Utc.with_ymd_and_hms(2024, 1, 1, 0, 1, 0).unwrap();

        let mut e_a = make_test_event("10");
        e_a.timestamp = t0;
        let mut e_b = make_test_event("20");
        e_b.timestamp = t1;

        event_tx.send(e_a).unwrap();
        event_tx.send(e_b).unwrap();
        drop(event_tx);

        let corr_hits: u32 = detection_rx
            .iter()
            .filter(|r| matches!(r, DetectionResult::Correlation(_)))
            .count() as u32;
        assert!(corr_hits >= 1);
    }

    #[test]
    fn test_temporal_ordered_does_not_fire_out_of_order() {
        use chrono::TimeZone;

        let yaml_a = r#"
title: Rule A
name: rule_a
logsource:
    product: test
detection:
    sel:
        EventID: 10
    condition: sel
"#;
        let yaml_b = r#"
title: Rule B
name: rule_b
logsource:
    product: test
detection:
    sel:
        EventID: 20
    condition: sel
"#;
        let corr_yaml = r#"
title: Ordered Temporal
type: correlation
correlation:
    type: temporal_ordered
    rules:
        - rule_a
        - rule_b
    group-by: []
    timespan: 10m
"#;
        let combined = format!("{}\n---\n{}\n---\n{}", yaml_a, yaml_b, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let processor = LogProcessor::from_collection(&collection).unwrap();
        let (event_tx, detection_rx) = processor.start();

        // b fires BEFORE a — wrong order
        let t0 = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let t1 = Utc.with_ymd_and_hms(2024, 1, 1, 0, 1, 0).unwrap();

        let mut e_b = make_test_event("20");
        e_b.timestamp = t0;
        let mut e_a = make_test_event("10");
        e_a.timestamp = t1;

        event_tx.send(e_b).unwrap();
        event_tx.send(e_a).unwrap();
        drop(event_tx);

        let corr_hits: u32 = detection_rx
            .iter()
            .filter(|r| matches!(r, DetectionResult::Correlation(_)))
            .count() as u32;
        assert_eq!(corr_hits, 0);
    }

    // ─── value_sum correlation tests ──────────────────────────────────────────

    #[test]
    fn test_value_sum_correlation_fires() {
        let det_yaml = r#"
title: Transfer Event
name: transfer_event
logsource:
    product: test
detection:
    sel:
        EventID: 1
    condition: sel
"#;
        let corr_yaml = r#"
title: Large Transfer Sum
type: correlation
correlation:
    type: value_sum
    rules:
        - transfer_event
    group-by: []
    timespan: 5m
    condition:
        field: Bytes
        gte: 1000
"#;
        let combined = format!("{}\n---\n{}", det_yaml, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let processor = LogProcessor::from_collection(&collection).unwrap();
        let (event_tx, detection_rx) = processor.start();

        // Sum = 400 + 700 = 1100 ≥ 1000 — should fire on 2nd event
        for bytes in &["400", "700"] {
            let mut data = HashMap::new();
            data.insert("EventID".to_string(), "1".to_string());
            data.insert("Bytes".to_string(), bytes.to_string());
            let event = LogEvent::from_fields(
                LogSource { category: None, product: Some("test".to_string()), service: None },
                data,
            );
            event_tx.send(event).unwrap();
        }
        drop(event_tx);

        let corr_hits: u32 = detection_rx
            .iter()
            .filter(|r| matches!(r, DetectionResult::Correlation(_)))
            .count() as u32;
        assert!(corr_hits >= 1);
    }

    // ─── value_avg correlation tests ──────────────────────────────────────────

    #[test]
    fn test_value_avg_correlation_fires() {
        let det_yaml = r#"
title: CPU Event
name: cpu_event
logsource:
    product: test
detection:
    sel:
        EventID: 1
    condition: sel
"#;
        let corr_yaml = r#"
title: High Avg CPU
type: correlation
correlation:
    type: value_avg
    rules:
        - cpu_event
    group-by: []
    timespan: 5m
    condition:
        field: CPU
        gte: 80
"#;
        let combined = format!("{}\n---\n{}", det_yaml, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let processor = LogProcessor::from_collection(&collection).unwrap();
        let (event_tx, detection_rx) = processor.start();

        // Average = (85 + 90) / 2 = 87.5 ≥ 80 — fires on second event
        for cpu in &["85", "90"] {
            let mut data = HashMap::new();
            data.insert("EventID".to_string(), "1".to_string());
            data.insert("CPU".to_string(), cpu.to_string());
            let event = LogEvent::from_fields(
                LogSource { category: None, product: Some("test".to_string()), service: None },
                data,
            );
            event_tx.send(event).unwrap();
        }
        drop(event_tx);

        let corr_hits: u32 = detection_rx
            .iter()
            .filter(|r| matches!(r, DetectionResult::Correlation(_)))
            .count() as u32;
        assert!(corr_hits >= 1);
    }

    // ─── group_by tests ───────────────────────────────────────────────────────

    #[test]
    fn test_event_count_with_group_by_isolates_groups() {
        let det_yaml = r#"
title: Login Event
name: login_event
logsource:
    product: test
detection:
    sel:
        EventID: 1
    condition: sel
"#;
        let corr_yaml = r#"
title: Brute Force by User
type: correlation
correlation:
    type: event_count
    rules:
        - login_event
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 3
"#;
        let combined = format!("{}\n---\n{}", det_yaml, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let processor = LogProcessor::from_collection(&collection).unwrap();
        let (event_tx, detection_rx) = processor.start();

        // user_alice gets 3 events → should fire
        // user_bob gets 2 events → should NOT fire
        let users = ["alice", "alice", "alice", "bob", "bob"];
        for user in &users {
            let mut data = HashMap::new();
            data.insert("EventID".to_string(), "1".to_string());
            data.insert("User".to_string(), user.to_string());
            let event = LogEvent::from_fields(
                LogSource { category: None, product: Some("test".to_string()), service: None },
                data,
            );
            event_tx.send(event).unwrap();
        }
        drop(event_tx);

        let corr_detections: Vec<_> = detection_rx
            .iter()
            .filter_map(|r| match r {
                DetectionResult::Correlation(cd) => Some(cd),
                _ => None,
            })
            .collect();

        // All correlation detections must be for alice
        for cd in &corr_detections {
            assert_eq!(cd.group_key.get("User"), Some(&"alice".to_string()));
        }
        // At least one correlation detection
        assert!(!corr_detections.is_empty());
    }

    // ─── from_collection tests ────────────────────────────────────────────────

    #[test]
    fn test_from_collection_loads_both_rule_types() {
        let det_yaml = make_detection_rule_yaml("my_rule", "My Rule");
        let corr_yaml = r#"
title: Count Corr
type: correlation
correlation:
    type: event_count
    rules:
        - my_rule
    group-by: []
    timespan: 1h
    condition:
        gte: 10
"#;
        let combined = format!("{}\n---\n{}", det_yaml, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let processor = LogProcessor::from_collection(&collection).unwrap();

        // The processor should have both a matcher and a correlation rule loaded
        assert_eq!(processor.matchers.len(), 1);
        assert_eq!(processor.correlation_rules.len(), 1);
    }

    // ─── late-event threshold tests ───────────────────────────────────────────

    #[test]
    fn test_late_event_is_discarded() {
        let det_yaml = make_detection_rule_yaml("ev", "Event");
        let corr_yaml = r#"
title: Count
type: correlation
correlation:
    type: event_count
    rules:
        - ev
    group-by: []
    timespan: 5m
    condition:
        gte: 3
"#;
        let combined = format!("{}\n---\n{}", det_yaml, corr_yaml);
        let collection = crate::SigmaCollection::from_yaml(&combined).unwrap();
        let config = ProcessorConfig {
            num_threads: 1,
            event_buffer_size: 100,
            detection_buffer_size: 100,
            // Only allow events up to 60 seconds old relative to latest
            late_event_threshold_secs: 60,
        };
        let processor =
            LogProcessor::from_collection_with_config(&collection, config).unwrap();
        let (event_tx, detection_rx) = processor.start();

        // Send two recent events (now) and one very old event (2 hours ago).
        // The two recent events alone do not reach the threshold of 3.
        // The old event is beyond the 60-second threshold and must be discarded.
        let now = Utc::now();
        let old_ts = now - chrono::Duration::hours(2);

        let mut e1 = make_test_event("1");
        e1.timestamp = now;
        let mut e2 = make_test_event("1");
        e2.timestamp = now;
        let mut old_event = make_test_event("1");
        old_event.timestamp = old_ts;

        event_tx.send(e1).unwrap();
        event_tx.send(e2).unwrap();
        event_tx.send(old_event).unwrap();
        drop(event_tx);

        let corr_hits: u32 = detection_rx
            .iter()
            .filter(|r| matches!(r, DetectionResult::Correlation(_)))
            .count() as u32;
        // The old event must have been discarded, so the threshold of 3 is never reached.
        assert_eq!(corr_hits, 0);
    }
}
