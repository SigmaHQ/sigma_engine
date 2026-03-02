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
//! while let Ok(detection) = detection_rx.recv() {
//!     println!("Matched: {}", detection.rule.title);
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

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use serde_json::Value as JsonValue;

use crate::matcher::SigmaRuleMatcher;
use crate::types::{LogSource, SigmaRule};

/// A log event that can be matched against Sigma rules.
#[derive(Debug, Clone)]
pub struct LogEvent {
    /// The log source this event belongs to
    pub log_source: LogSource,
    /// The event data as field-value pairs
    pub data: HashMap<String, String>,
    /// The raw event string (if available)
    pub raw: Option<String>,
}

impl LogEvent {
    /// Create a new log event from structured field-value pairs.
    pub fn from_fields(log_source: LogSource, data: HashMap<String, String>) -> Self {
        Self {
            log_source,
            data,
            raw: None,
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
        }
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
                    .map(|v| Self::json_value_to_string(v))
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
            while chars.peek().map_or(false, |c| c.is_whitespace()) {
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
            while chars.peek().map_or(false, |c| c.is_whitespace()) {
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

/// Configuration for the log processor.
#[derive(Debug, Clone)]
pub struct ProcessorConfig {
    /// Number of worker threads for matching (default: CPU count - 1, minimum 1)
    pub num_threads: usize,
    /// Size of the event input channel buffer (0 = unbounded)
    pub event_buffer_size: usize,
    /// Size of the detection output channel buffer (0 = unbounded)
    pub detection_buffer_size: usize,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        let num_cpus = num_cpus::get();
        Self {
            num_threads: if num_cpus > 1 { num_cpus - 1 } else { 1 },
            event_buffer_size: 1000,
            detection_buffer_size: 1000,
        }
    }
}

/// A multithreaded log processor that matches events against Sigma rules.
///
/// The processor uses message passing to ingest log events and output detections.
/// It dispatches events to matchers based on log source matching.
pub struct LogProcessor {
    /// Compiled matchers for all rules
    matchers: Vec<Arc<SigmaRuleMatcher>>,
    /// Configuration
    config: ProcessorConfig,
}

impl LogProcessor {
    /// Create a new log processor with the given rules.
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

        Ok(Self { matchers, config })
    }

    /// Start processing events.
    ///
    /// Returns a tuple of (event_sender, detection_receiver) for message passing.
    /// Send events to the event_sender, and receive detections from the detection_receiver.
    /// When done sending events, drop the event_sender to signal workers to shut down.
    pub fn start(
        &self,
    ) -> (Sender<LogEvent>, Receiver<Detection>) {
        let (event_tx, event_rx) = if self.config.event_buffer_size == 0 {
            unbounded()
        } else {
            bounded(self.config.event_buffer_size)
        };

        let (detection_tx, detection_rx) = if self.config.detection_buffer_size == 0 {
            unbounded()
        } else {
            bounded(self.config.detection_buffer_size)
        };

        // Spawn worker threads
        for _ in 0..self.config.num_threads {
            let event_rx_clone = event_rx.clone();
            let detection_tx_clone = detection_tx.clone();
            let matchers = self.matchers.clone();

            thread::spawn(move || {
                Self::worker_thread(event_rx_clone, detection_tx_clone, matchers);
            });
        }

        // Drop our copies so only the senders/receivers returned to caller remain
        drop(event_rx);
        drop(detection_tx);

        (event_tx, detection_rx)
    }

    /// Worker thread function that processes events.
    fn worker_thread(
        event_rx: Receiver<LogEvent>,
        detection_tx: Sender<Detection>,
        matchers: Vec<Arc<SigmaRuleMatcher>>,
    ) {
        while let Ok(event) = event_rx.recv() {
            // Try each matcher that matches the log source
            for matcher in &matchers {
                if Self::log_source_matches(&event.log_source, &matcher.rule.logsource) {
                    if matcher.matches(&event.data) {
                        let detection = Detection {
                            rule: matcher.rule.clone(),
                            event: event.clone(),
                        };
                        // If send fails, the receiver was dropped, so we should exit
                        if detection_tx.send(detection).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Check if an event's log source matches a rule's log source.
    ///
    /// Matching follows the Sigma specification:
    /// - An empty field in the rule matches any value in the event
    /// - A field value in the rule must match the corresponding event field value
    fn log_source_matches(event_source: &LogSource, rule_source: &LogSource) -> bool {
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
        let detection = detection_rx.recv().unwrap();
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
}
