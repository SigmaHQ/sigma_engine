//! Sigma rule matcher for efficient event matching.
//!
//! This module provides functionality to compile Sigma rules into matcher objects
//! that can efficiently match events. Matchers are thread-safe and can be used
//! concurrently.
//!
//! # Example
//!
//! ```rust
//! use sigma_engine::{SigmaCollection, SigmaDocument, SigmaRuleMatcher};
//! use std::collections::HashMap;
//!
//! let yaml = r#"
//! title: Suspicious Process
//! logsource:
//!     product: windows
//! detection:
//!     selection:
//!         Image|endswith: '\cmd.exe'
//!     condition: selection
//! "#;
//!
//! let collection = SigmaCollection::from_yaml(yaml).unwrap();
//! let rule = match &collection.documents[0] {
//!     SigmaDocument::Rule(r) => r.clone(),
//!     _ => panic!("Expected rule"),
//! };
//!
//! let matcher = SigmaRuleMatcher::new(rule).unwrap();
//!
//! let mut event = HashMap::new();
//! event.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());
//!
//! assert!(matcher.matches(&event));
//! ```
//!
//! # Supported Modifiers
//!
//! The matcher supports all Sigma modifiers including:
//! - String modifiers: `contains`, `startswith`, `endswith`, `re` (regex)
//! - Case modifiers: `cased`
//! - Encoding modifiers: `base64`, `base64offset`, `utf16le`, `utf16be`, `utf16`, `wide`
//! - Logic modifiers: `all`, `exists`, `neq`
//! - Numeric modifiers: `lt`, `lte`, `gt`, `gte`
//! - Dash expansion: `windash` (generates all dash character permutations)
//!
//! # Thread Safety
//!
//! `SigmaRuleMatcher` is thread-safe and uses `Arc` internally for efficient sharing
//! across threads.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;
use regex::Regex;

use crate::error::{Error, Result};
use crate::types::*;

// Cache for compiled regex patterns
static REGEX_CACHE: Lazy<Mutex<HashMap<String, std::result::Result<Regex, String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// A trait for types that can be used as events in Sigma rule matching.
///
/// Implement this trait to allow [`SigmaRuleMatcher::matches`] to operate on
/// arbitrary event representations beyond a plain `HashMap<String, String>`.
///
/// # Examples
///
/// Implementing `Event` for a custom struct:
///
/// ```rust
/// use sigma_engine::Event;
/// use std::borrow::Cow;
/// use std::collections::HashMap;
///
/// struct MyEvent {
///     fields: HashMap<String, String>,
///     raw_line: Option<String>,
/// }
///
/// impl Event for MyEvent {
///     fn get_field(&self, field: &str) -> Option<&str> {
///         self.fields.get(field).map(String::as_str)
///     }
///
///     fn has_field(&self, field: &str) -> bool {
///         self.fields.contains_key(field)
///     }
///
///     fn raw(&self) -> Cow<'_, str> {
///         match &self.raw_line {
///             Some(r) => Cow::Borrowed(r.as_str()),
///             None => Cow::Owned(
///                 self.fields.values().map(String::as_str).collect::<Vec<_>>().join(" ")
///             ),
///         }
///     }
/// }
/// ```
pub trait Event {
    /// Return the value of a named field, or `None` if the field does not exist.
    fn get_field(&self, field: &str) -> Option<&str>;

    /// Return `true` if the named field is present in the event.
    fn has_field(&self, field: &str) -> bool;

    /// Return the raw string representation of the event.
    ///
    /// This is used for keyword (field-less) detection items.  When the event
    /// has a pre-existing raw log line that representation is returned directly
    /// (borrowed).  If no raw representation is available, an owned string is
    /// built by joining all field values with a single space, which preserves
    /// the original behaviour of the library.
    fn raw(&self) -> Cow<'_, str>;
}

/// Blanket [`Event`] implementation for `HashMap<String, String>`.
///
/// This keeps all existing call-sites that pass a plain hash-map working
/// without any changes.
///
/// # Examples
///
/// ```rust
/// use sigma_engine::{SigmaCollection, SigmaDocument, SigmaRuleMatcher};
/// use std::collections::HashMap;
///
/// let yaml = r#"
/// title: Test
/// logsource:
///     product: test
/// detection:
///     sel:
///         Field: value
///     condition: sel
/// "#;
///
/// let collection = SigmaCollection::from_yaml(yaml).unwrap();
/// let rule = match &collection.documents[0] {
///     SigmaDocument::Rule(r) => r.clone(),
///     _ => panic!("Expected rule"),
/// };
/// let matcher = SigmaRuleMatcher::new(rule).unwrap();
///
/// let mut event = HashMap::new();
/// event.insert("Field".to_string(), "value".to_string());
/// assert!(matcher.matches(&event));
/// ```
impl Event for HashMap<String, String> {
    fn get_field(&self, field: &str) -> Option<&str> {
        self.get(field).map(String::as_str)
    }

    fn has_field(&self, field: &str) -> bool {
        self.contains_key(field)
    }

    fn raw(&self) -> Cow<'_, str> {
        Cow::Owned(self.values().map(String::as_str).collect::<Vec<_>>().join(" "))
    }
}

/// A compiled matcher for a Sigma detection rule.
///
/// This struct represents a compiled version of a SigmaRule that can efficiently
/// match against events. It is thread-safe and can be used concurrently.
#[derive(Debug, Clone)]
pub struct SigmaRuleMatcher {
    /// The original rule this matcher was compiled from
    pub rule: Arc<SigmaRule>,
    /// Compiled search identifiers for efficient matching
    compiled_searches: HashMap<String, CompiledSearch>,
}

/// A compiled search identifier that can be evaluated against an event.
#[derive(Debug, Clone)]
enum CompiledSearch {
    /// AND-connected detection items
    Map(Vec<CompiledDetectionItem>),
    /// OR-connected list of AND-connected groups
    MapList(Vec<Vec<CompiledDetectionItem>>),
}

/// A compiled detection item ready for matching.
#[derive(Debug, Clone)]
struct CompiledDetectionItem {
    field: Option<String>,
    modifiers: Vec<Modifier>,
    patterns: Vec<CompiledPattern>,
}

/// A compiled pattern for efficient matching.
#[derive(Debug, Clone)]
enum CompiledPattern {
    /// Exact string match (after applying modifiers)
    Exact(String),
    /// Wildcard pattern (using glob-like matching)
    Wildcard(String),
    /// Regular expression pattern
    Regex(String),
    /// Integer value
    Int(i64),
    /// Float value
    Float(f64),
    /// Boolean value
    Bool(bool),
    /// Null value
    Null,
}

impl SigmaRuleMatcher {
    /// Compile a Sigma rule into a matcher.
    ///
    /// # Errors
    /// Returns an error if the rule cannot be compiled (e.g., invalid regex patterns).
    pub fn new(rule: SigmaRule) -> Result<Self> {
        let mut compiled_searches = HashMap::new();

        for (name, search_id) in &rule.detection.search_identifiers {
            let compiled = match search_id {
                SearchIdentifier::Map(items) => {
                    CompiledSearch::Map(Self::compile_detection_items(items)?)
                }
                SearchIdentifier::MapList(maps) => {
                    let mut compiled_maps = Vec::new();
                    for items in maps {
                        compiled_maps.push(Self::compile_detection_items(items)?);
                    }
                    CompiledSearch::MapList(compiled_maps)
                }
            };
            compiled_searches.insert(name.clone(), compiled);
        }

        Ok(Self {
            rule: Arc::new(rule),
            compiled_searches,
        })
    }

    /// Compile a list of detection items.
    fn compile_detection_items(items: &[DetectionItem]) -> Result<Vec<CompiledDetectionItem>> {
        let mut compiled = Vec::new();
        for item in items {
            compiled.push(Self::compile_detection_item(item)?);
        }
        Ok(compiled)
    }

    /// Compile a single detection item.
    fn compile_detection_item(item: &DetectionItem) -> Result<CompiledDetectionItem> {
        let mut patterns = Vec::new();
        
        for value in &item.values {
            // For base64offset and windash, we need to generate multiple patterns
            if item.modifiers.contains(&Modifier::Base64Offset) || 
               item.modifiers.contains(&Modifier::Windash) {
                let expanded_patterns = Self::compile_value_with_expansion(value, &item.modifiers)?;
                patterns.extend(expanded_patterns);
            } else {
                let pattern = Self::compile_value(value, &item.modifiers)?;
                patterns.push(pattern);
            }
        }

        Ok(CompiledDetectionItem {
            field: item.field.clone(),
            modifiers: item.modifiers.clone(),
            patterns,
        })
    }

    /// Compile a single value into a pattern.
    fn compile_value(value: &SigmaValue, modifiers: &[Modifier]) -> Result<CompiledPattern> {
        match value {
            SigmaValue::String(sigma_str) => {
                let mut s = sigma_str.to_string();
                
                // Apply string transformation modifiers
                s = Self::apply_string_modifiers(&s, modifiers)?;
                
                // Determine pattern type based on modifiers
                if modifiers.contains(&Modifier::Re) {
                    Ok(CompiledPattern::Regex(s))
                } else if sigma_str.has_special_parts() || 
                          modifiers.contains(&Modifier::Contains) ||
                          modifiers.contains(&Modifier::StartsWith) ||
                          modifiers.contains(&Modifier::EndsWith) {
                    Ok(CompiledPattern::Wildcard(s))
                } else {
                    Ok(CompiledPattern::Exact(s))
                }
            }
            SigmaValue::Int(i) => Ok(CompiledPattern::Int(*i)),
            SigmaValue::Float(f) => Ok(CompiledPattern::Float(*f)),
            SigmaValue::Bool(b) => Ok(CompiledPattern::Bool(*b)),
            SigmaValue::Null => Ok(CompiledPattern::Null),
        }
    }

    /// Compile a single value with expansion for base64offset and windash.
    fn compile_value_with_expansion(value: &SigmaValue, modifiers: &[Modifier]) -> Result<Vec<CompiledPattern>> {
        if let SigmaValue::String(sigma_str) = value {
            let base_str = sigma_str.to_string();
            let mut variants = vec![base_str.clone()];
            
            // Apply windash first if present
            if modifiers.contains(&Modifier::Windash) {
                variants = Self::apply_windash_expansion(&variants);
            }
            
            // Apply base64offset if present
            if modifiers.contains(&Modifier::Base64Offset) {
                variants = Self::apply_base64offset_expansion(&variants, modifiers)?;
            } else {
                // Apply other string modifiers
                let mut processed_variants = Vec::new();
                for variant in variants {
                    let processed = Self::apply_string_modifiers(&variant, modifiers)?;
                    processed_variants.push(processed);
                }
                variants = processed_variants;
            }
            
            // Convert all variants to patterns
            let mut patterns = Vec::new();
            for variant in variants {
                if modifiers.contains(&Modifier::Re) {
                    patterns.push(CompiledPattern::Regex(variant));
                } else if sigma_str.has_special_parts() || 
                          modifiers.contains(&Modifier::Contains) ||
                          modifiers.contains(&Modifier::StartsWith) ||
                          modifiers.contains(&Modifier::EndsWith) {
                    patterns.push(CompiledPattern::Wildcard(variant));
                } else {
                    patterns.push(CompiledPattern::Exact(variant));
                }
            }
            
            Ok(patterns)
        } else {
            // Non-string values just compile normally
            Ok(vec![Self::compile_value(value, modifiers)?])
        }
    }

    /// Apply windash expansion: replace dashes with all variants.
    fn apply_windash_expansion(variants: &[String]) -> Vec<String> {
        // Dash characters: hyphen-minus, solidus, en-dash, em-dash, horizontal bar
        const DASH_CHARS: &[char] = &['-', '/', '–', '—', '―'];
        
        let mut result = Vec::new();
        
        for variant in variants {
            // Find all dash positions
            let chars: Vec<char> = variant.chars().collect();
            let mut dash_positions = Vec::new();
            
            for (i, &ch) in chars.iter().enumerate() {
                if DASH_CHARS.contains(&ch) {
                    dash_positions.push(i);
                }
            }
            
            if dash_positions.is_empty() {
                result.push(variant.clone());
                continue;
            }
            
            // Generate all permutations
            let num_dashes = dash_positions.len();
            let num_permutations = DASH_CHARS.len().pow(num_dashes as u32);
            
            for perm_idx in 0..num_permutations {
                let mut new_chars = chars.clone();
                let mut temp_idx = perm_idx;
                
                for &pos in &dash_positions {
                    let dash_idx = temp_idx % DASH_CHARS.len();
                    new_chars[pos] = DASH_CHARS[dash_idx];
                    temp_idx /= DASH_CHARS.len();
                }
                
                result.push(new_chars.iter().collect());
            }
        }
        
        result
    }

    /// Apply base64offset expansion: encode with 0, 1, and 2 byte offsets.
    fn apply_base64offset_expansion(variants: &[String], modifiers: &[Modifier]) -> Result<Vec<String>> {
        use std::io::Write;
        let mut result = Vec::new();
        
        for variant in variants {
            // Generate 3 variants with different offsets
            for offset in 0..3 {
                let mut bytes = vec![0u8; offset];
                bytes.extend_from_slice(variant.as_bytes());
                
                // Apply other encoding modifiers before base64
                let encoded_bytes = if modifiers.contains(&Modifier::Wide) || modifiers.contains(&Modifier::Utf16Le) {
                    // UTF-16LE encoding
                    let utf16: Vec<u16> = variant.encode_utf16().collect();
                    let mut utf16_bytes: Vec<u8> = utf16.iter()
                        .flat_map(|&c| c.to_le_bytes())
                        .collect();
                    let mut result_bytes = vec![0u8; offset];
                    result_bytes.append(&mut utf16_bytes);
                    result_bytes
                } else if modifiers.contains(&Modifier::Utf16Be) {
                    // UTF-16BE encoding
                    let utf16: Vec<u16> = variant.encode_utf16().collect();
                    let mut utf16_bytes: Vec<u8> = utf16.iter()
                        .flat_map(|&c| c.to_be_bytes())
                        .collect();
                    let mut result_bytes = vec![0u8; offset];
                    result_bytes.append(&mut utf16_bytes);
                    result_bytes
                } else {
                    bytes
                };
                
                // Base64 encode
                let mut buf = Vec::new();
                let mut encoder = base64::write::EncoderWriter::new(&mut buf, &base64::engine::general_purpose::STANDARD);
                encoder.write_all(&encoded_bytes).map_err(|e| {
                    Error::InvalidValue {
                        field: "base64offset".to_string(),
                        message: e.to_string(),
                    }
                })?;
                drop(encoder);
                
                let encoded = String::from_utf8(buf).map_err(|e| {
                    Error::InvalidValue {
                        field: "base64offset".to_string(),
                        message: e.to_string(),
                    }
                })?;
                
                // Skip the padding bytes at the beginning
                let skip_chars = (offset * 4 + 2) / 3;
                if encoded.len() > skip_chars {
                    result.push(encoded[skip_chars..].to_string());
                }
            }
        }
        
        // Apply other string modifiers (contains, startswith, endswith)
        let mut final_result = Vec::new();
        for variant in result {
            let mut processed = variant;
            if modifiers.contains(&Modifier::Contains) {
                processed = format!("*{}*", processed);
            } else if modifiers.contains(&Modifier::StartsWith) {
                processed = format!("{}*", processed);
            } else if modifiers.contains(&Modifier::EndsWith) {
                processed = format!("*{}", processed);
            }
            final_result.push(processed);
        }
        
        Ok(final_result)
    }

    /// Apply string transformation modifiers to a value.
    fn apply_string_modifiers(s: &str, modifiers: &[Modifier]) -> Result<String> {
        let mut result = s.to_string();

        for modifier in modifiers {
            result = match modifier {
                Modifier::Contains => format!("*{}*", result),
                Modifier::StartsWith => format!("{}*", result),
                Modifier::EndsWith => format!("*{}", result),
                Modifier::Base64 => {
                    use std::io::Write;
                    let mut buf = Vec::new();
                    let mut encoder = base64::write::EncoderWriter::new(&mut buf, &base64::engine::general_purpose::STANDARD);
                    encoder.write_all(result.as_bytes()).map_err(|e| {
                        Error::InvalidValue {
                            field: "base64".to_string(),
                            message: e.to_string(),
                        }
                    })?;
                    drop(encoder);
                    String::from_utf8(buf).map_err(|e| {
                        Error::InvalidValue {
                            field: "base64".to_string(),
                            message: e.to_string(),
                        }
                    })?
                }
                Modifier::Wide | Modifier::Utf16Le => {
                    // Convert to UTF-16LE
                    let utf16: Vec<u16> = result.encode_utf16().collect();
                    let bytes: Vec<u8> = utf16.iter()
                        .flat_map(|&c| c.to_le_bytes())
                        .collect();
                    String::from_utf8_lossy(&bytes).to_string()
                }
                Modifier::Utf16Be => {
                    // Convert to UTF-16BE
                    let utf16: Vec<u16> = result.encode_utf16().collect();
                    let bytes: Vec<u8> = utf16.iter()
                        .flat_map(|&c| c.to_be_bytes())
                        .collect();
                    String::from_utf8_lossy(&bytes).to_string()
                }
                // Skip these modifiers as they're handled separately
                Modifier::Base64Offset | Modifier::Windash => result,
                _ => result, // Other modifiers don't transform the string
            };
        }

        Ok(result)
    }

    /// Match an event against this rule.
    ///
    /// The `event` parameter can be any type that implements [`Event`], including
    /// a plain [`std::collections::HashMap`]`<String, String>` or a custom struct.
    ///
    /// # Arguments
    /// * `event` - The event to match
    ///
    /// # Returns
    /// `true` if the event matches any of the rule's conditions, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::{SigmaCollection, SigmaDocument, SigmaRuleMatcher};
    /// use std::collections::HashMap;
    ///
    /// let yaml = r#"
    /// title: Test
    /// logsource:
    ///     product: windows
    /// detection:
    ///     sel:
    ///         Image|endswith: '\cmd.exe'
    ///     condition: sel
    /// "#;
    ///
    /// let collection = SigmaCollection::from_yaml(yaml).unwrap();
    /// let rule = match &collection.documents[0] {
    ///     SigmaDocument::Rule(r) => r.clone(),
    ///     _ => panic!("Expected rule"),
    /// };
    /// let matcher = SigmaRuleMatcher::new(rule).unwrap();
    ///
    /// let mut event = HashMap::new();
    /// event.insert("Image".to_string(), r"C:\Windows\System32\cmd.exe".to_string());
    /// assert!(matcher.matches(&event));
    /// ```
    pub fn matches<E: Event>(&self, event: &E) -> bool {
        // Evaluate all conditions (they are implicitly OR-connected)
        for condition in &self.rule.detection.conditions {
            if self.eval_condition(condition, event) {
                return true;
            }
        }
        false
    }

    /// Evaluate a condition expression against an event.
    fn eval_condition<E: Event>(&self, expr: &ConditionExpression, event: &E) -> bool {
        match expr {
            ConditionExpression::Identifier(name) => {
                self.eval_search_identifier(name, event)
            }
            ConditionExpression::And(left, right) => {
                self.eval_condition(left, event) && self.eval_condition(right, event)
            }
            ConditionExpression::Or(left, right) => {
                self.eval_condition(left, event) || self.eval_condition(right, event)
            }
            ConditionExpression::Not(inner) => {
                !self.eval_condition(inner, event)
            }
            ConditionExpression::OneOfThem => {
                self.eval_one_of_them(event)
            }
            ConditionExpression::AllOfThem => {
                self.eval_all_of_them(event)
            }
            ConditionExpression::OneOfPattern(pattern) => {
                self.eval_one_of_pattern(pattern, event)
            }
            ConditionExpression::AllOfPattern(pattern) => {
                self.eval_all_of_pattern(pattern, event)
            }
        }
    }

    /// Evaluate a search identifier against an event.
    fn eval_search_identifier<E: Event>(&self, name: &str, event: &E) -> bool {
        if let Some(search) = self.compiled_searches.get(name) {
            match search {
                CompiledSearch::Map(items) => {
                    self.eval_detection_items_and(items, event)
                }
                CompiledSearch::MapList(maps) => {
                    // OR-connected list of AND-connected groups
                    for items in maps {
                        if self.eval_detection_items_and(items, event) {
                            return true;
                        }
                    }
                    false
                }
            }
        } else {
            false
        }
    }

    /// Evaluate a list of detection items with AND logic.
    fn eval_detection_items_and<E: Event>(&self, items: &[CompiledDetectionItem], event: &E) -> bool {
        for item in items {
            if !self.eval_detection_item(item, event) {
                return false;
            }
        }
        true
    }

    /// Evaluate a single detection item against an event.
    fn eval_detection_item<E: Event>(&self, item: &CompiledDetectionItem, event: &E) -> bool {
        // Handle exists modifier
        if item.modifiers.contains(&Modifier::Exists) {
            if let Some(field) = &item.field {
                let exists = event.has_field(field);
                // The pattern should be a boolean indicating desired existence
                if let Some(CompiledPattern::Bool(should_exist)) = item.patterns.first() {
                    return exists == *should_exist;
                }
            }
            return false;
        }

        // Get the value to match against
        let value_to_match: Cow<'_, str> = if let Some(field) = &item.field {
            // Field matching
            if let Some(val) = event.get_field(field) {
                Cow::Borrowed(val)
            } else {
                // Field doesn't exist in event
                return false;
            }
        } else {
            // Keyword search - use the raw event representation
            event.raw()
        };

        // Check if ALL modifier is present
        let use_all_logic = item.modifiers.contains(&Modifier::All);

        if use_all_logic {
            // ALL: all patterns must match
            for pattern in &item.patterns {
                if !self.match_pattern(pattern, &value_to_match, &item.modifiers) {
                    return false;
                }
            }
            true
        } else {
            // Default OR: any pattern can match
            for pattern in &item.patterns {
                if self.match_pattern(pattern, &value_to_match, &item.modifiers) {
                    return true;
                }
            }
            false
        }
    }

    /// Match a compiled pattern against a value.
    fn match_pattern(&self, pattern: &CompiledPattern, value: &str, modifiers: &[Modifier]) -> bool {
        let case_sensitive = modifiers.contains(&Modifier::Cased);
        let negate = modifiers.contains(&Modifier::Neq);

        let matches = match pattern {
            CompiledPattern::Exact(s) => {
                if case_sensitive {
                    value == s
                } else {
                    value.eq_ignore_ascii_case(s)
                }
            }
            CompiledPattern::Wildcard(pattern_str) => {
                self.match_wildcard(pattern_str, value, case_sensitive)
            }
            CompiledPattern::Regex(regex_str) => {
                // For production use, we should cache compiled regex patterns
                // For now, we'll do a simple implementation
                self.match_regex(regex_str, value, modifiers)
            }
            CompiledPattern::Int(i) => {
                if let Ok(parsed) = value.parse::<i64>() {
                    self.match_numeric_int(parsed, *i, modifiers)
                } else {
                    false
                }
            }
            CompiledPattern::Float(f) => {
                if let Ok(parsed) = value.parse::<f64>() {
                    self.match_numeric_float(parsed, *f, modifiers)
                } else {
                    false
                }
            }
            CompiledPattern::Bool(b) => {
                value.eq_ignore_ascii_case(&b.to_string())
            }
            CompiledPattern::Null => {
                value.is_empty() || value.eq_ignore_ascii_case("null")
            }
        };

        if negate {
            !matches
        } else {
            matches
        }
    }

    /// Match a wildcard pattern against a value.
    fn match_wildcard(&self, pattern: &str, value: &str, case_sensitive: bool) -> bool {
        let pattern_chars: Vec<char> = pattern.chars().collect();
        let value_chars: Vec<char> = value.chars().collect();
        
        self.match_wildcard_recursive(&pattern_chars, 0, &value_chars, 0, case_sensitive)
    }

    /// Recursive wildcard matching implementation.
    fn match_wildcard_recursive(
        &self,
        pattern: &[char],
        p_idx: usize,
        value: &[char],
        v_idx: usize,
        case_sensitive: bool,
    ) -> bool {
        // Base cases
        if p_idx >= pattern.len() && v_idx >= value.len() {
            return true; // Both exhausted
        }
        if p_idx >= pattern.len() {
            return false; // Pattern exhausted but value remains
        }

        match pattern[p_idx] {
            '*' => {
                // Multi-character wildcard
                // Try matching zero or more characters
                if self.match_wildcard_recursive(pattern, p_idx + 1, value, v_idx, case_sensitive) {
                    return true;
                }
                if v_idx < value.len() {
                    return self.match_wildcard_recursive(pattern, p_idx, value, v_idx + 1, case_sensitive);
                }
                false
            }
            '?' => {
                // Single-character wildcard
                if v_idx >= value.len() {
                    return false;
                }
                self.match_wildcard_recursive(pattern, p_idx + 1, value, v_idx + 1, case_sensitive)
            }
            ch => {
                // Literal character
                if v_idx >= value.len() {
                    return false;
                }
                let matches = if case_sensitive {
                    ch == value[v_idx]
                } else {
                    ch.to_ascii_lowercase() == value[v_idx].to_ascii_lowercase()
                };
                if matches {
                    self.match_wildcard_recursive(pattern, p_idx + 1, value, v_idx + 1, case_sensitive)
                } else {
                    false
                }
            }
        }
    }

    /// Match a regex pattern against a value.
    fn match_regex(&self, regex_str: &str, value: &str, modifiers: &[Modifier]) -> bool {
        // Build regex flags from modifiers
        let mut flags = String::new();
        if modifiers.contains(&Modifier::I) {
            flags.push_str("(?i)");
        }
        if modifiers.contains(&Modifier::M) {
            flags.push_str("(?m)");
        }
        if modifiers.contains(&Modifier::S) {
            flags.push_str("(?s)");
        }

        let pattern = format!("{}{}", flags, regex_str);

        // Check cache first
        {
            let cache = REGEX_CACHE.lock().unwrap();
            if let Some(cached) = cache.get(&pattern) {
                return match cached {
                    Ok(regex) => regex.is_match(value),
                    Err(_) => false, // Cached as invalid
                };
            }
        }

        // Compile and cache
        let result = Regex::new(&pattern);
        let matches = match &result {
            Ok(regex) => regex.is_match(value),
            Err(_) => false,
        };

        // Cache the result (either the compiled regex or the error)
        {
            let mut cache = REGEX_CACHE.lock().unwrap();
            cache.insert(
                pattern,
                result.map_err(|e| e.to_string()),
            );
        }

        matches
    }

    /// Match numeric comparisons for integers.
    fn match_numeric_int(&self, value: i64, pattern: i64, modifiers: &[Modifier]) -> bool {
        if modifiers.contains(&Modifier::Lt) {
            value < pattern
        } else if modifiers.contains(&Modifier::Lte) {
            value <= pattern
        } else if modifiers.contains(&Modifier::Gt) {
            value > pattern
        } else if modifiers.contains(&Modifier::Gte) {
            value >= pattern
        } else {
            value == pattern
        }
    }

    /// Match numeric comparisons for floats.
    fn match_numeric_float(&self, value: f64, pattern: f64, modifiers: &[Modifier]) -> bool {
        if modifiers.contains(&Modifier::Lt) {
            value < pattern
        } else if modifiers.contains(&Modifier::Lte) {
            value <= pattern
        } else if modifiers.contains(&Modifier::Gt) {
            value > pattern
        } else if modifiers.contains(&Modifier::Gte) {
            value >= pattern
        } else {
            (value - pattern).abs() < f64::EPSILON
        }
    }

    /// Evaluate "1 of them" - any non-underscore-prefixed search identifier matches.
    fn eval_one_of_them<E: Event>(&self, event: &E) -> bool {
        for name in self.compiled_searches.keys() {
            if !name.starts_with('_') && self.eval_search_identifier(name, event) {
                return true;
            }
        }
        false
    }

    /// Evaluate "all of them" - all non-underscore-prefixed search identifiers match.
    fn eval_all_of_them<E: Event>(&self, event: &E) -> bool {
        let mut found_any = false;
        for name in self.compiled_searches.keys() {
            if !name.starts_with('_') {
                found_any = true;
                if !self.eval_search_identifier(name, event) {
                    return false;
                }
            }
        }
        found_any
    }

    /// Evaluate "1 of pattern" - any matching search identifier matches.
    fn eval_one_of_pattern<E: Event>(&self, pattern: &str, event: &E) -> bool {
        for name in self.compiled_searches.keys() {
            if self.match_identifier_pattern(name, pattern) && self.eval_search_identifier(name, event) {
                return true;
            }
        }
        false
    }

    /// Evaluate "all of pattern" - all matching search identifiers match.
    fn eval_all_of_pattern<E: Event>(&self, pattern: &str, event: &E) -> bool {
        let mut found_any = false;
        for name in self.compiled_searches.keys() {
            if self.match_identifier_pattern(name, pattern) {
                found_any = true;
                if !self.eval_search_identifier(name, event) {
                    return false;
                }
            }
        }
        found_any
    }

    /// Check if an identifier name matches a pattern (with wildcards).
    fn match_identifier_pattern(&self, name: &str, pattern: &str) -> bool {
        self.match_wildcard(pattern, name, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matcher_simple_exact_match() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
        Image: 'C:\Windows\System32\cmd.exe'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("EventID".to_string(), "4688".to_string());
        event.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());

        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_no_match() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("EventID".to_string(), "4689".to_string());

        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_matcher_with_contains() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("CommandLine".to_string(), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string());

        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_and_condition() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
        Image|endswith: '\cmd.exe'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("EventID".to_string(), "4688".to_string());
        event.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());

        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_not_condition() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
    filter:
        Image|endswith: '\svchost.exe'
    condition: selection and not filter
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("EventID".to_string(), "4688".to_string());
        event1.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("EventID".to_string(), "4688".to_string());
        event2.insert("Image".to_string(), "C:\\Windows\\System32\\svchost.exe".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_or_values() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        Image:
            - 'C:\Windows\System32\cmd.exe'
            - 'C:\Windows\System32\powershell.exe'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Image".to_string(), "C:\\Windows\\System32\\powershell.exe".to_string());
        assert!(matcher.matches(&event2));

        let mut event3 = HashMap::new();
        event3.insert("Image".to_string(), "C:\\Windows\\System32\\notepad.exe".to_string());
        assert!(!matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_all_modifier() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '-enc'
            - '-nop'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("CommandLine".to_string(), "powershell.exe -enc abc123 -nop".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("CommandLine".to_string(), "powershell.exe -enc abc123".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_exists() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        EventID: 4738
        PasswordLastSet|exists: true
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("EventID".to_string(), "4738".to_string());
        event1.insert("PasswordLastSet".to_string(), "some_value".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("EventID".to_string(), "4738".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_startswith() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        Image|startswith: 'C:\Windows\'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Image".to_string(), "C:\\Program Files\\app.exe".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_case_sensitivity() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        User|cased: 'SYSTEM'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("User".to_string(), "SYSTEM".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("User".to_string(), "system".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_one_of_them() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    sel1:
        EventID: 4688
    sel2:
        EventID: 4689
    condition: 1 of them
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("EventID".to_string(), "4688".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("EventID".to_string(), "4689".to_string());
        assert!(matcher.matches(&event2));

        let mut event3 = HashMap::new();
        event3.insert("EventID".to_string(), "1234".to_string());
        assert!(!matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_one_of_pattern() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\cmd.exe'
    selection_powershell:
        Image|endswith: '\powershell.exe'
    filter_sys:
        User: SYSTEM
    condition: 1 of selection* and not filter_sys
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());
        event1.insert("User".to_string(), "admin".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Image".to_string(), "C:\\Windows\\System32\\powershell.exe".to_string());
        event2.insert("User".to_string(), "admin".to_string());
        assert!(matcher.matches(&event2));

        let mut event3 = HashMap::new();
        event3.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());
        event3.insert("User".to_string(), "SYSTEM".to_string());
        assert!(!matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_wildcard() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        Image: '*\cmd.exe'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Image".to_string(), "C:\\temp\\cmd.exe".to_string());
        assert!(matcher.matches(&event2));

        // This should NOT match because there's no backslash before cmd.exe
        let mut event3 = HashMap::new();
        event3.insert("Image".to_string(), "cmd.exe".to_string());
        assert!(!matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_wildcard_any() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        Image: '*cmd.exe'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Image".to_string(), "cmd.exe".to_string());
        assert!(matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_regex() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|re: '^powershell\.exe.*-enc.*$'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("CommandLine".to_string(), "powershell.exe -enc abc123".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("CommandLine".to_string(), "cmd.exe -enc abc123".to_string());
        assert!(!matcher.matches(&event2));

        let mut event3 = HashMap::new();
        event3.insert("CommandLine".to_string(), "test powershell.exe -enc abc123".to_string());
        assert!(!matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_regex_case_insensitive() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        User|re|i: '^admin'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("User".to_string(), "Administrator".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("User".to_string(), "ADMIN".to_string());
        assert!(matcher.matches(&event2));

        let mut event3 = HashMap::new();
        event3.insert("User".to_string(), "testadmin".to_string());
        assert!(!matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_base64_modifier() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        CommandLine|base64|contains: 'test'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // "test" in base64 is "dGVzdA=="
        let mut event = HashMap::new();
        event.insert("CommandLine".to_string(), "some dGVzdA== command".to_string());
        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_base64offset_modifier() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        CommandLine|base64offset|contains: 'test'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // Test with offset 0: "test" -> "dGVzdA=="
        let mut event1 = HashMap::new();
        event1.insert("CommandLine".to_string(), "prefix dGVzdA== suffix".to_string());
        assert!(matcher.matches(&event1));

        // Test with offset 1: prepend one byte -> "AHRlc3Q=" -> skip 2 -> "Rlc3Q="
        let mut event2 = HashMap::new();
        event2.insert("CommandLine".to_string(), "prefix Rlc3Q= suffix".to_string());
        assert!(matcher.matches(&event2));

        // Test with offset 2: prepend two bytes -> "AAB0ZXN0" -> skip 3 -> "0ZXN0"
        let mut event3 = HashMap::new();
        event3.insert("CommandLine".to_string(), "prefix 0ZXN0 suffix".to_string());
        assert!(matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_windash_modifier() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|windash|contains: 'test-flag'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // Test with hyphen-minus
        let mut event1 = HashMap::new();
        event1.insert("CommandLine".to_string(), "cmd.exe test-flag".to_string());
        assert!(matcher.matches(&event1));

        // Test with forward slash
        let mut event2 = HashMap::new();
        event2.insert("CommandLine".to_string(), "cmd.exe test/flag".to_string());
        assert!(matcher.matches(&event2));

        // Test with en-dash
        let mut event3 = HashMap::new();
        event3.insert("CommandLine".to_string(), "cmd.exe test–flag".to_string());
        assert!(matcher.matches(&event3));

        // Test with em-dash
        let mut event4 = HashMap::new();
        event4.insert("CommandLine".to_string(), "cmd.exe test—flag".to_string());
        assert!(matcher.matches(&event4));

        // Test with horizontal bar
        let mut event5 = HashMap::new();
        event5.insert("CommandLine".to_string(), "cmd.exe test―flag".to_string());
        assert!(matcher.matches(&event5));
    }

    #[test]
    fn test_matcher_utf16_modifiers() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|utf16le|contains: 'A'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // "A" in UTF-16LE is "A\x00"
        let mut event = HashMap::new();
        event.insert("Data".to_string(), "prefix A\x00 suffix".to_string());
        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_wide_modifier() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|wide|contains: 'AB'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // "AB" in UTF-16LE (wide) is "A\x00B\x00"
        let mut event = HashMap::new();
        event.insert("Data".to_string(), "prefix A\x00B\x00 suffix".to_string());
        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_neq_modifier() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        EventID: 4688
        User|neq: 'SYSTEM'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("EventID".to_string(), "4688".to_string());
        event1.insert("User".to_string(), "Administrator".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("EventID".to_string(), "4688".to_string());
        event2.insert("User".to_string(), "SYSTEM".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_numeric_lt() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Count|lt: 100
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Count".to_string(), "50".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Count".to_string(), "150".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_numeric_lte() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Count|lte: 100
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Count".to_string(), "100".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Count".to_string(), "101".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_numeric_gt() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Count|gt: 100
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Count".to_string(), "150".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Count".to_string(), "50".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_numeric_gte() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Count|gte: 100
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Count".to_string(), "100".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Count".to_string(), "99".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_windash_multiple_dashes() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|windash|contains: 'test-flag-value'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // Test with mixed dash types
        let mut event = HashMap::new();
        event.insert("CommandLine".to_string(), "cmd.exe test/flag—value".to_string());
        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_base64offset_with_wide() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|wide|base64offset|contains: 'test'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // This should match one of the base64-encoded UTF-16LE variants of "test"
        // UTF-16LE of "test" is "t\x00e\x00s\x00t\x00" (bytes: 74 00 65 00 73 00 74 00)
        // Offset 0: "dABlAHMAdAA="
        let mut event = HashMap::new();
        event.insert("CommandLine".to_string(), "prefix dABlAHMAdAA= suffix".to_string());
        assert!(matcher.matches(&event));
        
        // Offset 1: skip 2 -> "QAZQBzAHQA"
        let mut event2 = HashMap::new();
        event2.insert("CommandLine".to_string(), "prefix QAZQBzAHQA suffix".to_string());
        assert!(matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_or_condition() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    sel1:
        EventID: 4688
    sel2:
        EventID: 4689
    condition: sel1 or sel2
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("EventID".to_string(), "4688".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("EventID".to_string(), "4689".to_string());
        assert!(matcher.matches(&event2));

        let mut event3 = HashMap::new();
        event3.insert("EventID".to_string(), "9999".to_string());
        assert!(!matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_all_of_them() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    sel1:
        EventID: 4688
    sel2:
        Image|endswith: '\cmd.exe'
    condition: all of them
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("EventID".to_string(), "4688".to_string());
        event1.insert("Image".to_string(), "C:\\Windows\\cmd.exe".to_string());
        assert!(matcher.matches(&event1));

        // Only one matches
        let mut event2 = HashMap::new();
        event2.insert("EventID".to_string(), "4688".to_string());
        event2.insert("Image".to_string(), "notepad.exe".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_all_of_pattern() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    sel_id:
        EventID: 4688
    sel_img:
        Image|endswith: '\cmd.exe'
    condition: all of sel*
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("EventID".to_string(), "4688".to_string());
        event1.insert("Image".to_string(), "C:\\Windows\\cmd.exe".to_string());
        assert!(matcher.matches(&event1));

        // Only one matches
        let mut event2 = HashMap::new();
        event2.insert("EventID".to_string(), "4688".to_string());
        event2.insert("Image".to_string(), "notepad.exe".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_maplist_detection() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        - EventID: 4688
          Image|endswith: '\cmd.exe'
        - EventID: 4689
          Image|endswith: '\powershell.exe'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // First map matches
        let mut event1 = HashMap::new();
        event1.insert("EventID".to_string(), "4688".to_string());
        event1.insert("Image".to_string(), "C:\\Windows\\cmd.exe".to_string());
        assert!(matcher.matches(&event1));

        // Second map matches
        let mut event2 = HashMap::new();
        event2.insert("EventID".to_string(), "4689".to_string());
        event2.insert("Image".to_string(), "C:\\Windows\\powershell.exe".to_string());
        assert!(matcher.matches(&event2));

        // Neither matches (wrong combo)
        let mut event3 = HashMap::new();
        event3.insert("EventID".to_string(), "4688".to_string());
        event3.insert("Image".to_string(), "C:\\Windows\\powershell.exe".to_string());
        assert!(!matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_int_value() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Count: 42
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Count".to_string(), "42".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Count".to_string(), "99".to_string());
        assert!(!matcher.matches(&event2));

        // Non-parseable number should not match
        let mut event3 = HashMap::new();
        event3.insert("Count".to_string(), "abc".to_string());
        assert!(!matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_float_value() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Score: 3.14
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Score".to_string(), "3.14".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Score".to_string(), "2.71".to_string());
        assert!(!matcher.matches(&event2));

        let mut event3 = HashMap::new();
        event3.insert("Score".to_string(), "abc".to_string());
        assert!(!matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_float_comparisons() {
        // lt
        let yaml_lt = r#"
title: Test
logsource:
    product: test
detection:
    selection:
        Score|lt: 5.0
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml_lt).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };
        let matcher = SigmaRuleMatcher::new(rule).unwrap();
        let mut event = HashMap::new();
        event.insert("Score".to_string(), "3.0".to_string());
        assert!(matcher.matches(&event));
        event.insert("Score".to_string(), "7.0".to_string());
        assert!(!matcher.matches(&event));

        // lte
        let yaml_lte = r#"
title: Test
logsource:
    product: test
detection:
    selection:
        Score|lte: 5.0
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml_lte).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };
        let matcher = SigmaRuleMatcher::new(rule).unwrap();
        let mut event = HashMap::new();
        event.insert("Score".to_string(), "5.0".to_string());
        assert!(matcher.matches(&event));
        event.insert("Score".to_string(), "6.0".to_string());
        assert!(!matcher.matches(&event));

        // gt
        let yaml_gt = r#"
title: Test
logsource:
    product: test
detection:
    selection:
        Score|gt: 5.0
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml_gt).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };
        let matcher = SigmaRuleMatcher::new(rule).unwrap();
        let mut event = HashMap::new();
        event.insert("Score".to_string(), "7.0".to_string());
        assert!(matcher.matches(&event));
        event.insert("Score".to_string(), "3.0".to_string());
        assert!(!matcher.matches(&event));

        // gte
        let yaml_gte = r#"
title: Test
logsource:
    product: test
detection:
    selection:
        Score|gte: 5.0
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml_gte).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };
        let matcher = SigmaRuleMatcher::new(rule).unwrap();
        let mut event = HashMap::new();
        event.insert("Score".to_string(), "5.0".to_string());
        assert!(matcher.matches(&event));
        event.insert("Score".to_string(), "4.0".to_string());
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_matcher_bool_pattern() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Enabled: true
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("Enabled".to_string(), "true".to_string());
        assert!(matcher.matches(&event));

        event.insert("Enabled".to_string(), "false".to_string());
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_matcher_null_pattern() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Field: null
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("Field".to_string(), "".to_string());
        assert!(matcher.matches(&event));

        event.insert("Field".to_string(), "null".to_string());
        assert!(matcher.matches(&event));

        event.insert("Field".to_string(), "something".to_string());
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_matcher_keyword_search() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    keywords:
        - '*suspicious*'
        - '*malware*'
    condition: keywords
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("Field1".to_string(), "this is suspicious activity".to_string());
        assert!(matcher.matches(&event));

        let mut event2 = HashMap::new();
        event2.insert("Field1".to_string(), "normal activity".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_missing_field() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        NonExistentField: 'value'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("OtherField".to_string(), "value".to_string());
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_matcher_missing_search_identifier() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        EventID: 4688
    condition: missing_identifier
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("EventID".to_string(), "4688".to_string());
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_matcher_wildcard_single_char() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Image: 'cmd.ex?'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event1 = HashMap::new();
        event1.insert("Image".to_string(), "cmd.exe".to_string());
        assert!(matcher.matches(&event1));

        let mut event2 = HashMap::new();
        event2.insert("Image".to_string(), "cmd.exa".to_string());
        assert!(matcher.matches(&event2));

        // ? requires exactly one char
        let mut event3 = HashMap::new();
        event3.insert("Image".to_string(), "cmd.ex".to_string());
        assert!(!matcher.matches(&event3));
    }

    #[test]
    fn test_matcher_regex_multiline_flag() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|re|m: '^start'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("Data".to_string(), "prefix\nstart of new line".to_string());
        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_regex_dotall_flag() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|re|s: 'start.*end'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("Data".to_string(), "start\nmiddle\nend".to_string());
        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_regex_invalid() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|re: '[invalid'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("Data".to_string(), "test".to_string());
        // Invalid regex should not match
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_matcher_utf16be_modifier() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|utf16be|contains: 'A'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // "A" in UTF-16BE is "\x00A"
        let mut event = HashMap::new();
        event.insert("Data".to_string(), "prefix \x00A suffix".to_string());
        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_base64offset_with_utf16be() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|utf16be|base64offset|contains: 'A'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        // Should compile without error
        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // UTF-16BE "A" = [0x00, 0x41]
        // Offset 0: base64([0x00, 0x41]) = "AEE=" -> skip 0 -> "AEE="
        let mut event = HashMap::new();
        event.insert("Data".to_string(), "prefix AEE= suffix".to_string());
        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_base64offset_startswith() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|base64offset|startswith: 'test'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let _matcher = SigmaRuleMatcher::new(rule).unwrap();
    }

    #[test]
    fn test_matcher_base64offset_endswith() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|base64offset|endswith: 'test'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let _matcher = SigmaRuleMatcher::new(rule).unwrap();
    }

    #[test]
    fn test_matcher_one_of_them_no_match() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    sel1:
        EventID: 4688
    sel2:
        EventID: 4689
    condition: 1 of them
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("EventID".to_string(), "9999".to_string());
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_matcher_all_of_them_empty_non_underscore() {
        // All search identifiers start with _ (should return false for all of them)
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    _filter:
        EventID: 4688
    condition: all of them
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("EventID".to_string(), "4688".to_string());
        // Should return false since no non-underscore-prefixed identifiers exist
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_matcher_one_of_pattern_no_match() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    sel_a:
        EventID: 4688
    other_b:
        EventID: 4689
    condition: 1 of sel*
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("EventID".to_string(), "9999".to_string());
        // sel_a doesn't match, other_b is not in pattern
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_matcher_all_of_pattern_no_match_pattern() {
        // Test all of pattern* where no identifiers match the pattern
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    other_a:
        EventID: 4688
    condition: all of sel*
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("EventID".to_string(), "4688".to_string());
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_matcher_exists_false() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Field|exists: false
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // Field does not exist - should match exists:false
        let mut event1 = HashMap::new();
        event1.insert("Other".to_string(), "val".to_string());
        assert!(matcher.matches(&event1));

        // Field exists - should not match exists:false
        let mut event2 = HashMap::new();
        event2.insert("Field".to_string(), "val".to_string());
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_matcher_windash_with_expansion_re() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|windash|re: 'test-data'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("Data".to_string(), "test/data".to_string());
        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_windash_no_dash() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|windash|contains: 'nodash'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("Data".to_string(), "prefix nodash suffix".to_string());
        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_windash_exact() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Data|windash: 'test-val'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("Data".to_string(), "test/val".to_string());
        assert!(matcher.matches(&event));
    }

    #[test]
    fn test_matcher_base64offset_non_string_value() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Count|base64offset: 42
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };

        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut event = HashMap::new();
        event.insert("Count".to_string(), "42".to_string());
        assert!(matcher.matches(&event));
    }

    // ── Event trait tests ────────────────────────────────────────────────────

    /// A minimal custom event type used to verify that any type implementing
    /// [`Event`] works with [`SigmaRuleMatcher::matches`].
    struct CustomEvent {
        fields: HashMap<String, String>,
        raw_line: Option<String>,
    }

    impl Event for CustomEvent {
        fn get_field(&self, field: &str) -> Option<&str> {
            self.fields.get(field).map(String::as_str)
        }

        fn has_field(&self, field: &str) -> bool {
            self.fields.contains_key(field)
        }

        fn raw(&self) -> std::borrow::Cow<'_, str> {
            match &self.raw_line {
                Some(r) => std::borrow::Cow::Borrowed(r.as_str()),
                None => std::borrow::Cow::Owned(
                    self.fields.values().map(String::as_str).collect::<Vec<_>>().join(" ")
                ),
            }
        }
    }

    #[test]
    fn test_custom_event_field_match() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };
        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut fields = HashMap::new();
        fields.insert("Image".to_string(), r"C:\Windows\System32\cmd.exe".to_string());
        let event = CustomEvent { fields, raw_line: None };

        assert!(matcher.matches(&event));

        let mut fields2 = HashMap::new();
        fields2.insert("Image".to_string(), r"C:\Windows\System32\notepad.exe".to_string());
        let event2 = CustomEvent { fields: fields2, raw_line: None };
        assert!(!matcher.matches(&event2));
    }

    #[test]
    fn test_custom_event_exists_modifier() {
        let yaml = r#"
title: Test Rule
logsource:
    product: test
detection:
    selection:
        SomeField|exists: true
    condition: selection
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };
        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        let mut fields = HashMap::new();
        fields.insert("SomeField".to_string(), "anything".to_string());
        let event = CustomEvent { fields, raw_line: None };
        assert!(matcher.matches(&event));

        let event_missing = CustomEvent { fields: HashMap::new(), raw_line: None };
        assert!(!matcher.matches(&event_missing));
    }

    #[test]
    fn test_custom_event_keyword_uses_raw_when_available() {
        let yaml = r#"
title: Keyword Rule
logsource:
    product: test
detection:
    keywords:
        - '*suspicious_token*'
    condition: keywords
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };
        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // When raw is set, keyword matching uses it — even if field values don't contain the token
        let event_with_raw = CustomEvent {
            fields: {
                let mut m = HashMap::new();
                m.insert("EventID".to_string(), "1234".to_string());
                m
            },
            raw_line: Some("raw log line with suspicious_token here".to_string()),
        };
        assert!(matcher.matches(&event_with_raw));

        // Without the token in the raw string, it should not match
        let event_without_token = CustomEvent {
            fields: {
                let mut m = HashMap::new();
                m.insert("EventID".to_string(), "1234".to_string());
                m
            },
            raw_line: Some("raw log line without the target".to_string()),
        };
        assert!(!matcher.matches(&event_without_token));
    }

    #[test]
    fn test_custom_event_keyword_falls_back_to_field_values() {
        let yaml = r#"
title: Keyword Rule
logsource:
    product: test
detection:
    keywords:
        - '*suspicious_token*'
    condition: keywords
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &collection.documents[0] {
            SigmaDocument::Rule(r) => r.clone(),
            _ => panic!("Expected rule"),
        };
        let matcher = SigmaRuleMatcher::new(rule).unwrap();

        // No raw string — keyword matching falls back to joined field values
        let event_no_raw = CustomEvent {
            fields: {
                let mut m = HashMap::new();
                m.insert("Data".to_string(), "value containing suspicious_token".to_string());
                m
            },
            raw_line: None,
        };
        assert!(matcher.matches(&event_no_raw));
    }
}

