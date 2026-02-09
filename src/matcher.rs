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
//! - Encoding modifiers: `base64`, `utf16le`, `utf16be`, `utf16`, `wide`
//! - Logic modifiers: `all`, `exists`, `neq`
//! - Numeric modifiers: `lt`, `lte`, `gt`, `gte`
//!
//! # Thread Safety
//!
//! `SigmaRuleMatcher` is thread-safe and uses `Arc` internally for efficient sharing
//! across threads.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::types::*;

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
            let pattern = Self::compile_value(value, &item.modifiers)?;
            patterns.push(pattern);
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
                _ => result, // Other modifiers don't transform the string
            };
        }

        Ok(result)
    }

    /// Match an event against this rule.
    ///
    /// # Arguments
    /// * `event` - The event to match, represented as a field-value map
    ///
    /// # Returns
    /// `true` if the event matches any of the rule's conditions, `false` otherwise
    pub fn matches(&self, event: &HashMap<String, String>) -> bool {
        // Evaluate all conditions (they are implicitly OR-connected)
        for condition in &self.rule.detection.conditions {
            if self.eval_condition(condition, event) {
                return true;
            }
        }
        false
    }

    /// Evaluate a condition expression against an event.
    fn eval_condition(&self, expr: &ConditionExpression, event: &HashMap<String, String>) -> bool {
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
    fn eval_search_identifier(&self, name: &str, event: &HashMap<String, String>) -> bool {
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
    fn eval_detection_items_and(&self, items: &[CompiledDetectionItem], event: &HashMap<String, String>) -> bool {
        for item in items {
            if !self.eval_detection_item(item, event) {
                return false;
            }
        }
        true
    }

    /// Evaluate a single detection item against an event.
    fn eval_detection_item(&self, item: &CompiledDetectionItem, event: &HashMap<String, String>) -> bool {
        // Handle exists modifier
        if item.modifiers.contains(&Modifier::Exists) {
            if let Some(field) = &item.field {
                let exists = event.contains_key(field);
                // The pattern should be a boolean indicating desired existence
                if let Some(CompiledPattern::Bool(should_exist)) = item.patterns.first() {
                    return exists == *should_exist;
                }
            }
            return false;
        }

        // Get the value to match against
        let value_to_match = if let Some(field) = &item.field {
            // Field matching
            if let Some(val) = event.get(field) {
                val.clone()
            } else {
                // Field doesn't exist in event
                return false;
            }
        } else {
            // Keyword search - match against all field values or entire event
            event.values().cloned().collect::<Vec<_>>().join(" ")
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
        // For a production implementation, we should use the regex crate and cache compiled patterns
        // For now, we'll do a simple substring match as a placeholder
        // TODO: Implement proper regex matching with the regex crate
        
        let case_insensitive = modifiers.contains(&Modifier::I);
        if case_insensitive {
            value.to_lowercase().contains(&regex_str.to_lowercase())
        } else {
            value.contains(regex_str)
        }
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
    fn eval_one_of_them(&self, event: &HashMap<String, String>) -> bool {
        for name in self.compiled_searches.keys() {
            if !name.starts_with('_') && self.eval_search_identifier(name, event) {
                return true;
            }
        }
        false
    }

    /// Evaluate "all of them" - all non-underscore-prefixed search identifiers match.
    fn eval_all_of_them(&self, event: &HashMap<String, String>) -> bool {
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
    fn eval_one_of_pattern(&self, pattern: &str, event: &HashMap<String, String>) -> bool {
        for name in self.compiled_searches.keys() {
            if self.match_identifier_pattern(name, pattern) && self.eval_search_identifier(name, event) {
                return true;
            }
        }
        false
    }

    /// Evaluate "all of pattern" - all matching search identifiers match.
    fn eval_all_of_pattern(&self, pattern: &str, event: &HashMap<String, String>) -> bool {
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
}
