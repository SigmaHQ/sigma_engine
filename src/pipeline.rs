//! Processing pipelines for transforming Sigma rules.
//!
//! Pipelines allow transforming Sigma rules to adapt them to specific environments,
//! log sources, and SIEM platforms. They consist of an ordered sequence of transformations
//! that modify rules before they are used for detection.
//!
//! # Example
//!
//! ```rust
//! use sigma_engine::{SigmaCollection, ProcessingPipeline};
//!
//! // Define a pipeline that adapts Windows rules for Splunk
//! let pipeline_yaml = r#"
//! name: Splunk Windows Pipeline
//! priority: 10
//! transformations:
//!   - id: field_mapping
//!     type: field_name_mapping
//!     mapping:
//!       EventID:
//!         - EventCode
//!   - id: add_index
//!     type: add_condition
//!     conditions:
//!       index: "windows"
//!     rule_conditions:
//!       - type: logsource_product
//!         product: windows
//! "#;
//!
//! let pipeline = ProcessingPipeline::from_yaml(pipeline_yaml).unwrap();
//!
//! // Parse a Sigma rule
//! let rule_yaml = r#"
//! title: Suspicious Process
//! logsource:
//!     product: windows
//!     category: process_creation
//! detection:
//!     selection:
//!         EventID: 4688
//!         CommandLine: '*powershell*'
//!     condition: selection
//! "#;
//!
//! let mut collection = SigmaCollection::from_yaml(rule_yaml).unwrap();
//! if let sigma_engine::SigmaDocument::Rule(ref mut rule) = collection.documents[0] {
//!     // Apply pipeline transformations
//!     pipeline.apply(rule).unwrap();
//!     
//!     // The rule is now transformed for Splunk:
//!     // - EventID is mapped to EventCode
//!     // - index: "windows" condition is added
//! }
//! ```

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::error::{Error, Result};
use crate::types::{SigmaRule, DetectionItem, SearchIdentifier, SigmaValue, SigmaString};

// ─── Pipeline Types ──────────────────────────────────────────────────────────

/// A processing pipeline that transforms Sigma rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessingPipeline {
    /// Name of the pipeline.
    #[serde(default)]
    pub name: String,
    
    /// Priority for ordering multiple pipelines (higher = applied earlier).
    #[serde(default)]
    pub priority: i32,
    
    /// Ordered list of transformations to apply.
    #[serde(default)]
    pub transformations: Vec<ProcessingItem>,
}

impl ProcessingPipeline {
    /// Parse a pipeline from YAML.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        serde_yaml::from_str(yaml).map_err(Error::from)
    }
    
    /// Apply this pipeline to a Sigma rule, transforming it in place.
    pub fn apply(&self, rule: &mut SigmaRule) -> Result<()> {
        for item in &self.transformations {
            item.apply(rule)?;
        }
        Ok(())
    }
    
    /// Apply multiple pipelines to a rule, sorted by priority (higher priority first).
    pub fn apply_multiple(pipelines: &mut [ProcessingPipeline], rule: &mut SigmaRule) -> Result<()> {
        // Sort by priority (descending)
        pipelines.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        for pipeline in pipelines {
            pipeline.apply(rule)?;
        }
        Ok(())
    }
}

/// A single processing/transformation item in a pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessingItem {
    /// Identifier for this processing item.
    #[serde(default)]
    pub id: String,
    
    /// Type of transformation to perform.
    #[serde(rename = "type")]
    pub transformation_type: String,
    
    /// Conditions that determine when this transformation applies.
    #[serde(default)]
    pub rule_conditions: Vec<RuleCondition>,
    
    /// Field name conditions for field-specific transformations.
    #[serde(default)]
    pub field_name_conditions: Vec<FieldCondition>,
    
    /// The transformation configuration (varies by type).
    #[serde(flatten)]
    pub config: TransformationConfig,
}

impl ProcessingItem {
    /// Apply this transformation to a rule.
    fn apply(&self, rule: &mut SigmaRule) -> Result<()> {
        // Check if rule conditions are met
        if !self.rule_conditions.is_empty() && !self.check_rule_conditions(rule) {
            return Ok(());
        }
        
        // Apply the transformation based on type
        match self.transformation_type.as_str() {
            "field_name_mapping" => self.apply_field_name_mapping(rule),
            "field_name_prefix" => self.apply_field_name_prefix(rule),
            "field_name_suffix" => self.apply_field_name_suffix(rule),
            "add_field" => self.apply_add_field(rule),
            "remove_field" => self.apply_remove_field(rule),
            "replace_string" => self.apply_replace_string(rule),
            "map_string" => self.apply_map_string(rule),
            "add_condition" => self.apply_add_condition(rule),
            _ => Err(Error::InvalidValue {
                field: "transformation_type".into(),
                message: format!("Unknown transformation type: {}", self.transformation_type),
            }),
        }
    }
    
    fn check_rule_conditions(&self, rule: &SigmaRule) -> bool {
        self.rule_conditions.iter().all(|cond| cond.matches(rule))
    }
    
    fn check_field_conditions(&self, field_name: &str) -> bool {
        if self.field_name_conditions.is_empty() {
            return true;
        }
        self.field_name_conditions.iter().any(|cond| cond.matches(field_name))
    }
    
    // ── Field Transformations ────────────────────────────────────────────
    
    fn apply_field_name_mapping(&self, rule: &mut SigmaRule) -> Result<()> {
        if let Some(mapping) = &self.config.mapping {
            for search_id in rule.detection.search_identifiers.values_mut() {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        for item in items {
                            if let Some(field) = &item.field {
                                if let Some(new_names) = mapping.get(field) {
                                    if let Some(new_name) = new_names.first() {
                                        item.field = Some(new_name.clone());
                                    }
                                }
                            }
                        }
                    }
                    SearchIdentifier::MapList(maps) => {
                        for items in maps {
                            for item in items {
                                if let Some(field) = &item.field {
                                    if let Some(new_names) = mapping.get(field) {
                                        if let Some(new_name) = new_names.first() {
                                            item.field = Some(new_name.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn apply_field_name_prefix(&self, rule: &mut SigmaRule) -> Result<()> {
        if let Some(prefix) = &self.config.prefix {
            for search_id in rule.detection.search_identifiers.values_mut() {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        for item in items {
                            if let Some(field) = &mut item.field {
                                if self.check_field_conditions(field) {
                                    *field = format!("{}{}", prefix, field);
                                }
                            }
                        }
                    }
                    SearchIdentifier::MapList(maps) => {
                        for items in maps {
                            for item in items {
                                if let Some(field) = &mut item.field {
                                    if self.check_field_conditions(field) {
                                        *field = format!("{}{}", prefix, field);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn apply_field_name_suffix(&self, rule: &mut SigmaRule) -> Result<()> {
        if let Some(suffix) = &self.config.suffix {
            for search_id in rule.detection.search_identifiers.values_mut() {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        for item in items {
                            if let Some(field) = &mut item.field {
                                if self.check_field_conditions(field) {
                                    *field = format!("{}{}", field, suffix);
                                }
                            }
                        }
                    }
                    SearchIdentifier::MapList(maps) => {
                        for items in maps {
                            for item in items {
                                if let Some(field) = &mut item.field {
                                    if self.check_field_conditions(field) {
                                        *field = format!("{}{}", field, suffix);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn apply_add_field(&self, rule: &mut SigmaRule) -> Result<()> {
        if let (Some(field), Some(value)) = (&self.config.field, &self.config.value) {
            // Add field to all detection items
            for search_id in rule.detection.search_identifiers.values_mut() {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        items.push(DetectionItem {
                            field: Some(field.clone()),
                            modifiers: vec![],
                            values: vec![value.clone()],
                        });
                    }
                    SearchIdentifier::MapList(maps) => {
                        for items in maps {
                            items.push(DetectionItem {
                                field: Some(field.clone()),
                                modifiers: vec![],
                                values: vec![value.clone()],
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn apply_remove_field(&self, rule: &mut SigmaRule) -> Result<()> {
        if let Some(field) = &self.config.field {
            for search_id in rule.detection.search_identifiers.values_mut() {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        items.retain(|item| item.field.as_deref() != Some(field));
                    }
                    SearchIdentifier::MapList(maps) => {
                        for items in maps {
                            items.retain(|item| item.field.as_deref() != Some(field));
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    // ── Value Transformations ────────────────────────────────────────────
    
    fn apply_replace_string(&self, rule: &mut SigmaRule) -> Result<()> {
        if let (Some(regex_str), Some(replacement)) = (&self.config.regex, &self.config.replacement) {
            let re = regex::Regex::new(regex_str).map_err(|e| Error::InvalidValue {
                field: "regex".into(),
                message: e.to_string(),
            })?;
            
            for search_id in rule.detection.search_identifiers.values_mut() {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        for item in items {
                            if let Some(field) = &item.field {
                                if self.check_field_conditions(field) {
                                    self.replace_in_values(&mut item.values, &re, replacement);
                                }
                            }
                        }
                    }
                    SearchIdentifier::MapList(maps) => {
                        for items in maps {
                            for item in items {
                                if let Some(field) = &item.field {
                                    if self.check_field_conditions(field) {
                                        self.replace_in_values(&mut item.values, &re, replacement);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn replace_in_values(&self, values: &mut Vec<SigmaValue>, re: &regex::Regex, replacement: &str) {
        for value in values {
            if let SigmaValue::String(sigma_str) = value {
                // For simple strings, apply regex replacement
                // Complex strings with wildcards/placeholders are intentionally skipped
                // as they need special handling based on backend requirements
                if let Some(plain) = sigma_str.as_plain() {
                    let replaced = re.replace_all(plain, replacement);
                    if replaced != plain {
                        *sigma_str = SigmaString::from_literal(replaced.to_string());
                    }
                }
            }
        }
    }
    
    fn apply_map_string(&self, rule: &mut SigmaRule) -> Result<()> {
        if let Some(mapping) = &self.config.mapping {
            for search_id in rule.detection.search_identifiers.values_mut() {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        for item in items {
                            if let Some(field) = &item.field {
                                if self.check_field_conditions(field) {
                                    self.map_string_values(&mut item.values, mapping);
                                }
                            }
                        }
                    }
                    SearchIdentifier::MapList(maps) => {
                        for items in maps {
                            for item in items {
                                if let Some(field) = &item.field {
                                    if self.check_field_conditions(field) {
                                        self.map_string_values(&mut item.values, mapping);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn map_string_values(&self, values: &mut Vec<SigmaValue>, mapping: &HashMap<String, Vec<String>>) {
        for value in values {
            if let SigmaValue::String(sigma_str) = value {
                // Only map simple string values
                // Complex strings with wildcards/placeholders are intentionally skipped
                if let Some(plain) = sigma_str.as_plain() {
                    if let Some(new_values) = mapping.get(plain) {
                        if let Some(new_value) = new_values.first() {
                            *sigma_str = SigmaString::from_literal(new_value.clone());
                        }
                    }
                }
            }
        }
    }
    
    // ── Condition Transformations ────────────────────────────────────────
    
    fn apply_add_condition(&self, rule: &mut SigmaRule) -> Result<()> {
        if let Some(conditions) = &self.config.conditions {
            // Add conditions to all search identifiers
            for search_id in rule.detection.search_identifiers.values_mut() {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        for (field, value) in conditions {
                            items.push(DetectionItem {
                                field: Some(field.clone()),
                                modifiers: vec![],
                                values: vec![value.clone()],
                            });
                        }
                    }
                    SearchIdentifier::MapList(maps) => {
                        for items in maps {
                            for (field, value) in conditions {
                                items.push(DetectionItem {
                                    field: Some(field.clone()),
                                    modifiers: vec![],
                                    values: vec![value.clone()],
                                });
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

// ─── Transformation Configurations ───────────────────────────────────────────

/// Configuration for different transformation types.
/// Different fields are used based on the transformation type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TransformationConfig {
    // Field mapping
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping: Option<HashMap<String, Vec<String>>>,
    
    // Field prefix/suffix
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
    
    // Add field
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<SigmaValue>,
    
    // Replace string
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
    
    // Add condition
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<HashMap<String, SigmaValue>>,
}

// ─── Conditions ──────────────────────────────────────────────────────────────

/// Condition that determines if a transformation applies to a rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleCondition {
    /// Match rules by log source category.
    #[serde(rename = "logsource_category")]
    LogSourceCategory { category: String },
    
    /// Match rules by log source product.
    #[serde(rename = "logsource_product")]
    LogSourceProduct { product: String },
    
    /// Match rules by log source service.
    #[serde(rename = "logsource_service")]
    LogSourceService { service: String },
}

impl RuleCondition {
    fn matches(&self, rule: &SigmaRule) -> bool {
        match self {
            Self::LogSourceCategory { category } => {
                rule.logsource.category.as_deref() == Some(category)
            }
            Self::LogSourceProduct { product } => {
                rule.logsource.product.as_deref() == Some(product)
            }
            Self::LogSourceService { service } => {
                rule.logsource.service.as_deref() == Some(service)
            }
        }
    }
}

/// Condition for field-specific transformations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FieldCondition {
    /// Include only specific fields.
    #[serde(rename = "include_fields")]
    IncludeFields { fields: Vec<String> },
    
    /// Exclude specific fields.
    #[serde(rename = "exclude_fields")]
    ExcludeFields { fields: Vec<String> },
}

impl FieldCondition {
    fn matches(&self, field_name: &str) -> bool {
        match self {
            Self::IncludeFields { fields } => fields.iter().any(|f| f == field_name),
            Self::ExcludeFields { fields } => !fields.iter().any(|f| f == field_name),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Detection, ConditionExpression, LogSource};
    
    fn create_test_rule() -> SigmaRule {
        let mut search_identifiers = HashMap::new();
        search_identifiers.insert(
            "selection".to_string(),
            SearchIdentifier::Map(vec![
                DetectionItem {
                    field: Some("EventID".to_string()),
                    modifiers: vec![],
                    values: vec![SigmaValue::Int(4688)],
                },
                DetectionItem {
                    field: Some("CommandLine".to_string()),
                    modifiers: vec![],
                    values: vec![SigmaValue::String(SigmaString::from_literal("test.exe"))],
                },
            ]),
        );
        
        SigmaRule {
            title: "Test Rule".to_string(),
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            references: vec![],
            author: None,
            date: None,
            modified: None,
            logsource: LogSource {
                category: Some("process_creation".to_string()),
                product: Some("windows".to_string()),
                service: None,
                custom: HashMap::new(),
            },
            detection: Detection {
                search_identifiers,
                conditions: vec![ConditionExpression::Identifier("selection".to_string())],
            },
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec![],
            scope: vec![],
            custom: HashMap::new(),
        }
    }
    
    #[test]
    fn test_field_name_mapping() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: map_event_id
    type: field_name_mapping
    mapping:
      EventID:
        - event_id
        - evtid
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        // Check that EventID was mapped to event_id
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("event_id"));
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_field_name_prefix() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: add_prefix
    type: field_name_prefix
    prefix: "win."
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("win.EventID"));
            assert_eq!(items[1].field.as_deref(), Some("win.CommandLine"));
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_field_name_prefix_with_conditions() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: add_prefix
    type: field_name_prefix
    prefix: "win."
    field_name_conditions:
      - type: include_fields
        fields:
          - EventID
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("win.EventID"));
            assert_eq!(items[1].field.as_deref(), Some("CommandLine")); // Not modified
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_replace_string() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: replace_exe
    type: replace_string
    regex: "\\.exe$"
    replacement: ".bin"
    field_name_conditions:
      - type: include_fields
        fields:
          - CommandLine
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.as_plain(), Some("test.bin"));
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_logsource_condition() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: add_prefix
    type: field_name_prefix
    prefix: "proc."
    rule_conditions:
      - type: logsource_category
        category: process_creation
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("proc.EventID"));
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_add_field() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: add_index
    type: add_field
    field: index
    value: "windows"
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        let initial_count = match &rule.detection.search_identifiers["selection"] {
            SearchIdentifier::Map(items) => items.len(),
            _ => panic!("Expected Map"),
        };
        
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items.len(), initial_count + 1);
            let index_field = items.iter().find(|item| item.field.as_deref() == Some("index"));
            assert!(index_field.is_some());
            if let Some(field) = index_field {
                if let SigmaValue::String(s) = &field.values[0] {
                    assert_eq!(s.as_plain(), Some("windows"));
                } else {
                    panic!("Expected String value");
                }
            }
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_remove_field() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: remove_commandline
    type: remove_field
    field: CommandLine
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].field.as_deref(), Some("EventID"));
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_field_name_suffix() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: add_suffix
    type: field_name_suffix
    suffix: ".keyword"
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("EventID.keyword"));
            assert_eq!(items[1].field.as_deref(), Some("CommandLine.keyword"));
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_map_string() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: map_values
    type: map_string
    mapping:
      test.exe:
        - malware.exe
    field_name_conditions:
      - type: include_fields
        fields:
          - CommandLine
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.as_plain(), Some("malware.exe"));
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_multiple_transformations() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: map_field
    type: field_name_mapping
    mapping:
      EventID:
        - event_id
  - id: add_prefix
    type: field_name_prefix
    prefix: "win."
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            // First transformation: EventID -> event_id
            // Second transformation: event_id -> win.event_id
            assert_eq!(items[0].field.as_deref(), Some("win.event_id"));
            assert_eq!(items[1].field.as_deref(), Some("win.CommandLine"));
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_multiple_pipelines() {
        let yaml1 = r#"
name: Pipeline 1
priority: 10
transformations:
  - id: map_field
    type: field_name_mapping
    mapping:
      EventID:
        - event_id
"#;
        
        let yaml2 = r#"
name: Pipeline 2
priority: 20
transformations:
  - id: add_prefix
    type: field_name_prefix
    prefix: "win."
"#;
        
        let mut pipelines = vec![
            ProcessingPipeline::from_yaml(yaml1).unwrap(),
            ProcessingPipeline::from_yaml(yaml2).unwrap(),
        ];
        
        let mut rule = create_test_rule();
        ProcessingPipeline::apply_multiple(&mut pipelines, &mut rule).unwrap();
        
        // Pipeline 2 (priority 20) should run first, then Pipeline 1 (priority 10)
        // So: EventID -> win.EventID (mapping doesn't match "win.EventID")
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("win.EventID"));
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_exclude_fields_condition() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: add_prefix
    type: field_name_prefix
    prefix: "win."
    field_name_conditions:
      - type: exclude_fields
        fields:
          - CommandLine
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("win.EventID"));
            assert_eq!(items[1].field.as_deref(), Some("CommandLine")); // Not modified
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_add_condition() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: add_log_conditions
    type: add_condition
    conditions:
      index: "windows"
      source: "sysmon"
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        let initial_count = match &rule.detection.search_identifiers["selection"] {
            SearchIdentifier::Map(items) => items.len(),
            _ => panic!("Expected Map"),
        };
        
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items.len(), initial_count + 2);
            
            let has_index = items.iter().any(|item| item.field.as_deref() == Some("index"));
            let has_source = items.iter().any(|item| item.field.as_deref() == Some("source"));
            
            assert!(has_index);
            assert!(has_source);
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_rule_condition_not_matching() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: add_prefix
    type: field_name_prefix
    prefix: "proc."
    rule_conditions:
      - type: logsource_product
        product: linux
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule(); // Has product: windows
        pipeline.apply(&mut rule).unwrap();
        
        // Transformation should not be applied
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("EventID")); // Unchanged
        } else {
            panic!("Expected Map");
        }
    }
}
