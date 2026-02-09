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
//! let yaml = r#"
//! name: Example Pipeline
//! priority: 10
//! transformations:
//!   - id: field_mapping
//!     type: field_name_mapping
//!     mapping:
//!       EventID: event_id
//! "#;
//!
//! let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
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
        if let TransformationConfig::FieldMapping { mapping } = &self.config {
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
        if let TransformationConfig::FieldPrefix { prefix } = &self.config {
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
        if let TransformationConfig::FieldSuffix { suffix } = &self.config {
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
        if let TransformationConfig::AddField { field, value } = &self.config {
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
        if let TransformationConfig::RemoveField { field } = &self.config {
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
        if let TransformationConfig::ReplaceString { regex, replacement } = &self.config {
            let re = regex::Regex::new(regex).map_err(|e| Error::InvalidValue {
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
        if let TransformationConfig::MapString { mapping } = &self.config {
            for search_id in rule.detection.search_identifiers.values_mut() {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        for item in items {
                            if let Some(field) = &item.field {
                                if self.check_field_conditions(field) {
                                    self.map_values(&mut item.values, mapping);
                                }
                            }
                        }
                    }
                    SearchIdentifier::MapList(maps) => {
                        for items in maps {
                            for item in items {
                                if let Some(field) = &item.field {
                                    if self.check_field_conditions(field) {
                                        self.map_values(&mut item.values, mapping);
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
    
    fn map_values(&self, values: &mut Vec<SigmaValue>, mapping: &HashMap<String, String>) {
        for value in values {
            if let SigmaValue::String(sigma_str) = value {
                if let Some(plain) = sigma_str.as_plain() {
                    if let Some(new_value) = mapping.get(plain) {
                        *sigma_str = SigmaString::from_literal(new_value.clone());
                    }
                }
            }
        }
    }
    
    // ── Condition Transformations ────────────────────────────────────────
    
    fn apply_add_condition(&self, rule: &mut SigmaRule) -> Result<()> {
        if let TransformationConfig::AddCondition { conditions } = &self.config {
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransformationConfig {
    /// Map field names to new names.
    FieldMapping {
        mapping: HashMap<String, Vec<String>>,
    },
    
    /// Add a prefix to field names.
    FieldPrefix {
        prefix: String,
    },
    
    /// Add a suffix to field names.
    FieldSuffix {
        suffix: String,
    },
    
    /// Add a new field with a value.
    AddField {
        field: String,
        value: SigmaValue,
    },
    
    /// Remove a field.
    RemoveField {
        field: String,
    },
    
    /// Replace strings using regex.
    ReplaceString {
        regex: String,
        replacement: String,
    },
    
    /// Map string values to new values.
    MapString {
        mapping: HashMap<String, String>,
    },
    
    /// Add conditions to detection items.
    AddCondition {
        conditions: HashMap<String, SigmaValue>,
    },
    
    /// Catch-all for unknown configurations.
    #[serde(skip)]
    Unknown,
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
}
