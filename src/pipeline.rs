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
use crate::types::{SigmaRule, DetectionItem, SearchIdentifier, SigmaValue, SigmaString, SigmaStringPart};

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
    
    /// Variables for placeholder replacement (used by `value_placeholders` transformation).
    /// Maps placeholder names to lists of replacement values.
    /// Available to all transformations via the pipeline context.
    #[serde(default)]
    pub vars: HashMap<String, Vec<String>>,
}

impl ProcessingPipeline {
    /// Parse a pipeline from YAML.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        serde_yaml::from_str(yaml).map_err(Error::from)
    }
    
    /// Apply this pipeline to a Sigma rule, transforming it in place.
    pub fn apply(&self, rule: &mut SigmaRule) -> Result<()> {
        for item in &self.transformations {
            item.apply(rule, &self.vars)?;
        }
        Ok(())
    }
    
    /// Apply multiple pipelines to a rule, sorted by priority (lower priority first).
    pub fn apply_multiple(pipelines: &mut [ProcessingPipeline], rule: &mut SigmaRule) -> Result<()> {
        // Sort by priority (ascending - lower priority values are applied first)
        pipelines.sort_by(|a, b| a.priority.cmp(&b.priority));
        
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
    fn apply(&self, rule: &mut SigmaRule, vars: &HashMap<String, Vec<String>>) -> Result<()> {
        // Check if rule conditions are met
        if !self.rule_conditions.is_empty() && !self.check_rule_conditions(rule) {
            return Ok(());
        }
        
        // Apply the transformation based on type
        match self.transformation_type.as_str() {
            "field_name_mapping" => self.apply_field_name_mapping(rule),
            "field_name_prefix" => self.apply_field_name_prefix(rule),
            "field_name_suffix" => self.apply_field_name_suffix(rule),
            "field_name_prefix_mapping" => self.apply_field_name_prefix_mapping(rule),
            "add_field" => self.apply_add_field(rule),
            "remove_field" => self.apply_remove_field(rule),
            "set_field" => self.apply_set_field(rule),
            "replace_string" => self.apply_replace_string(rule),
            "map_string" => self.apply_map_string(rule),
            "add_condition" => self.apply_add_condition(rule),
            "change_logsource" => self.apply_change_logsource(rule),
            "drop_detection_item" => self.apply_drop_detection_item(rule),
            "set_state" => self.apply_set_state(rule),
            "wildcard_placeholders" => {
                self.validate_placeholder_config()?;
                self.apply_wildcard_placeholders(rule)
            }
            "value_placeholders" => {
                self.validate_placeholder_config()?;
                self.apply_value_placeholders(rule, vars)
            }
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
            // Collect changes first to avoid mutable/immutable borrow conflict
            // (we need to read from search_identifiers while preparing replacements,
            // then write back to it)
            let mut replacements = Vec::new();
            
            for (search_name, search_id) in &rule.detection.search_identifiers {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        let mut needs_multi_mapping = false;
                        let mut mapped_variants = vec![Vec::new()];
                        
                        for item in items {
                            if let Some(field) = &item.field {
                                if let Some(new_names) = mapping.get(field) {
                                    if new_names.len() > 1 {
                                        // Multiple targets: expand variants
                                        needs_multi_mapping = true;
                                        let mut new_variants = Vec::new();
                                        for variant in &mapped_variants {
                                            for new_name in new_names {
                                                let mut new_variant = variant.clone();
                                                new_variant.push(DetectionItem {
                                                    field: Some(new_name.clone()),
                                                    modifiers: item.modifiers.clone(),
                                                    values: item.values.clone(),
                                                });
                                                new_variants.push(new_variant);
                                            }
                                        }
                                        mapped_variants = new_variants;
                                    } else if let Some(new_name) = new_names.first() {
                                        // Single target: simple replacement in all variants
                                        for variant in &mut mapped_variants {
                                            variant.push(DetectionItem {
                                                field: Some(new_name.clone()),
                                                modifiers: item.modifiers.clone(),
                                                values: item.values.clone(),
                                            });
                                        }
                                    }
                                } else {
                                    // No mapping: keep original in all variants
                                    for variant in &mut mapped_variants {
                                        variant.push(item.clone());
                                    }
                                }
                            } else {
                                // No field (keyword search): keep original in all variants
                                for variant in &mut mapped_variants {
                                    variant.push(item.clone());
                                }
                            }
                        }
                        
                        if needs_multi_mapping {
                            replacements.push((search_name.clone(), SearchIdentifier::MapList(mapped_variants)));
                        } else {
                            // No multi-mapping occurred, keep as Map
                            // Invariant: mapped_variants always has at least one element (initialized at line 182)
                            replacements.push((search_name.clone(), SearchIdentifier::Map(
                                mapped_variants.into_iter().next().expect("mapped_variants should have at least one element")
                            )));
                        }
                    }
                    SearchIdentifier::MapList(maps) => {
                        let mut new_maps = Vec::new();
                        
                        for items in maps {
                            let mut map_variants = vec![Vec::new()];
                            
                            for item in items {
                                if let Some(field) = &item.field {
                                    if let Some(new_names) = mapping.get(field) {
                                        if new_names.len() > 1 {
                                            // Multiple targets: multiply the variants
                                            let mut expanded_variants = Vec::new();
                                            for variant in &map_variants {
                                                for new_name in new_names {
                                                    let mut new_variant = variant.clone();
                                                    new_variant.push(DetectionItem {
                                                        field: Some(new_name.clone()),
                                                        modifiers: item.modifiers.clone(),
                                                        values: item.values.clone(),
                                                    });
                                                    expanded_variants.push(new_variant);
                                                }
                                            }
                                            map_variants = expanded_variants;
                                        } else if let Some(new_name) = new_names.first() {
                                            // Single target: add to all variants
                                            for variant in &mut map_variants {
                                                variant.push(DetectionItem {
                                                    field: Some(new_name.clone()),
                                                    modifiers: item.modifiers.clone(),
                                                    values: item.values.clone(),
                                                });
                                            }
                                        }
                                    } else {
                                        // No mapping: add original to all variants
                                        for variant in &mut map_variants {
                                            variant.push(item.clone());
                                        }
                                    }
                                } else {
                                    // No field: add original to all variants
                                    for variant in &mut map_variants {
                                        variant.push(item.clone());
                                    }
                                }
                            }
                            
                            new_maps.extend(map_variants);
                        }
                        
                        replacements.push((search_name.clone(), SearchIdentifier::MapList(new_maps)));
                    }
                }
            }
            
            // Apply replacements
            for (name, new_search_id) in replacements {
                rule.detection.search_identifiers.insert(name, new_search_id);
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
    
    // ── Additional Transformations ───────────────────────────────────────
    
    fn apply_field_name_prefix_mapping(&self, rule: &mut SigmaRule) -> Result<()> {
        if let Some(mapping) = &self.config.mapping {
            for search_id in rule.detection.search_identifiers.values_mut() {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        for item in items {
                            Self::apply_prefix_mapping_to_item(item, mapping);
                        }
                    }
                    SearchIdentifier::MapList(maps) => {
                        for items in maps {
                            for item in items {
                                Self::apply_prefix_mapping_to_item(item, mapping);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    /// Helper function to apply prefix mapping to a single detection item
    fn apply_prefix_mapping_to_item(item: &mut DetectionItem, mapping: &HashMap<String, Vec<String>>) {
        if let Some(field) = &item.field {
            // Check each prefix in mapping
            for (src_prefix, dest_prefixes) in mapping {
                if field.starts_with(src_prefix) {
                    let suffix = &field[src_prefix.len()..];
                    if let Some(dest_prefix) = dest_prefixes.first() {
                        item.field = Some(format!("{}{}", dest_prefix, suffix));
                        break;
                    }
                }
            }
        }
    }
    
    fn apply_set_field(&self, rule: &mut SigmaRule) -> Result<()> {
        if let Some(fields) = &self.config.fields {
            rule.fields = fields.clone();
        }
        Ok(())
    }
    
    fn apply_change_logsource(&self, rule: &mut SigmaRule) -> Result<()> {
        if let Some(category) = &self.config.category {
            rule.logsource.category = Some(category.clone());
        }
        if let Some(product) = &self.config.product {
            rule.logsource.product = Some(product.clone());
        }
        if let Some(service) = &self.config.service {
            rule.logsource.service = Some(service.clone());
        }
        Ok(())
    }
    
    fn apply_drop_detection_item(&self, rule: &mut SigmaRule) -> Result<()> {
        // Drop detection items that match field conditions
        if let Some(field_name) = &self.config.field {
            for search_id in rule.detection.search_identifiers.values_mut() {
                match search_id {
                    SearchIdentifier::Map(items) => {
                        items.retain(|item| item.field.as_deref() != Some(field_name));
                    }
                    SearchIdentifier::MapList(maps) => {
                        for items in maps {
                            items.retain(|item| item.field.as_deref() != Some(field_name));
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn apply_set_state(&self, _rule: &mut SigmaRule) -> Result<()> {
        // State management placeholder - not yet implemented
        // TODO: Full implementation requires a state store in the pipeline context
        // that can persist state across transformations and be queried by other transformations.
        // Currently, set_state transformations in pipelines will be silently ignored.
        // Consider implementing a pipeline context with state storage for full compatibility.
        Ok(())
    }
    
    // ── Placeholder Transformations ──────────────────────────────────────
    
    /// Validate that include and exclude lists are not both specified.
    fn validate_placeholder_config(&self) -> Result<()> {
        if self.config.include.is_some() && self.config.exclude.is_some() {
            return Err(Error::InvalidValue {
                field: "include/exclude".into(),
                message: "Placeholder transformation include and exclude lists can only be used exclusively".into(),
            });
        }
        Ok(())
    }
    
    /// Check whether a placeholder name should be handled by this transformation
    /// based on the include/exclude configuration.
    /// Include and exclude are mutually exclusive; both being set is prevented
    /// by validation in `apply`.
    fn is_handled_placeholder(&self, name: &str) -> bool {
        match (&self.config.include, &self.config.exclude) {
            (Some(include), _) => include.iter().any(|n| n == name),
            (_, Some(exclude)) => !exclude.iter().any(|n| n == name),
            (None, None) => true,
        }
    }
    
    fn apply_wildcard_placeholders(&self, rule: &mut SigmaRule) -> Result<()> {
        for search_id in rule.detection.search_identifiers.values_mut() {
            match search_id {
                SearchIdentifier::Map(items) => {
                    for item in items {
                        self.replace_placeholders_with_wildcards(&mut item.values);
                    }
                }
                SearchIdentifier::MapList(maps) => {
                    for items in maps {
                        for item in items {
                            self.replace_placeholders_with_wildcards(&mut item.values);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn replace_placeholders_with_wildcards(&self, values: &mut Vec<SigmaValue>) {
        for value in values {
            if let SigmaValue::String(sigma_str) = value {
                if sigma_str.parts.iter().any(|p| matches!(p, SigmaStringPart::Placeholder(name) if self.is_handled_placeholder(name))) {
                    let new_parts: Vec<SigmaStringPart> = sigma_str.parts.iter().map(|part| {
                        if let SigmaStringPart::Placeholder(name) = part {
                            if self.is_handled_placeholder(name) {
                                return SigmaStringPart::WildcardMulti;
                            }
                        }
                        part.clone()
                    }).collect();
                    sigma_str.parts = new_parts;
                }
            }
        }
    }
    
    fn apply_value_placeholders(&self, rule: &mut SigmaRule, vars: &HashMap<String, Vec<String>>) -> Result<()> {
        for search_id in rule.detection.search_identifiers.values_mut() {
            match search_id {
                SearchIdentifier::Map(items) => {
                    for item in items {
                        self.replace_placeholders_with_values(&mut item.values, vars)?;
                    }
                }
                SearchIdentifier::MapList(maps) => {
                    for items in maps {
                        for item in items {
                            self.replace_placeholders_with_values(&mut item.values, vars)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn replace_placeholders_with_values(
        &self,
        values: &mut Vec<SigmaValue>,
        vars: &HashMap<String, Vec<String>>,
    ) -> Result<()> {
        let mut new_values = Vec::new();
        
        for value in values.iter() {
            if let SigmaValue::String(sigma_str) = value {
                // Check if this string contains any handled placeholders
                let has_handled = sigma_str.parts.iter().any(|p| {
                    matches!(p, SigmaStringPart::Placeholder(name) if self.is_handled_placeholder(name))
                });
                
                if has_handled {
                    // Expand placeholders: for each placeholder, substitute with each
                    // value from vars, producing multiple SigmaStrings
                    let expanded = self.expand_value_placeholder(sigma_str, vars)?;
                    for s in expanded {
                        new_values.push(SigmaValue::String(s));
                    }
                } else {
                    new_values.push(value.clone());
                }
            } else {
                new_values.push(value.clone());
            }
        }
        
        *values = new_values;
        Ok(())
    }
    
    /// Expand a SigmaString that contains placeholders into multiple SigmaStrings
    /// by substituting placeholder values from vars.
    fn expand_value_placeholder(
        &self,
        sigma_str: &SigmaString,
        vars: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<SigmaString>> {
        // Start with a single empty variant
        let mut variants: Vec<Vec<SigmaStringPart>> = vec![vec![]];
        
        for part in &sigma_str.parts {
            match part {
                SigmaStringPart::Placeholder(name) if self.is_handled_placeholder(name) => {
                    let replacement_values = vars.get(name).ok_or_else(|| Error::InvalidValue {
                        field: "vars".into(),
                        message: format!("Placeholder replacement variable '{}' does not exist", name),
                    })?;
                    
                    if replacement_values.is_empty() {
                        return Err(Error::InvalidValue {
                            field: "vars".into(),
                            message: format!("Placeholder replacement variable '{}' is empty", name),
                        });
                    }
                    
                    // Multiply variants by the number of replacement values
                    let mut new_variants = Vec::new();
                    for variant in &variants {
                        for replacement in replacement_values {
                            let mut new_variant = variant.clone();
                            new_variant.push(SigmaStringPart::Literal(replacement.clone()));
                            new_variants.push(new_variant);
                        }
                    }
                    variants = new_variants;
                }
                other => {
                    // Append non-placeholder parts to all variants
                    for variant in &mut variants {
                        variant.push(other.clone());
                    }
                }
            }
        }
        
        Ok(variants
            .into_iter()
            .map(|parts| SigmaString { parts })
            .collect())
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
    
    // Add/set field(s)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<SigmaValue>,
    
    // Replace string / regex
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
    
    // Add condition
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<HashMap<String, SigmaValue>>,
    
    // Change logsource
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    
    // State management
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    
    // Placeholder include/exclude
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
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
    fn test_field_name_mapping_multiple() {
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
        
        // Check that EventID was mapped to multiple fields (OR-ed)
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::MapList(maps) = selection {
            // Should have 2 variants for the EventID field (event_id and evtid)
            // Each variant should have BOTH the mapped EventID field AND CommandLine
            assert_eq!(maps.len(), 2);
            
            // First variant: event_id + CommandLine
            assert_eq!(maps[0].len(), 2);
            assert_eq!(maps[0][0].field.as_deref(), Some("event_id"));
            assert_eq!(maps[0][1].field.as_deref(), Some("CommandLine"));
            
            // Second variant: evtid + CommandLine
            assert_eq!(maps[1].len(), 2);
            assert_eq!(maps[1][0].field.as_deref(), Some("evtid"));
            assert_eq!(maps[1][1].field.as_deref(), Some("CommandLine"));
        } else {
            panic!("Expected MapList for multi-field mapping");
        }
    }
    
    #[test]
    fn test_field_name_mapping_single() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: map_event_id
    type: field_name_mapping
    mapping:
      EventID:
        - event_id
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        // Check that EventID was mapped to event_id (1:1 mapping)
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("event_id"));
            assert_eq!(items[1].field.as_deref(), Some("CommandLine"));
        } else {
            panic!("Expected Map for single-field mapping");
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
        
        // Pipeline 1 (priority 10) should run first, then Pipeline 2 (priority 20)
        // So: EventID -> event_id -> win.event_id
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("win.event_id"));
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
    
    #[test]
    fn test_field_name_prefix_mapping() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: prefix_mapping
    type: field_name_prefix_mapping
    mapping:
      win.:
        - windows.
      Event:
        - event.
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        
        // Manually add a field with win. prefix
        if let SearchIdentifier::Map(items) = &mut rule.detection.search_identifiers.get_mut("selection").unwrap() {
            items[0].field = Some("win.EventID".to_string());
        }
        
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("windows.EventID"));
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_set_field() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: set_fields
    type: set_field
    fields:
      - ComputerName
      - UserName
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        assert_eq!(rule.fields, vec!["ComputerName", "UserName"]);
    }
    
    #[test]
    fn test_change_logsource() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: change_log
    type: change_logsource
    product: linux
    category: network_connection
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        
        assert_eq!(rule.logsource.product.as_deref(), Some("linux"));
        assert_eq!(rule.logsource.category.as_deref(), Some("network_connection"));
    }
    
    #[test]
    fn test_drop_detection_item() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: drop_commandline
    type: drop_detection_item
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
    
    fn create_test_rule_with_placeholders() -> SigmaRule {
        let mut search_identifiers = HashMap::new();
        search_identifiers.insert(
            "selection".to_string(),
            SearchIdentifier::Map(vec![
                DetectionItem {
                    field: Some("Image".to_string()),
                    modifiers: vec![],
                    values: vec![SigmaValue::String(SigmaString {
                        parts: vec![
                            SigmaStringPart::Placeholder("SystemRoot".to_string()),
                            SigmaStringPart::Literal("\\cmd.exe".to_string()),
                        ],
                    })],
                },
                DetectionItem {
                    field: Some("User".to_string()),
                    modifiers: vec![],
                    values: vec![SigmaValue::String(SigmaString {
                        parts: vec![
                            SigmaStringPart::Placeholder("Admins".to_string()),
                        ],
                    })],
                },
            ]),
        );
        
        SigmaRule {
            title: "Placeholder Test Rule".to_string(),
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
    fn test_wildcard_placeholders() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: wildcard_all
    type: wildcard_placeholders
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_placeholders();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            // Image: %SystemRoot%\cmd.exe -> *\cmd.exe
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.parts.len(), 2);
                assert_eq!(s.parts[0], SigmaStringPart::WildcardMulti);
                assert_eq!(s.parts[1], SigmaStringPart::Literal("\\cmd.exe".to_string()));
            } else {
                panic!("Expected String value");
            }
            
            // User: %Admins% -> *
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.parts.len(), 1);
                assert_eq!(s.parts[0], SigmaStringPart::WildcardMulti);
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_wildcard_placeholders_with_include() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: wildcard_some
    type: wildcard_placeholders
    include:
      - SystemRoot
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_placeholders();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            // Image: %SystemRoot%\cmd.exe -> *\cmd.exe (handled)
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.parts[0], SigmaStringPart::WildcardMulti);
            } else {
                panic!("Expected String value");
            }
            
            // User: %Admins% -> unchanged (not in include list)
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.parts[0], SigmaStringPart::Placeholder("Admins".to_string()));
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_wildcard_placeholders_with_exclude() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: wildcard_except
    type: wildcard_placeholders
    exclude:
      - Admins
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_placeholders();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            // Image: %SystemRoot%\cmd.exe -> *\cmd.exe (handled, not excluded)
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.parts[0], SigmaStringPart::WildcardMulti);
            } else {
                panic!("Expected String value");
            }
            
            // User: %Admins% -> unchanged (excluded)
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.parts[0], SigmaStringPart::Placeholder("Admins".to_string()));
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_value_placeholders() {
        let yaml = r#"
name: Test Pipeline
vars:
  SystemRoot:
    - "C:\\Windows"
    - "D:\\Windows"
  Admins:
    - Administrator
    - admin
transformations:
  - id: replace_placeholders
    type: value_placeholders
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_placeholders();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            // Image: %SystemRoot%\cmd.exe -> 2 values (C:\Windows\cmd.exe, D:\Windows\cmd.exe)
            assert_eq!(items[0].values.len(), 2);
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.to_string(), "C:\\Windows\\cmd.exe");
            } else {
                panic!("Expected String value");
            }
            if let SigmaValue::String(s) = &items[0].values[1] {
                assert_eq!(s.to_string(), "D:\\Windows\\cmd.exe");
            } else {
                panic!("Expected String value");
            }
            
            // User: %Admins% -> 2 values (Administrator, admin)
            assert_eq!(items[1].values.len(), 2);
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.as_plain(), Some("Administrator"));
            } else {
                panic!("Expected String value");
            }
            if let SigmaValue::String(s) = &items[1].values[1] {
                assert_eq!(s.as_plain(), Some("admin"));
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_value_placeholders_with_include() {
        let yaml = r#"
name: Test Pipeline
vars:
  SystemRoot:
    - "C:\\Windows"
    - "D:\\Windows"
    - "E:\\WinNT"
  Admins:
    - Administrator
    - root
    - admin
transformations:
  - id: replace_some
    type: value_placeholders
    include:
      - SystemRoot
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_placeholders();
        pipeline.apply(&mut rule).unwrap();
        
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            // Image: %SystemRoot%\cmd.exe -> 3 values (included placeholder expanded)
            assert_eq!(items[0].values.len(), 3);
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.to_string(), "C:\\Windows\\cmd.exe");
            } else {
                panic!("Expected String value");
            }
            if let SigmaValue::String(s) = &items[0].values[1] {
                assert_eq!(s.to_string(), "D:\\Windows\\cmd.exe");
            } else {
                panic!("Expected String value");
            }
            if let SigmaValue::String(s) = &items[0].values[2] {
                assert_eq!(s.to_string(), "E:\\WinNT\\cmd.exe");
            } else {
                panic!("Expected String value");
            }
            
            // User: %Admins% -> unchanged (not in include list, stays as placeholder)
            assert_eq!(items[1].values.len(), 1);
            if let SigmaValue::String(s) = &items[1].values[0] {
                assert_eq!(s.parts.len(), 1);
                assert_eq!(s.parts[0], SigmaStringPart::Placeholder("Admins".to_string()));
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_value_placeholders_missing_var() {
        let yaml = r#"
name: Test Pipeline
vars: {}
transformations:
  - id: replace_placeholders
    type: value_placeholders
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_placeholders();
        let result = pipeline.apply(&mut rule);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }
    
    #[test]
    fn test_value_placeholders_no_placeholders_in_rule() {
        let yaml = r#"
name: Test Pipeline
vars:
  SystemRoot:
    - "C:\\Windows"
transformations:
  - id: replace_placeholders
    type: value_placeholders
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule(); // No placeholders
        pipeline.apply(&mut rule).unwrap();
        
        // Rule should be unchanged
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("EventID"));
            assert_eq!(items[0].values, vec![SigmaValue::Int(4688)]);
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_wildcard_placeholders_no_placeholders_in_rule() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: wildcard_all
    type: wildcard_placeholders
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule(); // No placeholders
        pipeline.apply(&mut rule).unwrap();
        
        // Rule should be unchanged
        let selection = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::Map(items) = selection {
            assert_eq!(items[0].field.as_deref(), Some("EventID"));
            assert_eq!(items[0].values, vec![SigmaValue::Int(4688)]);
        } else {
            panic!("Expected Map");
        }
    }
    
    #[test]
    fn test_placeholder_include_exclude_mutually_exclusive() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: bad_config
    type: wildcard_placeholders
    include:
      - SystemRoot
    exclude:
      - Admins
"#;
        
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_placeholders();
        let result = pipeline.apply(&mut rule);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exclusively"));
    }
    
    #[test]
    fn test_unknown_transformation_type() {
        let yaml = r#"
name: Test Pipeline
transformations:
  - id: bad
    type: nonexistent_type
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        let err = pipeline.apply(&mut rule).unwrap_err();
        assert!(err.to_string().contains("Unknown transformation type"));
    }

    fn create_test_rule_with_maplist() -> SigmaRule {
        let mut search_identifiers = HashMap::new();
        search_identifiers.insert(
            "selection".to_string(),
            SearchIdentifier::MapList(vec![
                vec![DetectionItem {
                    field: Some("EventID".to_string()),
                    modifiers: vec![],
                    values: vec![SigmaValue::Int(4688)],
                }],
                vec![DetectionItem {
                    field: Some("CommandLine".to_string()),
                    modifiers: vec![],
                    values: vec![SigmaValue::String(SigmaString::from_literal("test.exe"))],
                }],
            ]),
        );
        SigmaRule {
            title: "MapList Rule".to_string(),
            id: None, name: None, related: vec![], taxonomy: None,
            status: None, description: None, license: None, references: vec![],
            author: None, date: None, modified: None,
            logsource: LogSource {
                category: Some("process_creation".to_string()),
                product: Some("windows".to_string()),
                service: Some("sysmon".to_string()),
                custom: HashMap::new(),
            },
            detection: Detection {
                search_identifiers,
                conditions: vec![ConditionExpression::Identifier("selection".to_string())],
            },
            fields: vec![], falsepositives: vec![], level: None,
            tags: vec![], scope: vec![], custom: HashMap::new(),
        }
    }

    #[test]
    fn test_field_name_mapping_maplist_multi() {
        let yaml = r#"
name: Test
transformations:
  - id: map
    type: field_name_mapping
    mapping:
      EventID:
        - event_id
        - evtid
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        let sel = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::MapList(maps) = sel {
            // First map (EventID) gets expanded into two variants; second map unchanged
            assert!(maps.len() >= 3);
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_field_name_mapping_maplist_single() {
        // MapList with single-target mapping → covers lines 279-283
        let yaml = r#"
name: Test
transformations:
  - id: map
    type: field_name_mapping
    mapping:
      EventID:
        - event_id
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        let sel = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::MapList(maps) = sel {
            assert_eq!(maps[0][0].field.as_deref(), Some("event_id"));
            assert_eq!(maps[1][0].field.as_deref(), Some("CommandLine"));
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_field_name_mapping_map_with_keyword_and_multi() {
        // Map with a keyword search (no field) AND a multi-mapped field → covers lines 237-238
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
                    field: None, // keyword search
                    modifiers: vec![],
                    values: vec![SigmaValue::String(SigmaString::from_literal("keyword"))],
                },
            ]),
        );
        let mut rule = SigmaRule {
            title: "Test".to_string(),
            id: None, name: None, related: vec![], taxonomy: None,
            status: None, description: None, license: None, references: vec![],
            author: None, date: None, modified: None,
            logsource: LogSource {
                category: Some("test".to_string()),
                product: None, service: None, custom: HashMap::new(),
            },
            detection: Detection {
                search_identifiers,
                conditions: vec![ConditionExpression::Identifier("selection".to_string())],
            },
            fields: vec![], falsepositives: vec![], level: None,
            tags: vec![], scope: vec![], custom: HashMap::new(),
        };
        let yaml = r#"
name: Test
transformations:
  - id: map
    type: field_name_mapping
    mapping:
      EventID:
        - event_id
        - evtid
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        pipeline.apply(&mut rule).unwrap();
        let sel = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::MapList(maps) = sel {
            assert_eq!(maps.len(), 2);
            // Each variant should have the keyword item
            assert!(maps[0].iter().any(|i| i.field.is_none()));
            assert!(maps[1].iter().any(|i| i.field.is_none()));
        } else {
            panic!("Expected MapList due to multi-mapping");
        }
    }

    fn create_test_rule_with_maplist_keyword() -> SigmaRule {
        // MapList that includes a keyword (no-field) item → for covering line 295-296
        let mut search_identifiers = HashMap::new();
        search_identifiers.insert(
            "selection".to_string(),
            SearchIdentifier::MapList(vec![
                vec![
                    DetectionItem {
                        field: None,
                        modifiers: vec![],
                        values: vec![SigmaValue::String(SigmaString::from_literal("keyword"))],
                    },
                ],
            ]),
        );
        SigmaRule {
            title: "Test".to_string(),
            id: None, name: None, related: vec![], taxonomy: None,
            status: None, description: None, license: None, references: vec![],
            author: None, date: None, modified: None,
            logsource: LogSource {
                category: Some("test".to_string()),
                product: None, service: None, custom: HashMap::new(),
            },
            detection: Detection {
                search_identifiers,
                conditions: vec![ConditionExpression::Identifier("selection".to_string())],
            },
            fields: vec![], falsepositives: vec![], level: None,
            tags: vec![], scope: vec![], custom: HashMap::new(),
        }
    }

    #[test]
    fn test_field_name_mapping_maplist_keyword() {
        // MapList with a no-field (keyword) entry → covers lines 295-296
        let yaml = r#"
name: Test
transformations:
  - id: map
    type: field_name_mapping
    mapping:
      EventID:
        - event_id
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist_keyword();
        pipeline.apply(&mut rule).unwrap();
        let sel = &rule.detection.search_identifiers["selection"];
        if let SearchIdentifier::MapList(maps) = sel {
            assert_eq!(maps[0][0].field, None); // keyword preserved
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_field_name_prefix_maplist() {
        let yaml = r#"
name: Test
transformations:
  - id: pfx
    type: field_name_prefix
    prefix: "x."
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["selection"] {
            assert_eq!(maps[0][0].field.as_deref(), Some("x.EventID"));
            assert_eq!(maps[1][0].field.as_deref(), Some("x.CommandLine"));
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_field_name_suffix_maplist() {
        let yaml = r#"
name: Test
transformations:
  - id: sfx
    type: field_name_suffix
    suffix: ".kw"
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["selection"] {
            assert_eq!(maps[0][0].field.as_deref(), Some("EventID.kw"));
            assert_eq!(maps[1][0].field.as_deref(), Some("CommandLine.kw"));
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_add_field_maplist() {
        let yaml = r#"
name: Test
transformations:
  - id: add
    type: add_field
    field: idx
    value: "win"
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["selection"] {
            for m in maps {
                assert!(m.iter().any(|i| i.field.as_deref() == Some("idx")));
            }
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_remove_field_maplist() {
        let yaml = r#"
name: Test
transformations:
  - id: rm
    type: remove_field
    field: EventID
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["selection"] {
            assert!(maps[0].iter().all(|i| i.field.as_deref() != Some("EventID")));
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_replace_string_maplist() {
        let yaml = r#"
name: Test
transformations:
  - id: rep
    type: replace_string
    regex: "\\.exe$"
    replacement: ".bin"
    field_name_conditions:
      - type: include_fields
        fields:
          - CommandLine
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["selection"] {
            if let SigmaValue::String(s) = &maps[1][0].values[0] {
                assert_eq!(s.as_plain(), Some("test.bin"));
            }
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_map_string_maplist() {
        let yaml = r#"
name: Test
transformations:
  - id: ms
    type: map_string
    mapping:
      test.exe:
        - new.exe
    field_name_conditions:
      - type: include_fields
        fields:
          - CommandLine
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["selection"] {
            if let SigmaValue::String(s) = &maps[1][0].values[0] {
                assert_eq!(s.as_plain(), Some("new.exe"));
            }
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_add_condition_maplist() {
        let yaml = r#"
name: Test
transformations:
  - id: ac
    type: add_condition
    conditions:
      source: "sysmon"
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["selection"] {
            for m in maps {
                assert!(m.iter().any(|i| i.field.as_deref() == Some("source")));
            }
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_field_name_prefix_mapping_maplist() {
        let yaml = r#"
name: Test
transformations:
  - id: pfm
    type: field_name_prefix_mapping
    mapping:
      Event:
        - evt.
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["selection"] {
            assert_eq!(maps[0][0].field.as_deref(), Some("evt.ID"));
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_change_logsource_service() {
        let yaml = r#"
name: Test
transformations:
  - id: cls
    type: change_logsource
    service: audit
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        pipeline.apply(&mut rule).unwrap();
        assert_eq!(rule.logsource.service.as_deref(), Some("audit"));
    }

    #[test]
    fn test_drop_detection_item_maplist() {
        let yaml = r#"
name: Test
transformations:
  - id: drop
    type: drop_detection_item
    field: EventID
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["selection"] {
            assert!(maps[0].is_empty());
        } else {
            panic!("Expected MapList");
        }
    }

    #[test]
    fn test_set_state() {
        let yaml = r#"
name: Test
transformations:
  - id: state
    type: set_state
    key: my_state
    value: "yes"
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule();
        // set_state is a no-op but should not error
        pipeline.apply(&mut rule).unwrap();
    }

    #[test]
    fn test_wildcard_placeholders_maplist() {
        let yaml = r#"
name: Test
transformations:
  - id: wc
    type: wildcard_placeholders
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut search_identifiers = HashMap::new();
        search_identifiers.insert(
            "sel".to_string(),
            SearchIdentifier::MapList(vec![vec![DetectionItem {
                field: Some("Image".to_string()),
                modifiers: vec![],
                values: vec![SigmaValue::String(SigmaString {
                    parts: vec![SigmaStringPart::Placeholder("X".to_string())],
                })],
            }]]),
        );
        let mut rule = SigmaRule {
            title: "T".into(), id: None, name: None, related: vec![], taxonomy: None,
            status: None, description: None, license: None, references: vec![],
            author: None, date: None, modified: None,
            logsource: LogSource { category: None, product: None, service: None, custom: HashMap::new() },
            detection: Detection { search_identifiers, conditions: vec![ConditionExpression::Identifier("sel".into())] },
            fields: vec![], falsepositives: vec![], level: None, tags: vec![], scope: vec![], custom: HashMap::new(),
        };
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["sel"] {
            if let SigmaValue::String(s) = &maps[0][0].values[0] {
                assert_eq!(s.parts[0], SigmaStringPart::WildcardMulti);
            }
        }
    }

    #[test]
    fn test_value_placeholders_maplist() {
        let yaml = r#"
name: Test
vars:
  X:
    - "val1"
transformations:
  - id: vp
    type: value_placeholders
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut search_identifiers = HashMap::new();
        search_identifiers.insert(
            "sel".to_string(),
            SearchIdentifier::MapList(vec![vec![DetectionItem {
                field: Some("F".to_string()),
                modifiers: vec![],
                values: vec![SigmaValue::String(SigmaString {
                    parts: vec![SigmaStringPart::Placeholder("X".to_string())],
                })],
            }]]),
        );
        let mut rule = SigmaRule {
            title: "T".into(), id: None, name: None, related: vec![], taxonomy: None,
            status: None, description: None, license: None, references: vec![],
            author: None, date: None, modified: None,
            logsource: LogSource { category: None, product: None, service: None, custom: HashMap::new() },
            detection: Detection { search_identifiers, conditions: vec![ConditionExpression::Identifier("sel".into())] },
            fields: vec![], falsepositives: vec![], level: None, tags: vec![], scope: vec![], custom: HashMap::new(),
        };
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["sel"] {
            if let SigmaValue::String(s) = &maps[0][0].values[0] {
                assert_eq!(s.as_plain(), Some("val1"));
            }
        }
    }

    #[test]
    fn test_expand_value_placeholder_empty_var() {
        let yaml = r#"
name: Test
vars:
  Empty: []
transformations:
  - id: vp
    type: value_placeholders
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_placeholders();
        // Replace Admins placeholder with Empty
        if let SearchIdentifier::Map(items) = rule.detection.search_identifiers.get_mut("selection").unwrap() {
            items[1].values = vec![SigmaValue::String(SigmaString {
                parts: vec![SigmaStringPart::Placeholder("Empty".to_string())],
            })];
            items[0].values = vec![SigmaValue::String(SigmaString::from_literal("plain"))];
        }
        let err = pipeline.apply(&mut rule).unwrap_err();
        assert!(err.to_string().contains("is empty"));
    }

    #[test]
    fn test_logsource_service_condition() {
        let yaml = r#"
name: Test
transformations:
  - id: pfx
    type: field_name_prefix
    prefix: "s."
    rule_conditions:
      - type: logsource_service
        service: sysmon
"#;
        let pipeline = ProcessingPipeline::from_yaml(yaml).unwrap();
        let mut rule = create_test_rule_with_maplist();
        pipeline.apply(&mut rule).unwrap();
        if let SearchIdentifier::MapList(maps) = &rule.detection.search_identifiers["selection"] {
            assert_eq!(maps[0][0].field.as_deref(), Some("s.EventID"));
        }
    }
    
}
