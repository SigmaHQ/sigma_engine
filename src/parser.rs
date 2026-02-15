//! YAML → typed Sigma model conversion.
//!
//! This module handles deserializing raw YAML into [`SigmaCollection`],
//! [`SigmaRule`], and [`SigmaCorrelationRule`] instances.

use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;
use serde_yaml::{Mapping, Value};

use crate::condition::parse_condition;
use crate::error::Error;
use crate::types::*;

// ─── Multi-document splitting ────────────────────────────────────────────────

/// Split a (possibly multi-document) YAML string on `---` / `...` separators.
fn split_yaml_documents(yaml: &str) -> Vec<String> {
    let mut documents = Vec::new();
    let mut current = String::new();

    for line in yaml.lines() {
        let trimmed = line.trim();
        if trimmed == "---" || trimmed == "..." {
            let doc = current.trim().to_string();
            if !doc.is_empty() {
                documents.push(doc);
            }
            current.clear();
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }

    let doc = current.trim().to_string();
    if !doc.is_empty() {
        documents.push(doc);
    }

    documents
}

// ─── SigmaCollection entry point ────────────────────────────────────────────

impl SigmaCollection {
    /// Parse a (possibly multi-document) YAML string into a collection of Sigma documents.
    ///
    /// # Errors
    /// Returns an error if any document has invalid YAML or does not conform
    /// to the Sigma rule / correlation rule specification.
    pub fn from_yaml(yaml: &str) -> Result<Self, Error> {
        let doc_strings = split_yaml_documents(yaml);
        let mut documents = Vec::new();

        for doc_str in &doc_strings {
            let value: Value = serde_yaml::from_str(doc_str)?;
            if value.is_null() {
                continue;
            }
            documents.push(parse_document(value)?);
        }

        Ok(SigmaCollection { documents })
    }
}

// ─── Document dispatch ───────────────────────────────────────────────────────

fn parse_document(value: Value) -> Result<SigmaDocument, Error> {
    let map = value.as_mapping().ok_or_else(|| {
        Error::InvalidDocument("Expected a YAML mapping at document root".into())
    })?;

    if map.contains_key(&Value::String("correlation".into())) {
        Ok(SigmaDocument::Correlation(parse_correlation_rule(map)?))
    } else if map.contains_key(&Value::String("filter".into())) {
        Ok(SigmaDocument::Filter(parse_filter_rule(map)?))
    } else if map.contains_key(&Value::String("detection".into())) {
        Ok(SigmaDocument::Rule(parse_detection_rule(map)?))
    } else {
        Err(Error::InvalidDocument(
            "Document must contain either 'detection', 'correlation', or 'filter' section".into(),
        ))
    }
}

// ─── YAML helpers ────────────────────────────────────────────────────────────

fn get_str<'a>(map: &'a Mapping, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

fn get_string(map: &Mapping, key: &str) -> Option<String> {
    get_str(map, key).map(str::to_string)
}

fn get_bool(map: &Mapping, key: &str) -> Option<bool> {
    map.get(key).and_then(Value::as_bool)
}

fn get_i64(map: &Mapping, key: &str) -> Option<i64> {
    map.get(key).and_then(|v| match v {
        Value::Number(n) => n.as_i64(),
        _ => None,
    })
}

fn get_string_list(map: &Mapping, key: &str) -> Vec<String> {
    match map.get(key) {
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// Extract a string from a `Value`, unwrapping tagged values if necessary.
fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(format!("{n}")),
        Value::Bool(b) => Some(format!("{b}")),
        Value::Tagged(tagged) => value_as_string(&tagged.value),
        _ => None,
    }
}

/// Parse a date field from a YAML value in ISO 8601 format (YYYY-MM-DD).
fn get_date(map: &Mapping, key: &str) -> Result<Option<NaiveDate>, Error> {
    match map.get(key) {
        Some(value) => {
            let date_str = value_as_string(value).ok_or_else(|| Error::InvalidValue {
                field: key.into(),
                message: "Date must be a string or number".into(),
            })?;
            
            NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
                .map(Some)
                .map_err(|e| Error::InvalidValue {
                    field: key.into(),
                    message: format!("Invalid date format (expected YYYY-MM-DD): {e}"),
                })
        }
        None => Ok(None),
    }
}

// ─── Enum conversions ────────────────────────────────────────────────────────

fn parse_status(s: &str) -> Result<Status, Error> {
    match s {
        "stable" => Ok(Status::Stable),
        "test" => Ok(Status::Test),
        "experimental" => Ok(Status::Experimental),
        "deprecated" => Ok(Status::Deprecated),
        "unsupported" => Ok(Status::Unsupported),
        _ => Err(Error::InvalidValue {
            field: "status".into(),
            message: format!("Unknown status: {s}"),
        }),
    }
}

fn parse_level(s: &str) -> Result<Level, Error> {
    match s {
        "informational" => Ok(Level::Informational),
        "low" => Ok(Level::Low),
        "medium" => Ok(Level::Medium),
        "high" => Ok(Level::High),
        "critical" => Ok(Level::Critical),
        _ => Err(Error::InvalidValue {
            field: "level".into(),
            message: format!("Unknown level: {s}"),
        }),
    }
}

fn parse_relation_type(s: &str) -> Result<RelationType, Error> {
    match s {
        "derived" => Ok(RelationType::Derived),
        "obsolete" => Ok(RelationType::Obsolete),
        "merged" => Ok(RelationType::Merged),
        "renamed" => Ok(RelationType::Renamed),
        "similar" => Ok(RelationType::Similar),
        _ => Err(Error::InvalidValue {
            field: "type".into(),
            message: format!("Unknown relation type: {s}"),
        }),
    }
}

fn parse_modifier(s: &str) -> Result<Modifier, Error> {
    match s {
        // Generic
        "all" => Ok(Modifier::All),
        "contains" => Ok(Modifier::Contains),
        "startswith" => Ok(Modifier::StartsWith),
        "endswith" => Ok(Modifier::EndsWith),
        "exists" => Ok(Modifier::Exists),
        "cased" => Ok(Modifier::Cased),
        "neq" => Ok(Modifier::Neq),
        // String / regex
        "re" => Ok(Modifier::Re),
        "i" => Ok(Modifier::I),
        "m" => Ok(Modifier::M),
        "s" => Ok(Modifier::S),
        "base64" => Ok(Modifier::Base64),
        "base64offset" => Ok(Modifier::Base64Offset),
        "utf16le" => Ok(Modifier::Utf16Le),
        "utf16be" => Ok(Modifier::Utf16Be),
        "utf16" => Ok(Modifier::Utf16),
        "wide" => Ok(Modifier::Wide),
        "windash" => Ok(Modifier::Windash),
        // Numeric
        "lt" => Ok(Modifier::Lt),
        "lte" => Ok(Modifier::Lte),
        "gt" => Ok(Modifier::Gt),
        "gte" => Ok(Modifier::Gte),
        // Time
        "minute" => Ok(Modifier::Minute),
        "hour" => Ok(Modifier::Hour),
        "day" => Ok(Modifier::Day),
        "week" => Ok(Modifier::Week),
        "month" => Ok(Modifier::Month),
        "year" => Ok(Modifier::Year),
        // IP
        "cidr" => Ok(Modifier::Cidr),
        // Specific
        "expand" => Ok(Modifier::Expand),
        "fieldref" => Ok(Modifier::FieldRef),
        other => Err(Error::InvalidModifier(other.to_string())),
    }
}

fn parse_correlation_type(s: &str) -> Result<CorrelationType, Error> {
    match s {
        "event_count" => Ok(CorrelationType::EventCount),
        "value_count" => Ok(CorrelationType::ValueCount),
        "temporal" => Ok(CorrelationType::Temporal),
        "temporal_ordered" => Ok(CorrelationType::TemporalOrdered),
        "value_sum" => Ok(CorrelationType::ValueSum),
        "value_avg" => Ok(CorrelationType::ValueAvg),
        "value_percentile" => Ok(CorrelationType::ValuePercentile),
        _ => Err(Error::InvalidValue {
            field: "type".into(),
            message: format!("Unknown correlation type: {s}"),
        }),
    }
}

// ─── Sigma string parsing ────────────────────────────────────────────────────

/// Parse a string into a SigmaString, identifying wildcards.
///
/// Placeholders (`%name%`) are NOT parsed here - they remain as literal text.
/// Use [`expand_placeholders`] to convert placeholder patterns into Placeholder parts
/// when the `Expand` modifier is applied.
///
/// ## Escape Sequences
///
/// Backslash (`\`) is used to escape special characters:
/// - `\*` → literal asterisk (not a multi-char wildcard)
/// - `\?` → literal question mark (not a single-char wildcard)
/// - `\\` → literal backslash
/// - `\<other>` → literal backslash followed by the character (backslash before non-special chars is kept as-is)
///
/// ## Examples
///
/// - `"*.exe"` → wildcard + literal ".exe"
/// - `"\*.exe"` → literal "*.exe" (escaped asterisk)
/// - `"%TEMP%\file.log"` → literal "%TEMP%\file.log" (placeholders not parsed)
/// - `"C:\\Windows"` → literal "C:\Windows" (escaped backslash)
fn parse_sigma_string(s: &str) -> SigmaString {
    use crate::types::{SigmaString, SigmaStringPart};

    let mut parts = Vec::new();
    let mut current_literal = String::new();
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                // Escape sequence: check if next char is special
                if let Some(&next_ch) = chars.peek() {
                    match next_ch {
                        '*' | '?' | '\\' => {
                            // Escaped special character - treat as literal
                            current_literal.push(chars.next().unwrap());
                        }
                        _ => {
                            // Not a special character, treat backslash as literal
                            current_literal.push('\\');
                        }
                    }
                } else {
                    // Backslash at end of string, treat as literal
                    current_literal.push('\\');
                }
            }
            '*' => {
                // Flush any accumulated literal
                if !current_literal.is_empty() {
                    parts.push(SigmaStringPart::Literal(current_literal.clone()));
                    current_literal.clear();
                }
                parts.push(SigmaStringPart::WildcardMulti);
            }
            '?' => {
                // Flush any accumulated literal
                if !current_literal.is_empty() {
                    parts.push(SigmaStringPart::Literal(current_literal.clone()));
                    current_literal.clear();
                }
                parts.push(SigmaStringPart::WildcardSingle);
            }
            _ => {
                // All other characters (including %) are treated as literals
                current_literal.push(ch);
            }
        }
    }

    // Flush any remaining literal
    if !current_literal.is_empty() {
        parts.push(SigmaStringPart::Literal(current_literal));
    }

    // If no parts were created, return an empty literal
    if parts.is_empty() {
        parts.push(SigmaStringPart::Literal(String::new()));
    }

    SigmaString { parts }
}

/// Expand placeholders in a SigmaString by converting `%name%` patterns into Placeholder parts.
///
/// This function should be called when the `Expand` modifier is applied to a field value.
/// It scans literal parts for `%name%` patterns and converts them into dedicated Placeholder parts.
///
/// ## Examples
///
/// - `"C:\%TEMP%\file.log"` → literal "C:\" + Placeholder("TEMP") + literal "\file.log"
/// - `"%SystemRoot%\*.dll"` → Placeholder("SystemRoot") + literal "\" + wildcard + literal ".dll"
/// - `"no_placeholders.txt"` → unchanged
///
/// Empty placeholder names (e.g., `%%`) are treated as literals, not placeholders.
pub fn expand_placeholders(sigma_string: &SigmaString) -> SigmaString {
    use crate::types::{SigmaString, SigmaStringPart};

    let mut expanded_parts = Vec::new();

    for part in &sigma_string.parts {
        match part {
            SigmaStringPart::Literal(s) => {
                // Parse this literal for %name% placeholder patterns
                let mut chars = s.chars().peekable();
                let mut current_literal = String::new();

                while let Some(ch) = chars.next() {
                    if ch == '%' {
                        // Look for closing %
                        let mut placeholder = String::new();
                        let mut found_closing = false;

                        while let Some(&next_ch) = chars.peek() {
                            if next_ch == '%' {
                                chars.next(); // consume closing %
                                found_closing = true;
                                break;
                            }
                            placeholder.push(chars.next().unwrap());
                        }

                        if found_closing && !placeholder.is_empty() {
                            // Valid placeholder found - flush current literal and add placeholder
                            if !current_literal.is_empty() {
                                expanded_parts.push(SigmaStringPart::Literal(current_literal.clone()));
                                current_literal.clear();
                            }
                            expanded_parts.push(SigmaStringPart::Placeholder(placeholder));
                        } else {
                            // Not a valid placeholder (empty name or no closing %), treat as literal
                            current_literal.push('%');
                            current_literal.push_str(&placeholder);
                            if found_closing {
                                current_literal.push('%');
                            }
                        }
                    } else {
                        current_literal.push(ch);
                    }
                }

                // Flush any remaining literal
                if !current_literal.is_empty() {
                    expanded_parts.push(SigmaStringPart::Literal(current_literal));
                }
            }
            // Copy wildcards and existing placeholders as-is
            other => {
                expanded_parts.push(other.clone());
            }
        }
    }

    // If no parts were created, return an empty literal
    if expanded_parts.is_empty() {
        expanded_parts.push(SigmaStringPart::Literal(String::new()));
    }

    SigmaString {
        parts: expanded_parts,
    }
}

// ─── Detection value conversion ──────────────────────────────────────────────

fn yaml_to_sigma_value(value: &Value) -> Result<SigmaValue, Error> {
    match value {
        Value::Null => Ok(SigmaValue::Null),
        Value::Bool(b) => Ok(SigmaValue::Bool(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(SigmaValue::Int(i))
            } else if let Some(f) = n.as_f64() {
                Ok(SigmaValue::Float(f))
            } else {
                Err(Error::InvalidValue {
                    field: "detection value".into(),
                    message: format!("Unsupported number: {n:?}"),
                })
            }
        }
        Value::String(s) => Ok(SigmaValue::String(parse_sigma_string(s))),
        Value::Tagged(tagged) => yaml_to_sigma_value(&tagged.value),
        other => Err(Error::InvalidValue {
            field: "detection value".into(),
            message: format!("Unsupported YAML value type: {other:?}"),
        }),
    }
}

fn yaml_to_sigma_values(value: &Value) -> Result<Vec<SigmaValue>, Error> {
    match value {
        Value::Sequence(seq) => seq.iter().map(yaml_to_sigma_value).collect(),
        other => Ok(vec![yaml_to_sigma_value(other)?]),
    }
}

// ─── Field name + modifier parsing ──────────────────────────────────────────

/// Parse a detection map key like `Image|endswith` into (field_name, modifiers).
fn parse_field_and_modifiers(key: &str) -> Result<(Option<String>, Vec<Modifier>), Error> {
    let parts: Vec<&str> = key.split('|').collect();
    let field = if parts[0].is_empty() {
        None
    } else {
        Some(parts[0].to_string())
    };
    let modifiers: Vec<Modifier> = parts[1..]
        .iter()
        .map(|m| parse_modifier(m))
        .collect::<Result<_, _>>()?;
    Ok((field, modifiers))
}

// ─── Detection parsing ──────────────────────────────────────────────────────

/// Parse a YAML mapping into a list of [`DetectionItem`]s (AND-connected).
fn parse_detection_map(map: &Mapping) -> Result<Vec<DetectionItem>, Error> {
    let mut items = Vec::new();
    for (key, value) in map {
        let key_str = key
            .as_str()
            .ok_or_else(|| Error::InvalidDetection(format!("Map key must be a string: {key:?}")))?;
        let (field, modifiers) = parse_field_and_modifiers(key_str)?;
        let values = yaml_to_sigma_values(value)?;
        items.push(DetectionItem {
            field,
            modifiers,
            values,
        });
    }
    Ok(items)
}

fn parse_search_identifier(value: &Value) -> Result<SearchIdentifier, Error> {
    match value {
        Value::Sequence(seq) => {
            if seq.is_empty() {
                return Err(Error::InvalidDetection("Empty detection list".into()));
            }
            let all_scalars = seq.iter().all(|v| {
                matches!(
                    v,
                    Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null
                )
            });
            let all_mappings = seq.iter().all(Value::is_mapping);

            if all_scalars {
                // Keyword search: list of values, OR-connected by default
                let values: Vec<SigmaValue> =
                    seq.iter().map(yaml_to_sigma_value).collect::<Result<_, _>>()?;
                Ok(SearchIdentifier::Map(vec![DetectionItem {
                    field: None,
                    modifiers: vec![],
                    values,
                }]))
            } else if all_mappings {
                // List of maps → OR of ANDs
                let maps: Vec<Vec<DetectionItem>> = seq
                    .iter()
                    .map(|v| parse_detection_map(v.as_mapping().unwrap()))
                    .collect::<Result<_, _>>()?;
                Ok(SearchIdentifier::MapList(maps))
            } else {
                Err(Error::InvalidDetection(
                    "Detection list contains mixed types (scalars and mappings)".into(),
                ))
            }
        }
        Value::Mapping(map) => {
            let items = parse_detection_map(map)?;
            Ok(SearchIdentifier::Map(items))
        }
        _ => Err(Error::InvalidDetection(format!(
            "Search identifier value must be a mapping or sequence, got: {value:?}"
        ))),
    }
}

fn parse_detection(detection_value: &Value) -> Result<Detection, Error> {
    let map = detection_value.as_mapping().ok_or_else(|| {
        Error::InvalidDetection("Detection section must be a mapping".into())
    })?;

    // Extract and parse condition(s)
    let condition_value = map
        .get("condition")
        .ok_or_else(|| Error::MissingField("detection.condition".into()))?;

    let condition_strings: Vec<String> = match condition_value {
        Value::String(s) => vec![s.clone()],
        Value::Sequence(seq) => seq
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| Error::InvalidValue {
                        field: "condition".into(),
                        message: "Condition list items must be strings".into(),
                    })
                    .map(str::to_string)
            })
            .collect::<Result<_, _>>()?,
        _ => {
            return Err(Error::InvalidValue {
                field: "condition".into(),
                message: "Condition must be a string or list of strings".into(),
            });
        }
    };

    let conditions: Vec<ConditionExpression> = condition_strings
        .iter()
        .map(|s| parse_condition(s))
        .collect::<Result<_, _>>()?;

    // Parse all search identifiers (every key except "condition")
    let mut search_identifiers = HashMap::new();
    for (key, value) in map {
        let key_str = key
            .as_str()
            .ok_or_else(|| Error::InvalidDetection(format!("Detection key must be a string: {key:?}")))?;
        if key_str == "condition" {
            continue;
        }
        search_identifiers.insert(key_str.to_string(), parse_search_identifier(value)?);
    }

    Ok(Detection {
        search_identifiers,
        conditions,
    })
}

// ─── Related entries ─────────────────────────────────────────────────────────

fn parse_related(value: &Value) -> Result<Vec<RelatedEntry>, Error> {
    let seq = value.as_sequence().ok_or_else(|| Error::InvalidValue {
        field: "related".into(),
        message: "Must be a sequence".into(),
    })?;
    seq.iter()
        .map(|item| {
            let map = item.as_mapping().ok_or_else(|| Error::InvalidValue {
                field: "related".into(),
                message: "Each entry must be a mapping".into(),
            })?;
            let id = get_string(map, "id")
                .ok_or_else(|| Error::MissingField("related[].id".into()))?;
            let type_str = get_str(map, "type")
                .ok_or_else(|| Error::MissingField("related[].type".into()))?;
            Ok(RelatedEntry {
                id,
                relation_type: parse_relation_type(type_str)?,
            })
        })
        .collect()
}

// ─── LogSource ───────────────────────────────────────────────────────────────

fn parse_logsource(value: &Value) -> Result<LogSource, Error> {
    let map = value.as_mapping().ok_or_else(|| Error::InvalidValue {
        field: "logsource".into(),
        message: "Must be a mapping".into(),
    })?;

    let known = ["category", "product", "service"];
    let mut custom = HashMap::new();
    for (k, v) in map {
        if let (Some(ks), Some(vs)) = (k.as_str(), v.as_str()) {
            if !known.contains(&ks) {
                custom.insert(ks.to_string(), vs.to_string());
            }
        }
    }

    Ok(LogSource {
        category: get_string(map, "category"),
        product: get_string(map, "product"),
        service: get_string(map, "service"),
        custom,
    })
}

// ─── Detection rule ──────────────────────────────────────────────────────────

fn parse_detection_rule(map: &Mapping) -> Result<SigmaRule, Error> {
    let title = get_string(map, "title")
        .ok_or_else(|| Error::MissingField("title".into()))?;

    let detection = parse_detection(
        map.get("detection")
            .ok_or_else(|| Error::MissingField("detection".into()))?,
    )?;
    let logsource = parse_logsource(
        map.get("logsource")
            .ok_or_else(|| Error::MissingField("logsource".into()))?,
    )?;

    let status = get_str(map, "status").map(parse_status).transpose()?;
    let level = get_str(map, "level").map(parse_level).transpose()?;
    let related = match map.get("related") {
        Some(v) => parse_related(v)?,
        None => Vec::new(),
    };

    let date = get_date(map, "date")?;
    let modified = get_date(map, "modified")?;

    // Collect custom (non-standard) fields
    let known_keys: &[&str] = &[
        "title",
        "id",
        "name",
        "related",
        "taxonomy",
        "status",
        "description",
        "license",
        "references",
        "author",
        "date",
        "modified",
        "logsource",
        "detection",
        "fields",
        "falsepositives",
        "level",
        "tags",
        "scope",
    ];
    let custom = collect_custom_fields(map, known_keys);

    Ok(SigmaRule {
        title,
        id: get_string(map, "id"),
        name: get_string(map, "name"),
        related,
        taxonomy: get_string(map, "taxonomy"),
        status,
        description: get_string(map, "description"),
        license: get_string(map, "license"),
        references: get_string_list(map, "references"),
        author: get_string(map, "author"),
        date,
        modified,
        logsource,
        detection,
        fields: get_string_list(map, "fields"),
        falsepositives: get_string_list(map, "falsepositives"),
        level,
        tags: get_string_list(map, "tags"),
        scope: get_string_list(map, "scope"),
        custom,
    })
}

// ─── Filter rule ─────────────────────────────────────────────────────────────

fn parse_filter_section(value: &Value) -> Result<FilterSection, Error> {
    let map = value.as_mapping().ok_or_else(|| {
        Error::InvalidValue {
            field: "filter".into(),
            message: "Filter section must be a mapping".into(),
        }
    })?;

    // Parse rules references (mandatory)
    let rules_value = map.get("rules").ok_or_else(|| Error::MissingField("filter.rules".into()))?;
    let rules = match rules_value {
        Value::Sequence(seq) => seq
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| Error::InvalidValue {
                        field: "filter.rules".into(),
                        message: "Each rule reference must be a string".into(),
                    })
                    .map(str::to_string)
            })
            .collect::<Result<Vec<_>, _>>()?,
        Value::String(s) => vec![s.clone()],
        _ => {
            return Err(Error::InvalidValue {
                field: "filter.rules".into(),
                message: "Rules must be a string or list of strings".into(),
            });
        }
    };

    // Parse condition (mandatory)
    let condition_value = map
        .get("condition")
        .ok_or_else(|| Error::MissingField("filter.condition".into()))?;

    let condition_strings: Vec<String> = match condition_value {
        Value::String(s) => vec![s.clone()],
        Value::Sequence(seq) => seq
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| Error::InvalidValue {
                        field: "filter.condition".into(),
                        message: "Condition list items must be strings".into(),
                    })
                    .map(str::to_string)
            })
            .collect::<Result<_, _>>()?,
        _ => {
            return Err(Error::InvalidValue {
                field: "filter.condition".into(),
                message: "Condition must be a string or list of strings".into(),
            });
        }
    };

    let conditions: Vec<ConditionExpression> = condition_strings
        .iter()
        .map(|s| parse_condition(s))
        .collect::<Result<_, _>>()?;

    // Parse search identifiers (every key except "rules" and "condition")
    let mut search_identifiers = HashMap::new();
    for (key, value) in map {
        let key_str = key
            .as_str()
            .ok_or_else(|| Error::InvalidDetection(format!("Filter key must be a string: {key:?}")))?;
        if key_str == "rules" || key_str == "condition" {
            continue;
        }
        search_identifiers.insert(key_str.to_string(), parse_search_identifier(value)?);
    }

    Ok(FilterSection {
        rules,
        search_identifiers,
        conditions,
    })
}

fn parse_filter_rule(map: &Mapping) -> Result<SigmaFilter, Error> {
    let title = get_string(map, "title")
        .ok_or_else(|| Error::MissingField("title".into()))?;

    let filter = parse_filter_section(
        map.get("filter")
            .ok_or_else(|| Error::MissingField("filter".into()))?,
    )?;

    let logsource = parse_logsource(
        map.get("logsource")
            .ok_or_else(|| Error::MissingField("logsource".into()))?,
    )?;

    let date = get_date(map, "date")?;
    let modified = get_date(map, "modified")?;

    let known_keys: &[&str] = &[
        "title",
        "id",
        "description",
        "date",
        "modified",
        "taxonomy",
        "logsource",
        "filter",
    ];
    let custom = collect_custom_fields(map, known_keys);

    Ok(SigmaFilter {
        title,
        id: get_string(map, "id"),
        description: get_string(map, "description"),
        date,
        modified,
        taxonomy: get_string(map, "taxonomy"),
        logsource,
        filter,
        custom,
    })
}

// ─── Correlation rule ────────────────────────────────────────────────────────

fn parse_aliases(value: &Value) -> Result<HashMap<String, HashMap<String, String>>, Error> {
    let map = value.as_mapping().ok_or_else(|| Error::InvalidValue {
        field: "aliases".into(),
        message: "Must be a mapping".into(),
    })?;

    let mut aliases = HashMap::new();
    for (alias_key, alias_value) in map {
        let alias_name = alias_key
            .as_str()
            .ok_or_else(|| Error::InvalidValue {
                field: "aliases".into(),
                message: "Alias name must be a string".into(),
            })?
            .to_string();

        let rule_map = alias_value.as_mapping().ok_or_else(|| Error::InvalidValue {
            field: "aliases".into(),
            message: format!("Alias '{alias_name}' must map to a mapping"),
        })?;

        let mut field_map = HashMap::new();
        for (rule_key, field_value) in rule_map {
            let rule_name = rule_key
                .as_str()
                .ok_or_else(|| Error::InvalidValue {
                    field: "aliases".into(),
                    message: "Rule name must be a string".into(),
                })?
                .to_string();
            let field_name = field_value
                .as_str()
                .ok_or_else(|| Error::InvalidValue {
                    field: "aliases".into(),
                    message: "Field name must be a string".into(),
                })?
                .to_string();
            field_map.insert(rule_name, field_name);
        }
        aliases.insert(alias_name, field_map);
    }

    Ok(aliases)
}

fn parse_correlation_condition(value: &Value) -> Result<CorrelationCondition, Error> {
    match value {
        // Extended condition expression (string) — for temporal correlations (SEP #198)
        Value::String(s) => {
            let expr = parse_condition(s)?;
            Ok(CorrelationCondition::Extended(expr))
        }
        // Simple numeric condition (mapping)
        Value::Mapping(map) => Ok(CorrelationCondition::Simple(SimpleCondition {
            field: get_string(map, "field"),
            gt: get_i64(map, "gt"),
            gte: get_i64(map, "gte"),
            lt: get_i64(map, "lt"),
            lte: get_i64(map, "lte"),
            eq: get_i64(map, "eq"),
            neq: get_i64(map, "neq"),
        })),
        _ => Err(Error::InvalidValue {
            field: "condition".into(),
            message: "Correlation condition must be a string or mapping".into(),
        }),
    }
}

fn parse_correlation_section(value: &Value) -> Result<Correlation, Error> {
    let map = value.as_mapping().ok_or_else(|| Error::InvalidValue {
        field: "correlation".into(),
        message: "Must be a mapping".into(),
    })?;

    let type_str = get_str(map, "type")
        .ok_or_else(|| Error::MissingField("correlation.type".into()))?;
    let correlation_type = parse_correlation_type(type_str)?;

    let rules = get_string_list(map, "rules");
    let group_by = get_string_list(map, "group-by");
    let timespan = get_string(map, "timespan");
    let condition = map
        .get("condition")
        .map(parse_correlation_condition)
        .transpose()?;
    // Validation rules:
    // - Extended correlation conditions are only allowed for Temporal / TemporalOrdered
    // - If Extended condition is given and `rules` is set, they must reference the same rules
    if let Some(CorrelationCondition::Extended(expr)) = &condition {
        match correlation_type {
            CorrelationType::Temporal | CorrelationType::TemporalOrdered => {}
            _ => {
                return Err(Error::InvalidValue {
                    field: "correlation.type".into(),
                    message: "Extended correlation condition is only allowed for 'temporal' and 'temporal_ordered' types".into(),
                })
            }
        }

        // If `rules` is present, ensure the extended expression references the same rules.
        if !rules.is_empty() {
            // Collect explicit identifiers from the condition expression. If the
            // expression uses pattern-based scopes (e.g. `1 of sel*`) or `them`, we
            // cannot reliably compare; require explicit identifiers in that case.
            use crate::types::ConditionExpression;
            fn collect_ids(expr: &ConditionExpression, out: &mut HashSet<String>) -> Result<(), Error> {
                match expr {
                    ConditionExpression::And(l, r) | ConditionExpression::Or(l, r) => {
                        collect_ids(l, out)?;
                        collect_ids(r, out)
                    }
                    ConditionExpression::Not(e) => collect_ids(e, out),
                    ConditionExpression::Identifier(s) => {
                        out.insert(s.clone());
                        Ok(())
                    }
                    // Pattern-based scopes are not allowed when `rules` is provided
                    ConditionExpression::OneOfPattern(_)
                    | ConditionExpression::AllOfPattern(_)
                    | ConditionExpression::OneOfThem
                    | ConditionExpression::AllOfThem => Err(Error::InvalidValue {
                        field: "correlation.condition".into(),
                        message: "Extended correlation condition must reference explicit rule names when 'rules' is provided".into(),
                    }),
                }
            }

            let mut ids = HashSet::new();
            collect_ids(expr, &mut ids)?;

            let rules_set: HashSet<String> = rules.iter().cloned().collect();
            if ids != rules_set {
                return Err(Error::InvalidValue {
                    field: "correlation".into(),
                    message: "Mismatch between 'condition' rule references and 'rules' list: they must reference the same rules".into(),
                });
            }
        }
    }
    let aliases = match map.get("aliases") {
        Some(v) => parse_aliases(v)?,
        None => HashMap::new(),
    };

    Ok(Correlation {
        correlation_type,
        rules,
        group_by,
        timespan,
        condition,
        aliases,
    })
}

fn parse_correlation_rule(map: &Mapping) -> Result<SigmaCorrelationRule, Error> {
    let title = get_string(map, "title")
        .ok_or_else(|| Error::MissingField("title".into()))?;

    let correlation = parse_correlation_section(
        map.get("correlation")
            .ok_or_else(|| Error::MissingField("correlation".into()))?,
    )?;

    let status = get_str(map, "status").map(parse_status).transpose()?;
    let level = get_str(map, "level").map(parse_level).transpose()?;
    let date = get_date(map, "date")?;
    let modified = get_date(map, "modified")?;

    let known_keys: &[&str] = &[
        "title",
        "id",
        "name",
        "status",
        "description",
        "author",
        "references",
        "date",
        "modified",
        "taxonomy",
        "correlation",
        "falsepositives",
        "level",
        "generate",
    ];
    let custom = collect_custom_fields(map, known_keys);

    Ok(SigmaCorrelationRule {
        title,
        id: get_string(map, "id"),
        name: get_string(map, "name"),
        status,
        description: get_string(map, "description"),
        author: get_string(map, "author"),
        references: get_string_list(map, "references"),
        date,
        modified,
        taxonomy: get_string(map, "taxonomy"),
        correlation,
        falsepositives: get_string_list(map, "falsepositives"),
        level,
        generate: get_bool(map, "generate"),
        custom,
    })
}

// ─── Utilities ───────────────────────────────────────────────────────────────

fn collect_custom_fields(map: &Mapping, known: &[&str]) -> HashMap<String, serde_yaml::Value> {
    let mut custom = HashMap::new();
    for (key, value) in map {
        if let Some(k) = key.as_str() {
            if !known.contains(&k) {
                custom.insert(k.to_string(), value.clone());
            }
        }
    }
    custom
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SigmaStringPart};

    #[test]
    fn test_parse_sigma_string_plain() {
        let result = parse_sigma_string("hello world");
        assert_eq!(result.parts.len(), 1);
        assert_eq!(result.parts[0], SigmaStringPart::Literal("hello world".to_string()));
    }

    #[test]
    fn test_parse_sigma_string_wildcards() {
        let result = parse_sigma_string("*.exe");
        assert_eq!(result.parts.len(), 2);
        assert_eq!(result.parts[0], SigmaStringPart::WildcardMulti);
        assert_eq!(result.parts[1], SigmaStringPart::Literal(".exe".to_string()));

        let result = parse_sigma_string("file?.txt");
        assert_eq!(result.parts.len(), 3);
        assert_eq!(result.parts[0], SigmaStringPart::Literal("file".to_string()));
        assert_eq!(result.parts[1], SigmaStringPart::WildcardSingle);
        assert_eq!(result.parts[2], SigmaStringPart::Literal(".txt".to_string()));
    }

    #[test]
    fn test_parse_sigma_string_placeholder() {
        // Placeholders are NOT parsed in parse_sigma_string - they remain as literals
        let result = parse_sigma_string("%SystemRoot%/System32/*.exe");
        assert_eq!(result.parts.len(), 3);
        assert_eq!(result.parts[0], SigmaStringPart::Literal("%SystemRoot%/System32/".to_string()));
        assert_eq!(result.parts[1], SigmaStringPart::WildcardMulti);
        assert_eq!(result.parts[2], SigmaStringPart::Literal(".exe".to_string()));

        // Windows paths with escaped backslashes before wildcard
        let result = parse_sigma_string("%SystemRoot%\\\\System32\\\\*.exe");
        assert_eq!(result.parts.len(), 3);
        assert_eq!(result.parts[0], SigmaStringPart::Literal("%SystemRoot%\\System32\\".to_string()));
        assert_eq!(result.parts[1], SigmaStringPart::WildcardMulti);
        assert_eq!(result.parts[2], SigmaStringPart::Literal(".exe".to_string()));
    }

    #[test]
    fn test_parse_sigma_string_invalid_placeholder() {
        // Unclosed placeholder should be treated as literal
        let result = parse_sigma_string("%unclosed");
        assert_eq!(result.parts.len(), 1);
        assert_eq!(result.parts[0], SigmaStringPart::Literal("%unclosed".to_string()));

        // Empty placeholder should be treated as literal
        let result = parse_sigma_string("%%");
        assert_eq!(result.parts.len(), 1);
        assert_eq!(result.parts[0], SigmaStringPart::Literal("%%".to_string()));
    }

    #[test]
    fn test_parse_sigma_string_complex() {
        // Placeholders are NOT parsed - they remain as literals
        let result = parse_sigma_string("*%TEMP%\\file?.log*");
        assert_eq!(result.parts.len(), 5);
        assert_eq!(result.parts[0], SigmaStringPart::WildcardMulti);
        assert_eq!(result.parts[1], SigmaStringPart::Literal("%TEMP%\\file".to_string()));
        assert_eq!(result.parts[2], SigmaStringPart::WildcardSingle);
        assert_eq!(result.parts[3], SigmaStringPart::Literal(".log".to_string()));
        assert_eq!(result.parts[4], SigmaStringPart::WildcardMulti);
    }

    #[test]
    fn test_parse_sigma_string_escape_sequences() {
        // Escaped wildcard should be literal
        let result = parse_sigma_string(r"\*.exe");
        assert_eq!(result.parts.len(), 1);
        assert_eq!(result.parts[0], SigmaStringPart::Literal("*.exe".to_string()));

        // Escaped question mark should be literal
        let result = parse_sigma_string(r"file\?.txt");
        assert_eq!(result.parts.len(), 1);
        assert_eq!(result.parts[0], SigmaStringPart::Literal("file?.txt".to_string()));

        // Escaped backslash should be literal
        let result = parse_sigma_string(r"path\\to\\file");
        assert_eq!(result.parts.len(), 1);
        assert_eq!(result.parts[0], SigmaStringPart::Literal(r"path\to\file".to_string()));

        // Backslash before % is treated as literal (% is not special in parse_sigma_string)
        let result = parse_sigma_string(r"\%notplaceholder\%");
        assert_eq!(result.parts.len(), 1);
        assert_eq!(result.parts[0], SigmaStringPart::Literal("\\%notplaceholder\\%".to_string()));

        // Mixed: escaped and non-escaped
        let result = parse_sigma_string(r"*.exe\*");
        assert_eq!(result.parts.len(), 2);
        assert_eq!(result.parts[0], SigmaStringPart::WildcardMulti);
        assert_eq!(result.parts[1], SigmaStringPart::Literal(".exe*".to_string()));

        // Backslash before non-special char treated as literal
        let result = parse_sigma_string(r"\ntest");
        assert_eq!(result.parts.len(), 1);
        assert_eq!(result.parts[0], SigmaStringPart::Literal(r"\ntest".to_string()));

        // Trailing backslash
        let result = parse_sigma_string(r"test\");
        assert_eq!(result.parts.len(), 1);
        assert_eq!(result.parts[0], SigmaStringPart::Literal(r"test\".to_string()));
    }
    #[test]
    fn test_expand_placeholders_basic() {
        // Simple placeholder expansion
        let sigma_str = parse_sigma_string("%TEMP%\\\\file.log");
        let expanded = expand_placeholders(&sigma_str);
        assert_eq!(expanded.parts.len(), 2);
        assert_eq!(expanded.parts[0], SigmaStringPart::Placeholder("TEMP".to_string()));
        assert_eq!(expanded.parts[1], SigmaStringPart::Literal("\\file.log".to_string()));
    }

    #[test]
    fn test_expand_placeholders_with_wildcards() {
        // Placeholder expansion should preserve wildcards
        let sigma_str = parse_sigma_string("%SystemRoot%/System32/*.exe");
        let expanded = expand_placeholders(&sigma_str);
        assert_eq!(expanded.parts.len(), 4);
        assert_eq!(expanded.parts[0], SigmaStringPart::Placeholder("SystemRoot".to_string()));
        assert_eq!(expanded.parts[1], SigmaStringPart::Literal("/System32/".to_string()));
        assert_eq!(expanded.parts[2], SigmaStringPart::WildcardMulti);
        assert_eq!(expanded.parts[3], SigmaStringPart::Literal(".exe".to_string()));
    }

    #[test]
    fn test_expand_placeholders_multiple() {
        // Multiple placeholders in one string
        let sigma_str = parse_sigma_string("%SystemRoot%\\\\%TEMP%\\\\file.log");
        let expanded = expand_placeholders(&sigma_str);
        assert_eq!(expanded.parts.len(), 4);
        assert_eq!(expanded.parts[0], SigmaStringPart::Placeholder("SystemRoot".to_string()));
        assert_eq!(expanded.parts[1], SigmaStringPart::Literal("\\".to_string()));
        assert_eq!(expanded.parts[2], SigmaStringPart::Placeholder("TEMP".to_string()));
        assert_eq!(expanded.parts[3], SigmaStringPart::Literal("\\file.log".to_string()));
    }

    #[test]
    fn test_expand_placeholders_invalid() {
        // Invalid placeholders should remain as literals
        let sigma_str = parse_sigma_string("%unclosed");
        let expanded = expand_placeholders(&sigma_str);
        assert_eq!(expanded.parts.len(), 1);
        assert_eq!(expanded.parts[0], SigmaStringPart::Literal("%unclosed".to_string()));

        // Empty placeholder names should remain as literals
        let sigma_str = parse_sigma_string("%%");
        let expanded = expand_placeholders(&sigma_str);
        assert_eq!(expanded.parts.len(), 1);
        assert_eq!(expanded.parts[0], SigmaStringPart::Literal("%%".to_string()));
    }

    #[test]
    fn test_expand_placeholders_no_placeholders() {
        // Strings without placeholders should remain unchanged
        let sigma_str = parse_sigma_string("*.exe");
        let expanded = expand_placeholders(&sigma_str);
        assert_eq!(expanded.parts.len(), 2);
        assert_eq!(expanded.parts[0], SigmaStringPart::WildcardMulti);
        assert_eq!(expanded.parts[1], SigmaStringPart::Literal(".exe".to_string()));
    }}
