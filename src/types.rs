//! All data types for Sigma detection rules, correlation rules, and condition AST.

use std::collections::HashMap;
use std::fmt;

use chrono::NaiveDate;

// ─── Common Enums ────────────────────────────────────────────────────────────

/// Status of a Sigma rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    Stable,
    Test,
    Experimental,
    Deprecated,
    Unsupported,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stable => write!(f, "stable"),
            Self::Test => write!(f, "test"),
            Self::Experimental => write!(f, "experimental"),
            Self::Deprecated => write!(f, "deprecated"),
            Self::Unsupported => write!(f, "unsupported"),
        }
    }
}

/// Severity level of a Sigma rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Level {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Informational => write!(f, "informational"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Type of relationship between Sigma rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelationType {
    Derived,
    Obsolete,
    Merged,
    Renamed,
    Similar,
}

/// A reference to a related Sigma rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelatedEntry {
    pub id: String,
    pub relation_type: RelationType,
}

// ─── LogSource ───────────────────────────────────────────────────────────────

/// Describes the log source a detection rule applies to.
#[derive(Debug, Clone, PartialEq)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

// ─── Value Modifiers ─────────────────────────────────────────────────────────

/// A value modifier that transforms or constrains how detection values are matched.
///
/// Modifiers are applied in order via pipe syntax: `field|mod1|mod2: value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Modifier {
    // Generic modifiers (applicable to all field types)
    /// Changes list logic from OR to AND.
    All,
    /// Wraps value with `*...*` wildcards.
    Contains,
    /// Adds `value*` wildcard.
    StartsWith,
    /// Adds `*value` wildcard.
    EndsWith,
    /// Checks for field existence (value must be bool).
    Exists,
    /// Enables case-sensitive matching (default is case-insensitive).
    Cased,
    /// Field value must NOT equal the specified value.
    Neq,

    // String modifiers
    /// Value is a regular expression (PCRE subset).
    Re,
    /// Regex sub-modifier: case-insensitive.
    I,
    /// Regex sub-modifier: multi-line (`^`/`$` match line boundaries).
    M,
    /// Regex sub-modifier: single-line (`.` matches newlines).
    S,
    /// Base64-encode the value.
    Base64,
    /// Search for all three Base64 offset variants.
    Base64Offset,
    /// Encode value as UTF-16LE.
    Utf16Le,
    /// Encode value as UTF-16BE.
    Utf16Be,
    /// Encode value as UTF-16 with BOM.
    Utf16,
    /// Alias for `Utf16Le`.
    Wide,
    /// Generate all dash permutations (`-`, `/`, en-dash, em-dash, horizontal bar).
    Windash,

    // Numeric modifiers
    /// Field value is less than the specified value.
    Lt,
    /// Field value is less than or equal to the specified value.
    Lte,
    /// Field value is greater than the specified value.
    Gt,
    /// Field value is greater than or equal to the specified value.
    Gte,

    // Time modifiers (extract numeric component from a date)
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,

    // IP modifiers
    /// Value is a CIDR network range.
    Cidr,

    // Specific modifiers
    /// Expand placeholders (e.g. `%Servers%`).
    Expand,
    /// Value is a reference to another field.
    FieldRef,
}

// ─── Sigma String ────────────────────────────────────────────────────────────

/// A part of a Sigma string value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SigmaStringPart {
    /// A literal string segment.
    Literal(String),
    /// Multi-character wildcard (`*`).
    WildcardMulti,
    /// Single-character wildcard (`?`).
    WildcardSingle,
    /// A placeholder (e.g., `%Servers%`).
    Placeholder(String),
}

/// A Sigma string that may contain literals, wildcards, and placeholders.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SigmaString {
    pub parts: Vec<SigmaStringPart>,
}

impl SigmaString {
    /// Creates a new Sigma string from a plain literal.
    pub fn from_literal(s: impl Into<String>) -> Self {
        Self {
            parts: vec![SigmaStringPart::Literal(s.into())],
        }
    }

    /// Returns true if this string contains any wildcards or placeholders.
    pub fn has_special_parts(&self) -> bool {
        self.parts.iter().any(|p| !matches!(p, SigmaStringPart::Literal(_)))
    }

    /// Converts to a plain string if it contains only a single literal part.
    pub fn as_plain(&self) -> Option<&str> {
        if self.parts.len() == 1 {
            if let SigmaStringPart::Literal(s) = &self.parts[0] {
                return Some(s);
            }
        }
        None
    }
}

impl fmt::Display for SigmaString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for part in &self.parts {
            match part {
                SigmaStringPart::Literal(s) => write!(f, "{s}")?,
                SigmaStringPart::WildcardMulti => write!(f, "*")?,
                SigmaStringPart::WildcardSingle => write!(f, "?")?,
                SigmaStringPart::Placeholder(name) => write!(f, "%{name}%")?,
            }
        }
        Ok(())
    }
}

impl From<String> for SigmaString {
    fn from(s: String) -> Self {
        Self::from_literal(s)
    }
}

impl From<&str> for SigmaString {
    fn from(s: &str) -> Self {
        Self::from_literal(s)
    }
}

// ─── Detection Values ────────────────────────────────────────────────────────

/// A typed value that can appear in a Sigma detection.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum SigmaValue {
    String(SigmaString),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
}

impl<'de> serde::Deserialize<'de> for SigmaValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_yaml::Value::deserialize(deserializer)?;
        match value {
            serde_yaml::Value::String(s) => Ok(SigmaValue::String(SigmaString::from_literal(s))),
            serde_yaml::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(SigmaValue::Int(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(SigmaValue::Float(f))
                } else {
                    Err(serde::de::Error::custom("Invalid number"))
                }
            }
            serde_yaml::Value::Bool(b) => Ok(SigmaValue::Bool(b)),
            serde_yaml::Value::Null => Ok(SigmaValue::Null),
            _ => Err(serde::de::Error::custom("Invalid SigmaValue type")),
        }
    }
}

impl fmt::Display for SigmaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "{s}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Null => write!(f, "null"),
        }
    }
}

// ─── Detection Items ─────────────────────────────────────────────────────────

/// A single detection item: a field (with optional modifiers) matched against one or more values.
///
/// - If `field` is `None`, this is a keyword search (matches against the full log message).
/// - Multiple `values` are OR-connected (unless the `All` modifier changes this to AND).
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionItem {
    /// The field name to match against, or `None` for keyword searches.
    pub field: Option<String>,
    /// Modifiers parsed from pipe-separated syntax (e.g. `endswith`, `re|i`).
    pub modifiers: Vec<Modifier>,
    /// One or more values to match (OR-connected by default).
    pub values: Vec<SigmaValue>,
}

/// A named search identifier in the detection section.
#[derive(Debug, Clone, PartialEq)]
pub enum SearchIdentifier {
    /// AND-connected detection items from a single map or keyword list.
    Map(Vec<DetectionItem>),
    /// OR-connected list of AND-connected detection item groups (list of maps).
    MapList(Vec<Vec<DetectionItem>>),
}

/// The detection section of a Sigma rule.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    /// Named search identifiers (e.g. `selection`, `filter`).
    pub search_identifiers: HashMap<String, SearchIdentifier>,
    /// One or more condition expressions. Multiple conditions are implicit OR.
    pub conditions: Vec<ConditionExpression>,
}

// ─── Condition AST ───────────────────────────────────────────────────────────

/// AST node for a Sigma condition expression.
///
/// Used both in standard detection rule conditions and extended correlation conditions.
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionExpression {
    /// Logical AND of two sub-expressions.
    And(Box<ConditionExpression>, Box<ConditionExpression>),
    /// Logical OR of two sub-expressions.
    Or(Box<ConditionExpression>, Box<ConditionExpression>),
    /// Logical NOT of a sub-expression.
    Not(Box<ConditionExpression>),
    /// Reference to a search identifier (or rule name in correlation conditions).
    Identifier(String),
    /// `1 of them` — any non-underscore-prefixed search identifier matches.
    OneOfThem,
    /// `all of them` — all non-underscore-prefixed search identifiers match.
    AllOfThem,
    /// `1 of <pattern>` — any matching search identifier matches (pattern may contain `*`).
    OneOfPattern(String),
    /// `all of <pattern>` — all matching search identifiers match.
    AllOfPattern(String),
}

impl fmt::Display for ConditionExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::And(l, r) => write!(f, "({l} and {r})"),
            Self::Or(l, r) => write!(f, "({l} or {r})"),
            Self::Not(e) => write!(f, "not {e}"),
            Self::Identifier(s) => write!(f, "{s}"),
            Self::OneOfThem => write!(f, "1 of them"),
            Self::AllOfThem => write!(f, "all of them"),
            Self::OneOfPattern(p) => write!(f, "1 of {p}"),
            Self::AllOfPattern(p) => write!(f, "all of {p}"),
        }
    }
}

// ─── Sigma Detection Rule ────────────────────────────────────────────────────

/// A fully-parsed Sigma detection rule.
///
/// # Date Handling
///
/// The `date` and `modified` fields use [`chrono::NaiveDate`] for proper date
/// representation and support comparison operations:
///
/// ```
/// use sigma_engine::{SigmaCollection, SigmaDocument};
/// use chrono::NaiveDate;
///
/// let yaml = r#"
/// title: Example Rule
/// date: 2024-01-15
/// modified: 2024-02-20
/// logsource:
///     product: windows
/// detection:
///     sel:
///         EventID: 4688
///     condition: sel
/// "#;
///
/// let collection = SigmaCollection::from_yaml(yaml).unwrap();
/// if let SigmaDocument::Rule(rule) = &collection.documents[0] {
///     if let (Some(created), Some(modified)) = (rule.date, rule.modified) {
///         assert!(modified > created);  // Date comparison
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SigmaRule {
    /// Brief title describing what the rule detects (max 256 chars).
    pub title: String,
    /// Globally unique identifier (UUID v4).
    pub id: Option<String>,
    /// Human-readable name for cross-referencing in correlation rules.
    pub name: Option<String>,
    /// References to related rules.
    pub related: Vec<RelatedEntry>,
    /// Taxonomy identifier (default: `sigma`).
    pub taxonomy: Option<String>,
    pub status: Option<Status>,
    pub description: Option<String>,
    /// SPDX license identifier.
    pub license: Option<String>,
    /// URLs referencing source material.
    pub references: Vec<String>,
    pub author: Option<String>,
    /// Creation date in ISO 8601 format (YYYY-MM-DD).
    /// Supports comparison operators (e.g., `<`, `>`, `==`).
    pub date: Option<NaiveDate>,
    /// Last modification date in ISO 8601 format.
    /// Supports comparison operators (e.g., `<`, `>`, `==`).
    pub modified: Option<NaiveDate>,
    pub logsource: LogSource,
    pub detection: Detection,
    /// Fields of interest for analyst review.
    pub fields: Vec<String>,
    pub falsepositives: Vec<String>,
    pub level: Option<Level>,
    /// Tags for categorisation (e.g. `attack.t1234`).
    pub tags: Vec<String>,
    /// Intended scopes (e.g. `server`).
    pub scope: Vec<String>,
    /// Any additional fields not part of the standard specification.
    pub custom: HashMap<String, serde_yaml::Value>,
}

// ─── Correlation Rule Types ──────────────────────────────────────────────────

/// Type of a Sigma correlation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorrelationType {
    /// Count matching events.
    EventCount,
    /// Count distinct field values.
    ValueCount,
    /// All referenced rules must fire within the timespan (unordered).
    Temporal,
    /// All referenced rules must fire within the timespan in order.
    TemporalOrdered,
    /// Sum a numeric field across events.
    ValueSum,
    /// Average a numeric field across events.
    ValueAvg,
    /// Percentile of a numeric field across events.
    ValuePercentile,
}

/// A simple numeric condition used in aggregation-type correlations
/// (`event_count`, `value_count`, `value_sum`, `value_avg`, `value_percentile`).
#[derive(Debug, Clone, PartialEq)]
pub struct SimpleCondition {
    /// The field to aggregate (required for `value_count`, `value_sum`, etc.).
    pub field: Option<String>,
    pub gt: Option<i64>,
    pub gte: Option<i64>,
    pub lt: Option<i64>,
    pub lte: Option<i64>,
    pub eq: Option<i64>,
    pub neq: Option<i64>,
}

/// Condition for a correlation rule.
#[derive(Debug, Clone, PartialEq)]
pub enum CorrelationCondition {
    /// Simple numeric threshold (e.g. `gte: 100`).
    Simple(SimpleCondition),
    /// Extended boolean expression referencing rule names
    /// (for `temporal` / `temporal_ordered`, per SEP #198).
    Extended(ConditionExpression),
}

/// The `correlation` section of a Sigma correlation rule.
#[derive(Debug, Clone, PartialEq)]
pub struct Correlation {
    pub correlation_type: CorrelationType,
    /// References to Sigma rules or other correlations (by `id` or `name`).
    pub rules: Vec<String>,
    /// Fields to group events by; events must share the same value(s).
    pub group_by: Vec<String>,
    /// Time window (e.g. `1h`, `5m`, `30s`).
    pub timespan: Option<String>,
    pub condition: Option<CorrelationCondition>,
    /// Field name aliases: `alias_name` → { `rule_name` → `field_name` }.
    pub aliases: HashMap<String, HashMap<String, String>>,
}

/// A fully-parsed Sigma correlation rule.
#[derive(Debug, Clone, PartialEq)]
pub struct SigmaCorrelationRule {
    pub title: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub status: Option<Status>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub references: Vec<String>,
    pub date: Option<NaiveDate>,
    pub modified: Option<NaiveDate>,
    pub taxonomy: Option<String>,
    pub correlation: Correlation,
    pub falsepositives: Vec<String>,
    pub level: Option<Level>,
    /// Whether referred rules should also generate standalone queries.
    pub generate: Option<bool>,
    pub custom: HashMap<String, serde_yaml::Value>,
}

// ─── Sigma Filter Rule ───────────────────────────────────────────────────────

/// The `filter` section of a Sigma filter rule.
#[derive(Debug, Clone, PartialEq)]
pub struct FilterSection {
    /// References to Sigma rules (by `id`) where the filter should be applied.
    pub rules: Vec<String>,
    /// Named search identifiers (same semantics as in detection rules).
    pub search_identifiers: HashMap<String, SearchIdentifier>,
    /// The condition expression combining the search identifiers.
    pub conditions: Vec<ConditionExpression>,
}

/// A fully-parsed Sigma filter rule.
///
/// Sigma filters adapt existing [`SigmaRule`] objects by adding additional
/// conditions as defined in the filter specification.
#[derive(Debug, Clone, PartialEq)]
pub struct SigmaFilter {
    /// Brief title describing the filter (max 256 chars).
    pub title: String,
    /// Globally unique identifier (UUID v4).
    pub id: Option<String>,
    /// Description of the filter.
    pub description: Option<String>,
    /// Creation date in ISO 8601 format (YYYY-MM-DD).
    pub date: Option<NaiveDate>,
    /// Last modification date in ISO 8601 format.
    pub modified: Option<NaiveDate>,
    /// Taxonomy identifier (default: `sigma`).
    pub taxonomy: Option<String>,
    /// Log source this filter applies to.
    pub logsource: LogSource,
    /// The filter section containing rules, selections, and conditions.
    pub filter: FilterSection,
    /// Any additional fields not part of the standard specification.
    pub custom: HashMap<String, serde_yaml::Value>,
}

impl SigmaFilter {
    /// Apply this filter to a Sigma rule, modifying its detection section.
    ///
    /// The filter is applied only if:
    /// 1. The rule's id matches one of the filter's `rules` references.
    /// 2. The rule's logsource is compatible with the filter's logsource.
    ///
    /// When applied, the filter's search identifiers are merged into the rule's
    /// detection section (with a unique prefix to avoid name collisions), and the
    /// rule's conditions are extended with `and not <filter_condition>`.
    pub fn apply(&self, rule: &mut SigmaRule) -> bool {
        // Check if the rule matches the filter's target rules
        let rule_id = match &rule.id {
            Some(id) => id.clone(),
            None => return false,
        };

        if !self.filter.rules.contains(&rule_id) {
            return false;
        }

        // Check logsource compatibility
        if !self.logsource_matches(&rule.logsource) {
            return false;
        }

        // Generate a unique prefix for the filter's search identifiers.
        // Use a hash of the filter ID to avoid collisions when IDs differ
        // only in characters like '-' vs '_'.
        let prefix = {
            let id_str = self.id.as_deref().unwrap_or("anon");
            let hash = id_str.bytes().fold(0u64, |acc, b| {
                acc.wrapping_mul(31).wrapping_add(b as u64)
            });
            format!("_filter_{:016x}_", hash)
        };

        // Merge filter search identifiers into the rule's detection
        for (name, search_id) in &self.filter.search_identifiers {
            let prefixed_name = format!("{}{}", prefix, name);
            rule.detection
                .search_identifiers
                .insert(prefixed_name, search_id.clone());
        }

        // Extend each of the rule's existing conditions with the filter condition
        let new_conditions: Vec<ConditionExpression> = rule
            .detection
            .conditions
            .iter()
            .map(|existing_cond| {
                // Build the filter condition expression with prefixed identifiers
                let filter_conds: Vec<ConditionExpression> = self
                    .filter
                    .conditions
                    .iter()
                    .map(|fc| prefix_identifiers(fc, &prefix))
                    .collect();

                // Combine filter conditions (multiple conditions are OR-ed).
                // This is safe because the parser validates that at least one
                // condition is present in the filter section.
                let combined_filter = filter_conds
                    .into_iter()
                    .reduce(|a, b| ConditionExpression::Or(Box::new(a), Box::new(b)))
                    .expect("filter must have at least one condition (enforced by parser)");

                // Extend: existing_condition and not (filter_condition)
                ConditionExpression::And(
                    Box::new(existing_cond.clone()),
                    Box::new(ConditionExpression::Not(Box::new(combined_filter))),
                )
            })
            .collect();

        rule.detection.conditions = new_conditions;

        true
    }

    /// Check if the filter's logsource is compatible with a rule's logsource.
    ///
    /// A filter's logsource matches if every field specified in the filter
    /// is equal to the corresponding field in the rule. Fields not specified
    /// in the filter are ignored (wildcard match).
    fn logsource_matches(&self, rule_logsource: &LogSource) -> bool {
        if let Some(ref cat) = self.logsource.category {
            if rule_logsource.category.as_deref() != Some(cat) {
                return false;
            }
        }
        if let Some(ref prod) = self.logsource.product {
            if rule_logsource.product.as_deref() != Some(prod) {
                return false;
            }
        }
        if let Some(ref svc) = self.logsource.service {
            if rule_logsource.service.as_deref() != Some(svc) {
                return false;
            }
        }
        true
    }
}

/// Prefix all `Identifier` nodes in a condition expression.
fn prefix_identifiers(expr: &ConditionExpression, prefix: &str) -> ConditionExpression {
    match expr {
        ConditionExpression::And(l, r) => ConditionExpression::And(
            Box::new(prefix_identifiers(l, prefix)),
            Box::new(prefix_identifiers(r, prefix)),
        ),
        ConditionExpression::Or(l, r) => ConditionExpression::Or(
            Box::new(prefix_identifiers(l, prefix)),
            Box::new(prefix_identifiers(r, prefix)),
        ),
        ConditionExpression::Not(e) => {
            ConditionExpression::Not(Box::new(prefix_identifiers(e, prefix)))
        }
        ConditionExpression::Identifier(name) => {
            ConditionExpression::Identifier(format!("{}{}", prefix, name))
        }
        ConditionExpression::OneOfPattern(pattern) => {
            ConditionExpression::OneOfPattern(format!("{}{}", prefix, pattern))
        }
        ConditionExpression::AllOfPattern(pattern) => {
            ConditionExpression::AllOfPattern(format!("{}{}", prefix, pattern))
        }
        // OneOfThem and AllOfThem are left unchanged — they refer to
        // all search identifiers in the detection section.
        other => other.clone(),
    }
}

// ─── Document / Collection ───────────────────────────────────────────────────

/// A parsed Sigma YAML document: either a detection rule, a correlation rule,
/// or a filter rule.
#[derive(Debug, Clone, PartialEq)]
pub enum SigmaDocument {
    Rule(SigmaRule),
    Correlation(SigmaCorrelationRule),
    Filter(SigmaFilter),
}

/// A collection of Sigma documents parsed from a (possibly multi-document) YAML string.
#[derive(Debug, Clone)]
pub struct SigmaCollection {
    pub documents: Vec<SigmaDocument>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_display() {
        assert_eq!(Status::Stable.to_string(), "stable");
        assert_eq!(Status::Test.to_string(), "test");
        assert_eq!(Status::Experimental.to_string(), "experimental");
        assert_eq!(Status::Deprecated.to_string(), "deprecated");
        assert_eq!(Status::Unsupported.to_string(), "unsupported");
    }

    #[test]
    fn level_display() {
        assert_eq!(Level::Informational.to_string(), "informational");
        assert_eq!(Level::Low.to_string(), "low");
        assert_eq!(Level::Medium.to_string(), "medium");
        assert_eq!(Level::High.to_string(), "high");
        assert_eq!(Level::Critical.to_string(), "critical");
    }

    #[test]
    fn sigma_string_has_special_parts() {
        let plain = SigmaString::from_literal("hello");
        assert!(!plain.has_special_parts());

        let with_wildcard = SigmaString {
            parts: vec![
                SigmaStringPart::Literal("a".into()),
                SigmaStringPart::WildcardMulti,
            ],
        };
        assert!(with_wildcard.has_special_parts());
    }

    #[test]
    fn sigma_string_as_plain_none() {
        // Multiple parts → None
        let multi = SigmaString {
            parts: vec![
                SigmaStringPart::Literal("a".into()),
                SigmaStringPart::WildcardMulti,
            ],
        };
        assert!(multi.as_plain().is_none());

        // Single non-literal part → None
        let wc = SigmaString {
            parts: vec![SigmaStringPart::WildcardSingle],
        };
        assert!(wc.as_plain().is_none());
    }

    #[test]
    fn sigma_string_display_special() {
        let s = SigmaString {
            parts: vec![
                SigmaStringPart::Literal("a".into()),
                SigmaStringPart::WildcardSingle,
                SigmaStringPart::Placeholder("FOO".into()),
            ],
        };
        assert_eq!(s.to_string(), "a?%FOO%");
    }

    #[test]
    fn sigma_string_from_string() {
        let s: SigmaString = String::from("hello").into();
        assert_eq!(s.as_plain(), Some("hello"));
    }

    #[test]
    fn sigma_value_deserialize_all_types() {
        let float_val: SigmaValue = serde_yaml::from_str("3.14").unwrap();
        assert!(matches!(float_val, SigmaValue::Float(f) if (f - 3.14).abs() < 0.001));

        let bool_val: SigmaValue = serde_yaml::from_str("true").unwrap();
        assert_eq!(bool_val, SigmaValue::Bool(true));

        let int_val: SigmaValue = serde_yaml::from_str("42").unwrap();
        assert_eq!(int_val, SigmaValue::Int(42));

        let null_val: SigmaValue = serde_yaml::from_str("null").unwrap();
        assert_eq!(null_val, SigmaValue::Null);
    }

    #[test]
    fn sigma_value_display() {
        assert_eq!(SigmaValue::String("hi".into()).to_string(), "hi");
        assert_eq!(SigmaValue::Int(42).to_string(), "42");
        assert_eq!(SigmaValue::Float(1.5).to_string(), "1.5");
        assert_eq!(SigmaValue::Bool(false).to_string(), "false");
        assert_eq!(SigmaValue::Null.to_string(), "null");
    }

    #[test]
    fn condition_expression_display() {
        assert_eq!(
            ConditionExpression::Or(
                Box::new(ConditionExpression::Identifier("a".into())),
                Box::new(ConditionExpression::Identifier("b".into())),
            )
            .to_string(),
            "(a or b)"
        );
        assert_eq!(
            ConditionExpression::Not(Box::new(ConditionExpression::Identifier("x".into())))
                .to_string(),
            "not x"
        );
        assert_eq!(ConditionExpression::OneOfThem.to_string(), "1 of them");
        assert_eq!(ConditionExpression::AllOfThem.to_string(), "all of them");
        assert_eq!(
            ConditionExpression::OneOfPattern("sel*".into()).to_string(),
            "1 of sel*"
        );
        assert_eq!(
            ConditionExpression::AllOfPattern("sel*".into()).to_string(),
            "all of sel*"
        );
    }

    #[test]
    fn level_display_all() {
        assert_eq!(Level::Informational.to_string(), "informational");
        assert_eq!(Level::Low.to_string(), "low");
        assert_eq!(Level::Medium.to_string(), "medium");
        assert_eq!(Level::High.to_string(), "high");
        assert_eq!(Level::Critical.to_string(), "critical");
    }

    #[test]
    fn sigma_value_deserialize_invalid_sequence() {
        // A YAML sequence cannot be deserialized as a SigmaValue
        let yaml = "- a\n- b";
        let result: std::result::Result<SigmaValue, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }
}
