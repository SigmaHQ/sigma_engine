//! # Sigma Engine
//!
//! A Rust library for parsing [Sigma](https://sigmahq.io) detection and correlation rules
//! from YAML.
//!
//! ## Supported specifications
//!
//! - **Sigma Rules** v2.1.0 — detection rules with logsource, detection section (maps, lists,
//!   keyword searches, value modifiers) and boolean condition expressions.
//! - **Sigma Correlation Rules** v2.1.0 — `event_count`, `value_count`, `temporal`,
//!   `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile` with field aliases.
//! - **Extended Correlation Conditions** (SEP #198) — boolean condition expressions in
//!   `temporal` / `temporal_ordered` correlations referencing rule names.
//!
//! ## Quick start
//!
//! ```rust
//! use sigma_engine::{SigmaCollection, SigmaDocument};
//!
//! let yaml = r#"
//! title: Whoami Execution
//! logsource:
//!     category: process_creation
//!     product: windows
//! detection:
//!     selection:
//!         Image: 'C:\Windows\System32\whoami.exe'
//!     condition: selection
//! level: high
//! "#;
//!
//! let collection = SigmaCollection::from_yaml(yaml).unwrap();
//! assert_eq!(collection.documents.len(), 1);
//! match &collection.documents[0] {
//!     SigmaDocument::Rule(rule) => assert_eq!(rule.title, "Whoami Execution"),
//!     _ => panic!("Expected a detection rule"),
//! }
//! ```

pub mod condition;
pub mod error;
mod parser;
pub mod pipeline;
pub mod types;

pub use error::Error;
pub use pipeline::*;
pub use types::*;

// Re-export chrono's NaiveDate for date field access
pub use chrono::NaiveDate;

// ─── Integration tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Detection rules ──────────────────────────────────────────────────

    #[test]
    fn parse_basic_detection_rule() {
        let yaml = r#"
title: Whoami Execution
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
status: experimental
description: Detects a whoami.exe execution
author: Florian Roth
date: '2019-10-23'
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'C:\Windows\System32\whoami.exe'
    condition: selection
level: high
tags:
    - attack.discovery
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        assert_eq!(coll.documents.len(), 1);
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        assert_eq!(rule.title, "Whoami Execution");
        assert_eq!(
            rule.id.as_deref(),
            Some("929a690e-bef0-4204-a928-ef5e620d6fcc")
        );
        assert_eq!(rule.status, Some(Status::Experimental));
        assert_eq!(rule.level, Some(Level::High));
        assert_eq!(rule.logsource.category.as_deref(), Some("process_creation"));
        assert_eq!(rule.logsource.product.as_deref(), Some("windows"));
        assert_eq!(rule.tags, vec!["attack.discovery"]);

        // Detection: single search identifier "selection"
        assert_eq!(rule.detection.search_identifiers.len(), 1);
        let sel = &rule.detection.search_identifiers["selection"];
        match sel {
            SearchIdentifier::Map(items) => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].field.as_deref(), Some("Image"));
                assert!(items[0].modifiers.is_empty());
                assert_eq!(
                    items[0].values,
                    vec![SigmaValue::String(
                        r"C:\Windows\System32\whoami.exe".into()
                    )]
                );
            }
            _ => panic!("Expected Map"),
        }

        // Condition
        assert_eq!(rule.detection.conditions.len(), 1);
        assert_eq!(
            rule.detection.conditions[0],
            ConditionExpression::Identifier("selection".into())
        );
    }

    #[test]
    fn parse_rule_with_modifiers_and_lists() {
        let yaml = r#"
title: Suspicious Process
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
        CommandLine|contains|all:
            - '-enc'
            - '-nop'
    filter:
        ParentImage|endswith: '\explorer.exe'
    condition: selection and not filter
level: medium
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };

        // Check modifiers on selection
        let sel = match &rule.detection.search_identifiers["selection"] {
            SearchIdentifier::Map(items) => items,
            _ => panic!("Expected Map"),
        };
        assert_eq!(sel.len(), 2);

        // Image|endswith
        assert_eq!(sel[0].field.as_deref(), Some("Image"));
        assert_eq!(sel[0].modifiers, vec![Modifier::EndsWith]);
        assert_eq!(sel[0].values.len(), 2);

        // CommandLine|contains|all
        assert_eq!(sel[1].field.as_deref(), Some("CommandLine"));
        assert_eq!(
            sel[1].modifiers,
            vec![Modifier::Contains, Modifier::All]
        );
        assert_eq!(sel[1].values.len(), 2);

        // Condition: selection and not filter
        assert_eq!(
            rule.detection.conditions[0],
            ConditionExpression::And(
                Box::new(ConditionExpression::Identifier("selection".into())),
                Box::new(ConditionExpression::Not(Box::new(
                    ConditionExpression::Identifier("filter".into())
                ))),
            )
        );
    }

    #[test]
    fn parse_keyword_search() {
        let yaml = r#"
title: Keyword Test
logsource:
    category: test
detection:
    keywords_or:
        - 'EVILSERVICE'
        - 'svchost.exe -n evil'
    keywords_and:
        '|all':
            - 'OabVirtualDirectory'
            - ' -ExternalUrl '
    condition: keywords_or or keywords_and
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };

        // OR keywords
        let kw_or = match &rule.detection.search_identifiers["keywords_or"] {
            SearchIdentifier::Map(items) => items,
            _ => panic!("Expected Map"),
        };
        assert_eq!(kw_or.len(), 1);
        assert!(kw_or[0].field.is_none());
        assert!(kw_or[0].modifiers.is_empty());
        assert_eq!(kw_or[0].values.len(), 2);

        // AND keywords
        let kw_and = match &rule.detection.search_identifiers["keywords_and"] {
            SearchIdentifier::Map(items) => items,
            _ => panic!("Expected Map"),
        };
        assert_eq!(kw_and.len(), 1);
        assert!(kw_and[0].field.is_none());
        assert_eq!(kw_and[0].modifiers, vec![Modifier::All]);
        assert_eq!(kw_and[0].values.len(), 2);
    }

    #[test]
    fn parse_null_and_empty_values() {
        let yaml = r#"
title: Null Test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4738
    filter_null:
        PasswordLastSet: null
    filter_empty:
        PasswordLastSet: ''
    condition: selection and not filter_null and not filter_empty
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };

        let null_items = match &rule.detection.search_identifiers["filter_null"] {
            SearchIdentifier::Map(items) => items,
            _ => panic!("Expected Map"),
        };
        assert_eq!(null_items[0].values, vec![SigmaValue::Null]);

        let empty_items = match &rule.detection.search_identifiers["filter_empty"] {
            SearchIdentifier::Map(items) => items,
            _ => panic!("Expected Map"),
        };
        assert_eq!(
            empty_items[0].values,
            vec![SigmaValue::String("".into())]
        );
    }

    #[test]
    fn parse_exists_modifier() {
        let yaml = r#"
title: Exists Test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4738
        PasswordLastSet|exists: true
    condition: selection
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        let items = match &rule.detection.search_identifiers["selection"] {
            SearchIdentifier::Map(items) => items,
            _ => panic!("Expected Map"),
        };
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].field.as_deref(), Some("PasswordLastSet"));
        assert_eq!(items[1].modifiers, vec![Modifier::Exists]);
        assert_eq!(items[1].values, vec![SigmaValue::Bool(true)]);
    }

    #[test]
    fn parse_list_of_maps() {
        let yaml = r#"
title: List of Maps
logsource:
    category: test
detection:
    selection:
        - Image|endswith: '\example.exe'
        - Description|contains: 'Test executable'
    condition: selection
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        match &rule.detection.search_identifiers["selection"] {
            SearchIdentifier::MapList(maps) => {
                assert_eq!(maps.len(), 2);
                assert_eq!(maps[0][0].field.as_deref(), Some("Image"));
                assert_eq!(maps[0][0].modifiers, vec![Modifier::EndsWith]);
                assert_eq!(maps[1][0].field.as_deref(), Some("Description"));
                assert_eq!(maps[1][0].modifiers, vec![Modifier::Contains]);
            }
            _ => panic!("Expected MapList"),
        }
    }

    #[test]
    fn parse_multiple_conditions() {
        let yaml = r#"
title: Multi Condition
logsource:
    category: test
detection:
    sel1:
        FieldA: 'a'
    sel2:
        FieldB: 'b'
    condition:
        - sel1
        - sel2
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        assert_eq!(rule.detection.conditions.len(), 2);
        assert_eq!(
            rule.detection.conditions[0],
            ConditionExpression::Identifier("sel1".into())
        );
        assert_eq!(
            rule.detection.conditions[1],
            ConditionExpression::Identifier("sel2".into())
        );
    }

    #[test]
    fn parse_related_entries() {
        let yaml = r#"
title: Related Test
id: aaa
related:
    - id: bbb
      type: derived
    - id: ccc
      type: obsolete
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        assert_eq!(rule.related.len(), 2);
        assert_eq!(rule.related[0].id, "bbb");
        assert_eq!(rule.related[0].relation_type, RelationType::Derived);
        assert_eq!(rule.related[1].relation_type, RelationType::Obsolete);
    }

    // ── Correlation rules ────────────────────────────────────────────────

    #[test]
    fn parse_event_count_correlation() {
        let yaml = r#"
title: Many failed logins
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: event_count
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    group-by:
        - ComputerName
    timespan: 1h
    condition:
        gte: 100
level: high
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let corr = match &coll.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        assert_eq!(corr.title, "Many failed logins");
        assert_eq!(corr.correlation.correlation_type, CorrelationType::EventCount);
        assert_eq!(corr.correlation.rules, vec!["5638f7c0-ac70-491d-8465-2a65075e0d86"]);
        assert_eq!(corr.correlation.group_by, vec!["ComputerName"]);
        assert_eq!(corr.correlation.timespan.as_deref(), Some("1h"));
        match &corr.correlation.condition {
            Some(CorrelationCondition::Simple(sc)) => {
                assert_eq!(sc.gte, Some(100));
                assert!(sc.gt.is_none());
            }
            other => panic!("Expected Simple condition, got {other:?}"),
        }
    }

    #[test]
    fn parse_value_count_correlation() {
        let yaml = r#"
title: Failed login from many users
correlation:
    type: value_count
    rules:
        - failed_login
    group-by:
        - ComputerName
        - WorkstationName
    timespan: 1d
    condition:
        field: User
        gte: 100
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let corr = match &coll.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        assert_eq!(
            corr.correlation.correlation_type,
            CorrelationType::ValueCount
        );
        match &corr.correlation.condition {
            Some(CorrelationCondition::Simple(sc)) => {
                assert_eq!(sc.field.as_deref(), Some("User"));
                assert_eq!(sc.gte, Some(100));
            }
            other => panic!("Expected Simple condition, got {other:?}"),
        }
    }

    #[test]
    fn parse_temporal_correlation() {
        let yaml = r#"
title: Recon commands
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - ComputerName
        - User
    timespan: 5m
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let corr = match &coll.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        assert_eq!(
            corr.correlation.correlation_type,
            CorrelationType::Temporal
        );
        assert_eq!(
            corr.correlation.rules,
            vec!["recon_cmd_a", "recon_cmd_b", "recon_cmd_c"]
        );
        assert!(corr.correlation.condition.is_none());
    }

    #[test]
    fn parse_temporal_with_aliases() {
        let yaml = r#"
title: Internal Error Then Connection
correlation:
    type: temporal
    rules:
        - internal_error
        - new_network_connection
    group-by:
        - internal_ip
        - remote_ip
    timespan: 10s
    aliases:
        internal_ip:
            internal_error: destination.ip
            new_network_connection: source.ip
        remote_ip:
            internal_error: source.ip
            new_network_connection: destination.ip
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let corr = match &coll.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        assert_eq!(corr.correlation.aliases.len(), 2);
        assert_eq!(
            corr.correlation.aliases["internal_ip"]["internal_error"],
            "destination.ip"
        );
        assert_eq!(
            corr.correlation.aliases["remote_ip"]["new_network_connection"],
            "destination.ip"
        );
    }

    #[test]
    fn parse_extended_correlation_condition() {
        let yaml = r#"
title: Login Without MFA
correlation:
    type: temporal
    rules:
        - successful_login
        - mfa_verification
    group-by:
        - User
        - ComputerName
    timespan: 5m
    condition: successful_login and not mfa_verification
level: medium
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let corr = match &coll.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        match &corr.correlation.condition {
            Some(CorrelationCondition::Extended(expr)) => {
                assert_eq!(
                    *expr,
                    ConditionExpression::And(
                        Box::new(ConditionExpression::Identifier("successful_login".into())),
                        Box::new(ConditionExpression::Not(Box::new(
                            ConditionExpression::Identifier("mfa_verification".into())
                        ))),
                    )
                );
            }
            other => panic!("Expected Extended condition, got {other:?}"),
        }
    }

    #[test]
    fn parse_value_sum_correlation() {
        let yaml = r#"
title: Possible Exfiltration
correlation:
    type: value_sum
    rules:
        - website_access
    group-by:
        - SourceIP
        - User
    timespan: 1h
    condition:
        field: bytes_sent
        gt: 1000000
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let corr = match &coll.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        assert_eq!(
            corr.correlation.correlation_type,
            CorrelationType::ValueSum
        );
        match &corr.correlation.condition {
            Some(CorrelationCondition::Simple(sc)) => {
                assert_eq!(sc.field.as_deref(), Some("bytes_sent"));
                assert_eq!(sc.gt, Some(1_000_000));
            }
            other => panic!("Expected Simple condition, got {other:?}"),
        }
    }

    // ── Multi-document ───────────────────────────────────────────────────

    #[test]
    fn parse_multi_document_brute_force() {
        let yaml = r#"
---
title: Correlation - Multiple Failed Logins Followed by Successful Login
id: b180ead8-d58f-40b2-ae54-c8940995b9b6
status: experimental
correlation:
    type: temporal_ordered
    rules:
        - multiple_failed_login
        - successful_login
    group-by:
        - User
    timespan: 10m
level: high
---
title: Multiple failed logons
id: a8418a5a-5fc4-46b5-b23b-6c73beb19d41
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 10
---
title: Single failed login
id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
name: failed_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 529
            - 4625
    condition: selection
---
title: Successful login
id: 4d0a2c83-c62c-4ed4-b475-c7e23a9269b8
name: successful_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 528
            - 4624
    condition: selection
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        assert_eq!(coll.documents.len(), 4);

        // 1st: temporal_ordered correlation
        match &coll.documents[0] {
            SigmaDocument::Correlation(c) => {
                assert_eq!(
                    c.correlation.correlation_type,
                    CorrelationType::TemporalOrdered
                );
                assert_eq!(
                    c.correlation.rules,
                    vec!["multiple_failed_login", "successful_login"]
                );
            }
            _ => panic!("Expected Correlation"),
        }

        // 2nd: event_count correlation
        match &coll.documents[1] {
            SigmaDocument::Correlation(c) => {
                assert_eq!(c.name.as_deref(), Some("multiple_failed_login"));
                assert_eq!(
                    c.correlation.correlation_type,
                    CorrelationType::EventCount
                );
            }
            _ => panic!("Expected Correlation"),
        }

        // 3rd: detection rule for failed login
        match &coll.documents[2] {
            SigmaDocument::Rule(r) => {
                assert_eq!(r.name.as_deref(), Some("failed_login"));
                let sel = match &r.detection.search_identifiers["selection"] {
                    SearchIdentifier::Map(items) => items,
                    _ => panic!("Expected Map"),
                };
                assert_eq!(sel[0].field.as_deref(), Some("EventID"));
                assert_eq!(
                    sel[0].values,
                    vec![SigmaValue::Int(529), SigmaValue::Int(4625)]
                );
            }
            _ => panic!("Expected Rule"),
        }

        // 4th: detection rule for successful login
        match &coll.documents[3] {
            SigmaDocument::Rule(r) => {
                assert_eq!(r.name.as_deref(), Some("successful_login"));
            }
            _ => panic!("Expected Rule"),
        }
    }

    // ── Edge cases / error handling ──────────────────────────────────────

    #[test]
    fn missing_title_errors() {
        let yaml = r#"
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("title"));
    }

    #[test]
    fn missing_detection_errors() {
        let yaml = r#"
title: No Detection
logsource:
    category: test
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("detection"));
    }

    #[test]
    fn invalid_modifier_errors() {
        let yaml = r#"
title: Bad Modifier
logsource:
    category: test
detection:
    sel:
        Field|bogus: 'val'
    condition: sel
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn invalid_status_errors() {
        let yaml = r#"
title: Bad Status
status: foobar
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("foobar"));
    }

    #[test]
    fn custom_fields_preserved() {
        let yaml = r#"
title: Custom
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
custom_field: 'hello'
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        assert!(rule.custom.contains_key("custom_field"));
    }

    #[test]
    fn condition_display_roundtrip() {
        let expr = ConditionExpression::And(
            Box::new(ConditionExpression::OneOfPattern("selection*".into())),
            Box::new(ConditionExpression::Not(Box::new(
                ConditionExpression::OneOfPattern("filter*".into()),
            ))),
        );
        assert_eq!(expr.to_string(), "(1 of selection* and not 1 of filter*)");
    }

    #[test]
    fn parse_dates_and_compare() {
        use chrono::NaiveDate;

        let yaml = r#"
title: Date Test Rule
date: 2024-01-15
modified: 2024-02-20
logsource:
    product: test
detection:
    sel:
        field: value
    condition: sel
"#;
        let collection = SigmaCollection::from_yaml(yaml).unwrap();
        assert_eq!(collection.documents.len(), 1);

        match &collection.documents[0] {
            SigmaDocument::Rule(rule) => {
                assert_eq!(rule.date, Some(NaiveDate::from_ymd_opt(2024, 1, 15).unwrap()));
                assert_eq!(rule.modified, Some(NaiveDate::from_ymd_opt(2024, 2, 20).unwrap()));
                
                // Demonstrate date comparison
                let creation = rule.date.unwrap();
                let modification = rule.modified.unwrap();
                assert!(modification > creation);
                assert!(creation < modification);
            }
            _ => panic!("Expected a detection rule"),
        }
    }

    #[test]
    fn parse_invalid_date_format() {
        let yaml = r#"
title: Invalid Date Rule
date: 2024/01/15
logsource:
    product: test
detection:
    sel:
        field: value
    condition: sel
"#;
        let result = SigmaCollection::from_yaml(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid date format"));
    }

    #[test]
    fn extended_condition_disallowed_for_non_temporal() {
        let yaml = r#"
title: Bad Extended
correlation:
    type: event_count
    condition: rule_a and rule_b
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("correlation.type") || s.contains("Extended correlation condition"));
    }

    #[test]
    fn extended_condition_allowed_without_rules_for_temporal() {
        let yaml = r#"
title: Extended No Rules
correlation:
    type: temporal
    condition: rule_a and rule_b
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let corr = match &coll.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        assert!(corr.correlation.rules.is_empty());
        match &corr.correlation.condition {
            Some(CorrelationCondition::Extended(_)) => {}
            other => panic!("Expected Extended condition, got {other:?}"),
        }
    }

    #[test]
    fn extended_condition_rules_must_match_identifiers() {
        // mismatch -> error
        let yaml = r#"
title: Mismatch Extended Rules
correlation:
    type: temporal
    rules:
        - a
        - b
    condition: a and c
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("Mismatch between"));

        // matching -> ok
        let yaml2 = r#"
title: Matching Extended Rules
correlation:
    type: temporal
    rules:
        - a
        - b
    condition: a and b
"#;
        let coll = SigmaCollection::from_yaml(yaml2).unwrap();
        let corr = match &coll.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        assert_eq!(corr.correlation.rules, vec!["a", "b"]);
        match &corr.correlation.condition {
            Some(CorrelationCondition::Extended(_)) => {}
            other => panic!("Expected Extended condition, got {other:?}"),
        }
    }

    // ── Sigma Filter rules ──────────────────────────────────────────────

    #[test]
    fn parse_basic_filter() {
        let yaml = r#"
title: Filter Administrator account
description: The valid administrator account start with adm_
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 6f3e2987-db24-4c78-a860-b4f4095a7095
        - df0841c0-9846-4e9f-ad8a-7df91571771b
    selection:
        User|startswith: 'adm_'
    condition: selection
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        assert_eq!(coll.documents.len(), 1);
        let filter = match &coll.documents[0] {
            SigmaDocument::Filter(f) => f,
            other => panic!("Expected Filter, got {other:?}"),
        };
        assert_eq!(filter.title, "Filter Administrator account");
        assert_eq!(
            filter.description.as_deref(),
            Some("The valid administrator account start with adm_")
        );
        assert_eq!(filter.logsource.category.as_deref(), Some("process_creation"));
        assert_eq!(filter.logsource.product.as_deref(), Some("windows"));

        // Filter section
        assert_eq!(filter.filter.rules, vec![
            "6f3e2987-db24-4c78-a860-b4f4095a7095",
            "df0841c0-9846-4e9f-ad8a-7df91571771b",
        ]);
        assert_eq!(filter.filter.search_identifiers.len(), 1);
        assert!(filter.filter.search_identifiers.contains_key("selection"));
        assert_eq!(filter.filter.conditions.len(), 1);
        assert_eq!(
            filter.filter.conditions[0],
            ConditionExpression::Identifier("selection".into())
        );
    }

    #[test]
    fn parse_filter_with_id_and_dates() {
        let yaml = r#"
title: Filter with metadata
id: aaaa-bbbb-cccc
date: 2024-08-08
modified: 2025-01-01
taxonomy: sigma
logsource:
    product: windows
filter:
    rules:
        - some-rule-id
    selection:
        User: admin
    condition: selection
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let filter = match &coll.documents[0] {
            SigmaDocument::Filter(f) => f,
            other => panic!("Expected Filter, got {other:?}"),
        };
        assert_eq!(filter.id.as_deref(), Some("aaaa-bbbb-cccc"));
        assert_eq!(filter.taxonomy.as_deref(), Some("sigma"));
        assert!(filter.date.is_some());
        assert!(filter.modified.is_some());
    }

    #[test]
    fn apply_filter_to_matching_rule() {
        // Parse a detection rule
        let rule_yaml = r#"
title: Data Compressed - rar.exe
id: 6f3e2987-db24-4c78-a860-b4f4095a7095
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rar.exe'
    condition: selection
level: high
"#;
        let mut coll = SigmaCollection::from_yaml(rule_yaml).unwrap();
        let rule = match &mut coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };

        // Parse a filter
        let filter_yaml = r#"
title: Filter Administrator account
id: f1f1f1f1-0000-0000-0000-000000000001
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 6f3e2987-db24-4c78-a860-b4f4095a7095
    selection:
        User|startswith: 'adm_'
    condition: selection
"#;
        let filter_coll = SigmaCollection::from_yaml(filter_yaml).unwrap();
        let filter = match &filter_coll.documents[0] {
            SigmaDocument::Filter(f) => f,
            _ => panic!("Expected Filter"),
        };

        // Apply the filter
        let applied = filter.apply(rule);
        assert!(applied);

        // Rule should now have the filter's search identifier merged
        let prefix = "_filter_f1f1f1f1_0000_0000_0000_000000000001_";
        let prefixed_key = format!("{}selection", prefix);
        assert!(
            rule.detection.search_identifiers.contains_key(&prefixed_key),
            "Expected filter search identifier '{prefixed_key}' in rule detection"
        );

        // Rule's condition should be extended: original AND NOT filter
        assert_eq!(rule.detection.conditions.len(), 1);
        match &rule.detection.conditions[0] {
            ConditionExpression::And(left, right) => {
                // Left should be original condition
                assert_eq!(
                    **left,
                    ConditionExpression::Identifier("selection".into())
                );
                // Right should be NOT(filter_condition)
                match right.as_ref() {
                    ConditionExpression::Not(inner) => {
                        assert_eq!(
                            **inner,
                            ConditionExpression::Identifier(prefixed_key)
                        );
                    }
                    other => panic!("Expected Not, got {other:?}"),
                }
            }
            other => panic!("Expected And, got {other:?}"),
        }
    }

    #[test]
    fn filter_not_applied_to_non_matching_rule_id() {
        let rule_yaml = r#"
title: Some Rule
id: different-id-than-filter-expects
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: test.exe
    condition: selection
"#;
        let mut coll = SigmaCollection::from_yaml(rule_yaml).unwrap();
        let rule = match &mut coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };

        let filter_yaml = r#"
title: Filter
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 6f3e2987-db24-4c78-a860-b4f4095a7095
    selection:
        User: admin
    condition: selection
"#;
        let filter_coll = SigmaCollection::from_yaml(filter_yaml).unwrap();
        let filter = match &filter_coll.documents[0] {
            SigmaDocument::Filter(f) => f,
            _ => panic!("Expected Filter"),
        };

        let original_conditions = rule.detection.conditions.clone();
        let applied = filter.apply(rule);
        assert!(!applied);
        assert_eq!(rule.detection.conditions, original_conditions);
    }

    #[test]
    fn filter_not_applied_to_non_matching_logsource() {
        let rule_yaml = r#"
title: Some Rule
id: 6f3e2987-db24-4c78-a860-b4f4095a7095
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        DestPort: 443
    condition: selection
"#;
        let mut coll = SigmaCollection::from_yaml(rule_yaml).unwrap();
        let rule = match &mut coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };

        let filter_yaml = r#"
title: Filter
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 6f3e2987-db24-4c78-a860-b4f4095a7095
    selection:
        User: admin
    condition: selection
"#;
        let filter_coll = SigmaCollection::from_yaml(filter_yaml).unwrap();
        let filter = match &filter_coll.documents[0] {
            SigmaDocument::Filter(f) => f,
            _ => panic!("Expected Filter"),
        };

        let applied = filter.apply(rule);
        assert!(!applied);
    }

    #[test]
    fn filter_not_applied_to_rule_without_id() {
        let rule_yaml = r#"
title: Rule Without ID
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: test.exe
    condition: selection
"#;
        let mut coll = SigmaCollection::from_yaml(rule_yaml).unwrap();
        let rule = match &mut coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };

        let filter_yaml = r#"
title: Filter
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - some-rule-id
    selection:
        User: admin
    condition: selection
"#;
        let filter_coll = SigmaCollection::from_yaml(filter_yaml).unwrap();
        let filter = match &filter_coll.documents[0] {
            SigmaDocument::Filter(f) => f,
            _ => panic!("Expected Filter"),
        };

        let applied = filter.apply(rule);
        assert!(!applied);
    }

    #[test]
    fn filter_with_complex_condition() {
        let rule_yaml = r#"
title: Test Rule
id: target-rule-id
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
"#;
        let mut coll = SigmaCollection::from_yaml(rule_yaml).unwrap();
        let rule = match &mut coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };

        let filter_yaml = r#"
title: Complex Filter
id: complex-filter
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - target-rule-id
    sel1:
        User: admin
    sel2:
        ParentImage|endswith: '\explorer.exe'
    condition: sel1 and sel2
"#;
        let filter_coll = SigmaCollection::from_yaml(filter_yaml).unwrap();
        let filter = match &filter_coll.documents[0] {
            SigmaDocument::Filter(f) => f,
            _ => panic!("Expected Filter"),
        };

        let applied = filter.apply(rule);
        assert!(applied);

        // Verify both search identifiers were merged
        let prefix = "_filter_complex_filter_";
        assert!(rule.detection.search_identifiers.contains_key(&format!("{}sel1", prefix)));
        assert!(rule.detection.search_identifiers.contains_key(&format!("{}sel2", prefix)));

        // Condition should be: selection AND NOT (prefixed_sel1 AND prefixed_sel2)
        assert_eq!(rule.detection.conditions.len(), 1);
    }

    #[test]
    fn filter_applied_to_multiple_rules_in_collection() {
        let yaml = r#"
---
title: Rule A
id: rule-a-id
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: a.exe
    condition: selection
---
title: Rule B
id: rule-b-id
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: b.exe
    condition: selection
---
title: Filter Both
id: filter-both
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - rule-a-id
        - rule-b-id
    selection:
        User: admin
    condition: selection
"#;
        let mut coll = SigmaCollection::from_yaml(yaml).unwrap();
        assert_eq!(coll.documents.len(), 3);

        // Extract filter
        let filter = match &coll.documents[2] {
            SigmaDocument::Filter(f) => f.clone(),
            other => panic!("Expected Filter, got {other:?}"),
        };

        // Apply to all rules
        let mut applied_count = 0;
        for doc in &mut coll.documents {
            if let SigmaDocument::Rule(rule) = doc {
                if filter.apply(rule) {
                    applied_count += 1;
                }
            }
        }
        assert_eq!(applied_count, 2);
    }

    #[test]
    fn filter_missing_rules_errors() {
        let yaml = r#"
title: Bad Filter
logsource:
    category: test
filter:
    selection:
        X: 1
    condition: selection
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("filter.rules"));
    }

    #[test]
    fn filter_missing_condition_errors() {
        let yaml = r#"
title: Bad Filter
logsource:
    category: test
filter:
    rules:
        - some-id
    selection:
        X: 1
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("filter.condition"));
    }

    #[test]
    fn filter_missing_logsource_errors() {
        let yaml = r#"
title: Bad Filter
filter:
    rules:
        - some-id
    selection:
        X: 1
    condition: selection
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("logsource"));
    }
}

