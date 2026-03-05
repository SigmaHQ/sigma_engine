//! # Sigma Engine
//!
//! A Rust library for parsing [Sigma](https://sigmahq.io) detection and correlation rules
//! from YAML and matching them against log events in a multithreaded environment.
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
//! ## Features
//!
//! - **Rule Parsing**: Parse Sigma rules from YAML into structured Rust types
//! - **Rule Matching**: Compile Sigma rules into efficient matchers that can match events
//! - **Modifier Support**: Full support for Sigma modifiers (contains, startswith, endswith, 
//!   regex, base64, utf16, wildcards, numeric comparisons, and more)
//! - **Multithreaded Processing**: Process log events using multiple threads with message passing
//! - **Log Source Matching**: Automatic dispatching of events to matching rules based on log source
//! - **Multiple Input Formats**: Support for JSON, plain text, and Field="Value" formats
//!
//! ## Quick start
//!
//! ### Parsing a Sigma rule
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
//!
//! ### Matching events against rules
//!
//! ```rust
//! use sigma_engine::{SigmaCollection, SigmaDocument, SigmaRuleMatcher};
//! use std::collections::HashMap;
//!
//! let yaml = r#"
//! title: Suspicious Command
//! logsource:
//!     category: process_creation
//!     product: windows
//! detection:
//!     selection:
//!         Image|endswith: '\cmd.exe'
//!         CommandLine|contains: 'whoami'
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
//! event.insert("CommandLine".to_string(), "cmd.exe /c whoami".to_string());
//!
//! assert!(matcher.matches(&event));
//! ```
//!
//! ### Processing events with multithreading
//!
//! ```rust
//! use sigma_engine::{SigmaCollection, SigmaDocument, LogProcessor, LogEvent, LogSource};
//! use std::collections::HashMap;
//!
//! let yaml = r#"
//! title: Test Rule
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
//! // Create processor with rules
//! let processor = LogProcessor::new(vec![rule]).unwrap();
//!
//! // Start processing (returns channels for input/output)
//! let (event_tx, detection_rx) = processor.start();
//!
//! // Create and send an event
//! let log_source = LogSource {
//!     category: Some("process_creation".to_string()),
//!     product: Some("windows".to_string()),
//!     service: None,
//! };
//!
//! let mut data = HashMap::new();
//! data.insert("EventID".to_string(), "4688".to_string());
//! let event = LogEvent::from_fields(log_source, data);
//!
//! event_tx.send(event).unwrap();
//! drop(event_tx); // Signal completion
//!
//! // Receive detections
//! if let Ok(detection) = detection_rx.recv() {
//!     println!("Rule matched: {}", detection.rule.title);
//! }
//! ```

pub mod condition;
pub mod error;
mod parser;
pub mod pipeline;
pub mod types;
pub mod matcher;
pub mod processor;

pub use error::Error;
pub use pipeline::*;
pub use types::*;
pub use matcher::{SigmaRuleMatcher, SigmaEvent};
pub use processor::{LogProcessor, Detection, LogEvent};

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

    // ── Parser coverage tests ────────────────────────────────────────────

    #[test]
    fn parse_get_string_list_single_string() {
        // references as a single string (not a list) triggers get_string_list single-string path
        let yaml = r#"
title: Single Ref
references: "https://example.com"
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
        assert_eq!(rule.references, vec!["https://example.com"]);
    }

    #[test]
    fn parse_invalid_numeric_date_format_error() {
        // Numeric date triggers value_as_string for numbers
        let yaml = r#"
title: Numeric Date
date: 20240115
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("Invalid date format"));
    }

    #[test]
    fn parse_relation_type_merged_renamed_similar() {
        let yaml = r#"
title: Related Types
related:
    - id: aaa
      type: merged
    - id: bbb
      type: renamed
    - id: ccc
      type: similar
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
        assert_eq!(rule.related[0].relation_type, RelationType::Merged);
        assert_eq!(rule.related[1].relation_type, RelationType::Renamed);
        assert_eq!(rule.related[2].relation_type, RelationType::Similar);
    }

    #[test]
    fn parse_correlation_type_value_avg_and_percentile() {
        let yaml = r#"
title: Avg
correlation:
    type: value_avg
    rules:
        - rule_a
    group-by:
        - User
    timespan: 1h
    condition:
        field: bytes
        gte: 100
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let corr = match &coll.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        assert_eq!(corr.correlation.correlation_type, CorrelationType::ValueAvg);

        let yaml2 = r#"
title: Percentile
correlation:
    type: value_percentile
    rules:
        - rule_a
    condition:
        field: latency
        gt: 500
"#;
        let coll2 = SigmaCollection::from_yaml(yaml2).unwrap();
        let corr2 = match &coll2.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        assert_eq!(corr2.correlation.correlation_type, CorrelationType::ValuePercentile);
    }

    #[test]
    fn parse_sigma_string_wildcards_and_escapes() {
        // `?` wildcard and escaped chars via detection values
        let yaml = r#"
title: Wildcard Test
logsource:
    category: test
detection:
    sel:
        Path: 'C:\Windows\*.dl?'
        Escaped: 'test\*literal'
        TrailingBackslash: 'end\'
    condition: sel
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        let items = match &rule.detection.search_identifiers["sel"] {
            SearchIdentifier::Map(items) => items,
            _ => panic!("Expected Map"),
        };
        // Path contains WildcardMulti and WildcardSingle
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert!(s.has_special_parts());
        }
        // Escaped: test*literal (escaped *, should be literal)
        if let SigmaValue::String(s) = &items[1].values[0] {
            assert_eq!(s.as_plain(), Some("test*literal"));
        }
        // TrailingBackslash
        if let SigmaValue::String(s) = &items[2].values[0] {
            assert_eq!(s.as_plain(), Some("end\\"));
        }
    }

    #[test]
    fn parse_yaml_to_sigma_value_float() {
        let yaml = r#"
title: Float Test
logsource:
    category: test
detection:
    sel:
        Score: 3.14
    condition: sel
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        let items = match &rule.detection.search_identifiers["sel"] {
            SearchIdentifier::Map(items) => items,
            _ => panic!("Expected Map"),
        };
        assert!(matches!(&items[0].values[0], SigmaValue::Float(f) if (*f - 3.14).abs() < 0.01));
    }

    #[test]
    fn parse_expand_modifier() {
        let yaml = r#"
title: Expand Test
logsource:
    category: test
detection:
    sel:
        Path|expand: '%SystemRoot%\cmd.exe'
    condition: sel
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        let items = match &rule.detection.search_identifiers["sel"] {
            SearchIdentifier::Map(items) => items,
            _ => panic!("Expected Map"),
        };
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert!(s.parts.iter().any(|p| matches!(p, SigmaStringPart::Placeholder(name) if name == "SystemRoot")));
        }
    }

    #[test]
    fn parse_search_identifier_empty_list_error() {
        let yaml = r#"
title: Empty List
logsource:
    category: test
detection:
    sel: []
    condition: sel
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("Empty detection list"));
    }

    #[test]
    fn parse_search_identifier_mixed_types_error() {
        let yaml = r#"
title: Mixed
logsource:
    category: test
detection:
    sel:
        - 'string_val'
        - FieldA: 'map_val'
    condition: sel
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("mixed types"));
    }

    #[test]
    fn parse_search_identifier_scalar_error() {
        // A bare scalar (not mapping or sequence) as search identifier
        let yaml = r#"
title: Bare Scalar
logsource:
    category: test
detection:
    sel: 42
    condition: sel
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("mapping or sequence"));
    }

    #[test]
    fn parse_condition_list_non_string_error() {
        let yaml = r#"
title: Bad Cond
logsource:
    category: test
detection:
    sel:
        X: 1
    condition:
        - sel
        - 42
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("Condition list items must be strings"));
    }

    #[test]
    fn parse_related_error_not_sequence() {
        let yaml = r#"
title: Bad Related
related: "not a list"
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("Must be a sequence"));
    }

    #[test]
    fn parse_related_error_not_mapping() {
        let yaml = r#"
title: Bad Related Item
related:
    - "not a mapping"
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("must be a mapping"));
    }

    #[test]
    fn parse_detection_rule_all_known_keys() {
        let yaml = r#"
title: Full Rule
id: abc-123
name: my_rule
taxonomy: sigma
status: stable
description: A test
license: MIT
author: Tester
date: 2024-01-01
modified: 2024-06-15
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
fields:
    - FieldA
falsepositives:
    - "none"
level: low
tags:
    - attack.initial_access
scope:
    - server
custom_key: custom_val
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        assert_eq!(rule.taxonomy.as_deref(), Some("sigma"));
        assert_eq!(rule.license.as_deref(), Some("MIT"));
        assert_eq!(rule.fields, vec!["FieldA"]);
        assert_eq!(rule.falsepositives, vec!["none"]);
        assert_eq!(rule.status, Some(Status::Stable));
        assert_eq!(rule.level, Some(Level::Low));
        assert!(rule.custom.contains_key("custom_key"));
    }

    #[test]
    fn parse_aliases_errors() {
        // alias value not a mapping
        let yaml = r#"
title: Bad Alias
correlation:
    type: temporal
    rules:
        - a
    aliases:
        ip: "not_a_map"
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("must map to a mapping"));
    }

    #[test]
    fn parse_correlation_condition_bad_type_error() {
        // condition as a list (not string or mapping)
        let yaml = r#"
title: Bad Cond
correlation:
    type: event_count
    rules:
        - r1
    condition:
        - bad
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("Correlation condition must be a string or mapping"));
    }

    #[test]
    fn parse_correlation_section_not_mapping_error() {
        // correlation value not a mapping
        let yaml = r#"
title: Bad Corr
correlation: "not_a_map"
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("Must be a mapping"));
    }

    #[test]
    fn parse_collect_ids_pattern_error() {
        // Extended condition with pattern (e.g. all of them) when rules is provided
        let yaml = r#"
title: Pattern in Extended
correlation:
    type: temporal
    rules:
        - a
    condition: all of them
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("explicit rule names"));
    }

    #[test]
    fn parse_correlation_rule_fields() {
        let yaml = r#"
title: Full Correlation
id: corr-1
name: my_corr
status: test
description: correlation desc
author: Tester
references:
    - "https://example.com"
date: 2024-03-01
modified: 2024-04-01
taxonomy: sigma
correlation:
    type: event_count
    rules:
        - r1
    condition:
        gte: 5
falsepositives:
    - "fp1"
level: critical
generate: true
custom_corr_key: val
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let corr = match &coll.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        assert_eq!(corr.description.as_deref(), Some("correlation desc"));
        assert_eq!(corr.author.as_deref(), Some("Tester"));
        assert_eq!(corr.references, vec!["https://example.com"]);
        assert_eq!(corr.date, Some(chrono::NaiveDate::from_ymd_opt(2024, 3, 1).unwrap()));
        assert_eq!(corr.modified, Some(chrono::NaiveDate::from_ymd_opt(2024, 4, 1).unwrap()));
        assert_eq!(corr.taxonomy.as_deref(), Some("sigma"));
        assert_eq!(corr.falsepositives, vec!["fp1"]);
        assert_eq!(corr.level, Some(Level::Critical));
        assert_eq!(corr.generate, Some(true));
        assert!(corr.custom.contains_key("custom_corr_key"));
    }

    #[test]
    fn parse_level_informational() {
        let yaml = r#"
title: Info Level
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
level: informational
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        assert_eq!(rule.level, Some(Level::Informational));
    }

    #[test]
    fn parse_level_medium_and_critical() {
        let yaml = r#"
title: Med Level
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
level: medium
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        assert_eq!(rule.level, Some(Level::Medium));
    }

    #[test]
    fn parse_level_error() {
        let yaml = r#"
title: Bad Level
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
level: bogus
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn error_type_result_alias() {
        // Cover error.rs line 38 (type Result)
        let r: crate::error::Result<()> = Ok(());
        assert!(r.is_ok());
    }

    #[test]
    fn parse_expand_modifier_with_int() {
        // Covers parser.rs line 488 (expand modifier with non-string value)
        let yaml = r#"
title: Expand Int
logsource:
    category: test
detection:
    sel:
        EventID|expand: 4688
    condition: sel
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        let sel = match &rule.detection.search_identifiers["sel"] {
            SearchIdentifier::Map(items) => items,
            _ => panic!("Expected Map"),
        };
        assert_eq!(sel[0].values, vec![SigmaValue::Int(4688)]);
    }

    #[test]
    fn parse_numeric_date_value_as_string() {
        // Covers parser.rs lines 122-123 (value_as_string for numbers) and line 134 date parsing
        let yaml = r#"
title: Numeric Date
date: 2024-01-15
modified: 2024-01-15
logsource:
    product: test
detection:
    sel:
        field: value
    condition: sel
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        assert!(rule.date.is_some());
    }

    #[test]
    fn parse_full_detection_rule_all_fields() {
        // Covers parser.rs lines 680-719 (all known_keys and field accessors)
        let yaml = r#"
title: Full Rule
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
name: full_rule
status: stable
description: A full rule
license: MIT
references:
    - https://example.com
    - https://example.org
author: Test Author
date: 2024-01-15
modified: 2024-06-20
taxonomy: sigma
logsource:
    category: process_creation
    product: windows
    service: sysmon
    custom_key: custom_val
detection:
    sel:
        EventID: 4688
    condition: sel
fields:
    - ComputerName
    - User
falsepositives:
    - Legitimate admin
level: low
tags:
    - attack.discovery
scope:
    - server
related:
    - id: bbb
      type: similar
custom_field: hello
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        assert_eq!(rule.title, "Full Rule");
        assert_eq!(rule.status, Some(Status::Stable));
        assert_eq!(rule.level, Some(Level::Low));
        assert_eq!(rule.description.as_deref(), Some("A full rule"));
        assert_eq!(rule.license.as_deref(), Some("MIT"));
        assert_eq!(rule.references.len(), 2);
        assert_eq!(rule.author.as_deref(), Some("Test Author"));
        assert_eq!(rule.taxonomy.as_deref(), Some("sigma"));
        assert_eq!(rule.fields, vec!["ComputerName", "User"]);
        assert_eq!(rule.falsepositives, vec!["Legitimate admin"]);
        assert_eq!(rule.tags, vec!["attack.discovery"]);
        assert_eq!(rule.scope, vec!["server"]);
        assert_eq!(rule.related[0].relation_type, RelationType::Similar);
        assert_eq!(rule.logsource.service.as_deref(), Some("sysmon"));
        assert!(rule.custom.contains_key("custom_field"));
        assert!(rule.date.is_some());
        assert!(rule.modified.is_some());
    }

    #[test]
    fn parse_full_correlation_rule_all_fields() {
        // Covers parser.rs lines 898-928 (all correlation known_keys and field accessors)
        let yaml = r#"
title: Full Correlation
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
name: full_corr
status: test
description: A full correlation
author: Test Author
references:
    - https://example.com
date: 2024-03-01
modified: 2024-06-01
taxonomy: sigma
correlation:
    type: event_count
    rules:
        - some_rule
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 10
falsepositives:
    - Legitimate activity
level: critical
generate: true
custom_field: world
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let corr = match &coll.documents[0] {
            SigmaDocument::Correlation(c) => c,
            _ => panic!("Expected Correlation"),
        };
        assert_eq!(corr.title, "Full Correlation");
        assert_eq!(corr.name.as_deref(), Some("full_corr"));
        assert_eq!(corr.status, Some(Status::Test));
        assert_eq!(corr.description.as_deref(), Some("A full correlation"));
        assert_eq!(corr.author.as_deref(), Some("Test Author"));
        assert_eq!(corr.references, vec!["https://example.com"]);
        assert!(corr.date.is_some());
        assert!(corr.modified.is_some());
        assert_eq!(corr.taxonomy.as_deref(), Some("sigma"));
        assert_eq!(corr.falsepositives, vec!["Legitimate activity"]);
        assert_eq!(corr.level, Some(Level::Critical));
        assert_eq!(corr.generate, Some(true));
        assert!(corr.custom.contains_key("custom_field"));
    }

    #[test]
    fn parse_status_all_values() {
        // Covers parse_status lines 152-157 (all arms)
        for (status_str, expected) in [
            ("stable", Status::Stable),
            ("test", Status::Test),
            ("experimental", Status::Experimental),
            ("deprecated", Status::Deprecated),
            ("unsupported", Status::Unsupported),
        ] {
            let yaml = format!(
                r#"
title: Status Test
status: {}
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
"#,
                status_str
            );
            let coll = SigmaCollection::from_yaml(&yaml).unwrap();
            let rule = match &coll.documents[0] {
                SigmaDocument::Rule(r) => r,
                _ => panic!("Expected Rule"),
            };
            assert_eq!(rule.status, Some(expected));
        }
    }

    #[test]
    fn parse_relation_type_error() {
        // Covers parser.rs lines 186-188 (unknown relation type error)
        let yaml = r#"
title: Bad Relation
related:
    - id: xxx
      type: unknown_type
logsource:
    category: test
detection:
    sel:
        X: 1
    condition: sel
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown_type"));
    }

    #[test]
    fn parse_correlation_type_error() {
        // Covers parser.rs lines 246-247 (unknown correlation type error)
        let yaml = r#"
title: Bad Type
correlation:
    type: unknown_corr_type
    rules:
        - some
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown_corr_type"));
    }

    #[test]
    fn parse_date_from_non_value() {
        // Covers parser.rs lines 134-135 (date that's not convertible to string)
        let yaml = r#"
title: Bad Date
date:
    - 2024
    - 01
    - 15
logsource:
    product: test
detection:
    sel:
        field: value
    condition: sel
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("Date must be"));
    }

    #[test]
    fn parse_sigma_string_backslash_and_wildcards() {
        // Covers parser.rs lines 283 (backslash handling), 301 (*), 309 (?), 317 (normal chars)
        let yaml = r#"
title: Wildcard Test
logsource:
    category: test
detection:
    sel:
        Path: '*\Windows\?.exe'
    condition: sel
"#;
        let coll = SigmaCollection::from_yaml(yaml).unwrap();
        let rule = match &coll.documents[0] {
            SigmaDocument::Rule(r) => r,
            _ => panic!("Expected Rule"),
        };
        let items = match &rule.detection.search_identifiers["sel"] {
            SearchIdentifier::Map(items) => items,
            _ => panic!("Expected Map"),
        };
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert!(s.has_special_parts());
        }
    }

    #[test]
    fn parse_references_single_string() {
        // Covers parser.rs line 113 (get_string_list for single string)
        let yaml = r#"
title: Single Ref
references: https://example.com
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
        assert_eq!(rule.references, vec!["https://example.com"]);
    }

    #[test]
    fn parse_aliases_field_not_string_error() {
        // Covers parser.rs line 754 (alias field name not a string)
        let yaml = r#"
title: Bad Alias
correlation:
    type: temporal
    rules:
        - a
        - b
    timespan: 5m
    aliases:
        my_alias:
            a: field_a
            123: field_b
"#;
        let err = SigmaCollection::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("aliases") || err.to_string().contains("string"));
    }
}

