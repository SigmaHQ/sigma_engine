# Sigma Engine

A performant Rust library for parsing [Sigma](https://sigmahq.io) detection and correlation rules from YAML and matching them against log events in a multithreaded environment.

## Features

- **Rule Parsing**: Parse Sigma rules from YAML into structured Rust types
- **Rule Matching**: Compile Sigma rules into efficient matchers that can match events
- **Full Modifier Support**: Complete support for Sigma modifiers including:
  - String modifiers: `contains`, `startswith`, `endswith`, `re` (regex)
  - Case modifiers: `cased`
  - Encoding modifiers: `base64`, `base64offset`, `utf16le`, `utf16be`, `utf16`, `wide`
  - Logic modifiers: `all`, `exists`, `neq`
  - Numeric modifiers: `lt`, `lte`, `gt`, `gte`
  - Dash expansion: `windash` (for Windows command-line flags)
- **Multithreaded Processing**: Process log events using multiple threads with message passing
- **Log Source Matching**: Automatic dispatching of events to matching rules based on log source
- **Multiple Input Formats**: Support for JSON, plain text, and Field="Value" formats
- **Thread-Safe**: All matchers are thread-safe and use `Arc` for efficient sharing

## Supported Specifications

- **Sigma Rules** v2.1.0 — detection rules with logsource, detection section (maps, lists, keyword searches, value modifiers) and boolean condition expressions
- **Sigma Correlation Rules** v2.1.0 — `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile` with field aliases
- **Extended Correlation Conditions** (SEP #198) — boolean condition expressions in `temporal` / `temporal_ordered` correlations referencing rule names

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
sigma_engine = "0.1.0"
```

## Quick Start

### Parsing a Sigma Rule

```rust
use sigma_engine::{SigmaCollection, SigmaDocument};

let yaml = r#"
title: Whoami Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'C:\Windows\System32\whoami.exe'
    condition: selection
level: high
"#;

let collection = SigmaCollection::from_yaml(yaml).unwrap();
match &collection.documents[0] {
    SigmaDocument::Rule(rule) => println!("Parsed rule: {}", rule.title),
    _ => panic!("Expected a detection rule"),
}
```

### Matching Events Against Rules

```rust
use sigma_engine::{SigmaCollection, SigmaDocument, SigmaRuleMatcher};
use std::collections::HashMap;

let yaml = r#"
title: Suspicious Command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
        CommandLine|contains: 'whoami'
    condition: selection
"#;

let collection = SigmaCollection::from_yaml(yaml).unwrap();
let rule = match &collection.documents[0] {
    SigmaDocument::Rule(r) => r.clone(),
    _ => panic!("Expected rule"),
};

let matcher = SigmaRuleMatcher::new(rule).unwrap();

let mut event = HashMap::new();
event.insert("Image".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());
event.insert("CommandLine".to_string(), "cmd.exe /c whoami".to_string());

if matcher.matches(&event) {
    println!("Event matched the rule!");
}
```

### Processing Events with Multithreading

```rust
use sigma_engine::{LogProcessor, LogEvent, LogSource};
use std::collections::HashMap;

// Parse rules and create processor
let processor = LogProcessor::new(rules).unwrap();

// Start processing (returns channels for input/output)
let (event_tx, detection_rx) = processor.start();

// Create and send events
let log_source = LogSource {
    category: Some("process_creation".to_string()),
    product: Some("windows".to_string()),
    service: None,
};

// Send JSON event
let json = r#"{"EventID": 4688, "Image": "cmd.exe"}"#;
let event = LogEvent::from_json(log_source, json).unwrap();
event_tx.send(event).unwrap();

// Drop sender to signal completion
drop(event_tx);

// Receive detections
while let Ok(detection) = detection_rx.recv() {
    println!("Rule matched: {}", detection.rule.title);
}
```

## Input Formats

The LogProcessor supports three input formats:

### 1. JSON Format
```rust
let json = r#"{"EventID": 4688, "Image": "C:\\Windows\\cmd.exe"}"#;
let event = LogEvent::from_json(log_source, json)?;
```

### 2. Plain Text Format
```rust
let text = "This is a plain log message".to_string();
let event = LogEvent::from_plain(log_source, text);
```

### 3. Field="Value" Format
```rust
let text = r#"EventID="4688" User="SYSTEM" CommandLine="cmd.exe""#;
let event = LogEvent::from_field_value_format(log_source, text);
```

## Threading Model

By default, the LogProcessor uses `(CPU count - 1)` worker threads to process events. Each worker:
- Receives events from a shared channel
- Checks which rules match based on log source
- Evaluates matching rules against the event
- Sends detections to the output channel

This design allows for efficient parallel processing of high-volume log streams.

## Performance

- **Regex Caching**: Compiled regex patterns are cached for efficient reuse
- **Thread-Safe Design**: Matchers use `Arc` for zero-cost sharing across threads
- **Efficient Matching**: Compiled matchers avoid re-parsing rules for each event
- **Message Passing**: Lock-free channels for high-throughput event processing

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
