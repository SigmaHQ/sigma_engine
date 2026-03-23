# Copilot Instructions for Sigma Engine

## Project Overview

This is a Rust library for parsing and matching [Sigma](https://sigmahq.io) detection and correlation rules. It implements the Sigma specification v2.1.0 for security event detection and correlation.

**Important**: This is a library crate only. It should not contain executable programs (binaries). Examples belong in documentation, not as separate executable files.

## Code Quality Standards

### Test Coverage (Critical)

- **All features MUST be covered by tests**
- **Test coverage MUST NOT drop below 95%**
- Every new function, method, or feature requires corresponding tests
- Tests should cover:
  - Happy path cases
  - Error cases and edge cases
  - Boundary conditions
  - Different input formats and variations
- Use property-based testing where appropriate
- Integration tests should be in the `tests/` directory
- Unit tests should be in the same file as the code they test (using `#[cfg(test)]` modules)

### Documentation Requirements (Critical)

- **All public APIs MUST be documented with rustdoc comments**
- **Every documented feature MUST include a usage example**
- Documentation standards:
  - Module-level documentation (`//!`) explaining the module's purpose
  - Struct/enum documentation with field descriptions
  - Function/method documentation with:
    - Purpose description
    - Parameter descriptions
    - Return value description
    - Error conditions (if applicable)
    - At least one `# Examples` section with working code
    - `# Panics` section if the function can panic
    - `# Errors` section for fallible functions
  - Use `# Safety` for unsafe code
- Examples in documentation must compile and run (`cargo test --doc`)
- Keep examples concise but complete enough to be useful

### Code Organization

- **Library only**: No binary targets in `Cargo.toml`
- **No src/main.rs**: This is not an application
- **Examples in docs**: Usage examples belong in rustdoc comments, not separate files
- **Clean separation**:
  - Core types in `types.rs`
  - Parsing logic in `parser.rs`
  - Matching logic in `matcher.rs`
  - Error types in `error.rs`
  - Public API exposed through `lib.rs`
- Keep the public API surface minimal - only expose what's necessary
- Use `pub(crate)` for internal visibility

## Rust Best Practices

### Code Style

- Follow standard Rust formatting (`cargo fmt`)
- Run Clippy and fix all warnings (`cargo clippy -- -D warnings`)
- Use idiomatic Rust patterns:
  - Prefer `Result<T, E>` over panicking
  - Use `Option<T>` for optional values
  - Leverage the type system for correctness
  - Use iterators instead of manual loops where appropriate
  - Prefer immutability unless mutability is required

### Error Handling

- Use `thiserror` for error types (already in dependencies)
- Provide descriptive error messages
- Errors should be actionable - tell users what went wrong and how to fix it
- Don't use `unwrap()` or `expect()` in library code (only in tests/docs)
- Propagate errors with `?` operator

### Performance

- This is a performance-critical library for security event matching
- Use `Arc` for shared thread-safe data
- Minimize allocations where possible
- Use efficient data structures (e.g., `HashMap`, `BTreeMap` as appropriate)
- Profile before optimizing, but be mindful of obvious inefficiencies

### Thread Safety

- All public matchers must be thread-safe
- Use appropriate synchronization primitives
- Document thread-safety guarantees

## Sigma-Specific Guidelines

### Rule Parsing

- Support Sigma specification v2.1.0 completely
- Handle all defined modifiers correctly
- Validate rules during parsing and provide clear error messages
- Support both detection rules and correlation rules

### Rule Matching

- Matching must be accurate - false negatives are serious security issues
- Optimize for common cases but handle edge cases correctly
- Support multiple input formats (JSON, plain text, Field="Value")
- Log source matching should properly dispatch events to applicable rules

### Testing Sigma Rules

- Include tests with real-world Sigma rule examples
- Test edge cases in rule syntax
- Verify modifier behavior matches specification
- Test correlation rule timing and grouping logic

## Version Control

- Write clear, descriptive commit messages
- Keep commits focused and atomic
- Reference issue numbers when applicable

## Dependencies

- Minimize external dependencies
- Keep dependency versions up to date
- Document why each dependency is needed
- Use `default-features = false` where appropriate to reduce bloat

## Before Submitting Code

Checklist for any code changes:
- [ ] All new code has tests (coverage ≥ 95%)
- [ ] All public APIs are documented with examples
- [ ] `cargo test` passes
- [ ] `cargo test --doc` passes (doc examples work)
- [ ] `cargo fmt` applied
- [ ] `cargo clippy -- -D warnings` passes
- [ ] No new binary targets added
- [ ] No executables in the codebase (except test binaries)
- [ ] Documentation is clear and includes working examples

## Project Philosophy

- **Correctness first**: Security tooling must be accurate
- **Performance matters**: This library may process millions of events
- **Developer experience**: The API should be intuitive and well-documented
- **Maintainability**: Code should be clean, tested, and easy to understand
- **Library focus**: This is a building block for other tools, not a standalone application
