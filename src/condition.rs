//! Tokenizer and recursive-descent parser for Sigma condition expressions.
//!
//! Handles both standard detection rule conditions (with `1 of them`, `all of pattern*`, etc.)
//! and extended correlation conditions (plain boolean expressions referencing rule names/IDs).

use crate::error::Error;
use crate::types::ConditionExpression;

// ─── Tokens ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Token {
    And,
    Or,
    Not,
    One,   // literal "1"
    All,   // keyword "all"
    Of,    // keyword "of"
    Them,  // keyword "them"
    LParen,
    RParen,
    Ident(String),
}

// ─── Tokenizer ───────────────────────────────────────────────────────────────

fn tokenize(input: &str) -> Result<Vec<Token>, Error> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut pos = 0;

    while pos < chars.len() {
        // skip whitespace
        if chars[pos].is_whitespace() {
            pos += 1;
            continue;
        }

        match chars[pos] {
            '(' => {
                tokens.push(Token::LParen);
                pos += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                pos += 1;
            }
            _ => {
                let start = pos;
                while pos < chars.len()
                    && !chars[pos].is_whitespace()
                    && chars[pos] != '('
                    && chars[pos] != ')'
                {
                    pos += 1;
                }
                let word: String = chars[start..pos].iter().collect();
                let token = match word.as_str() {
                    "and" | "AND" => Token::And,
                    "or" | "OR" => Token::Or,
                    "not" | "NOT" => Token::Not,
                    "1" => Token::One,
                    "all" => Token::All,
                    "of" => Token::Of,
                    "them" => Token::Them,
                    _ => Token::Ident(word),
                };
                tokens.push(token);
            }
        }
    }

    Ok(tokens)
}

// ─── Parser ──────────────────────────────────────────────────────────────────

/// Parse a Sigma condition string into a [`ConditionExpression`] AST.
///
/// Operator precedence (lowest → highest):
/// 1. `or`
/// 2. `and`
/// 3. `not`
/// 4. `1 of …` / `all of …`
/// 5. `( expression )`
pub fn parse_condition(input: &str) -> Result<ConditionExpression, Error> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err(Error::Condition("Empty condition".into()));
    }
    let mut parser = Parser { tokens, pos: 0 };
    let expr = parser.parse_or()?;
    if parser.pos < parser.tokens.len() {
        return Err(Error::Condition(format!(
            "Unexpected token at position {}: {:?}",
            parser.pos, parser.tokens[parser.pos]
        )));
    }
    Ok(expr)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn lookahead(&self, offset: usize) -> Option<&Token> {
        self.tokens.get(self.pos + offset)
    }

    fn advance(&mut self) {
        self.pos += 1;
    }

    /// `or_expr := and_expr ('or' and_expr)*`
    fn parse_or(&mut self) -> Result<ConditionExpression, Error> {
        let mut left = self.parse_and()?;
        while self.peek() == Some(&Token::Or) {
            self.advance();
            let right = self.parse_and()?;
            left = ConditionExpression::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// `and_expr := not_expr ('and' not_expr)*`
    fn parse_and(&mut self) -> Result<ConditionExpression, Error> {
        let mut left = self.parse_not()?;
        while self.peek() == Some(&Token::And) {
            self.advance();
            let right = self.parse_not()?;
            left = ConditionExpression::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// `not_expr := 'not' not_expr | primary`
    fn parse_not(&mut self) -> Result<ConditionExpression, Error> {
        if self.peek() == Some(&Token::Not) {
            self.advance();
            let expr = self.parse_not()?;
            return Ok(ConditionExpression::Not(Box::new(expr)));
        }
        self.parse_primary()
    }

    /// ```text
    /// primary := '(' or_expr ')'
    ///          | ('1' | 'all') 'of' ('them' | pattern)
    ///          | identifier
    /// ```
    fn parse_primary(&mut self) -> Result<ConditionExpression, Error> {
        match self.peek().cloned() {
            Some(Token::LParen) => {
                self.advance();
                let expr = self.parse_or()?;
                if self.peek() != Some(&Token::RParen) {
                    return Err(Error::Condition("Expected closing ')'".into()));
                }
                self.advance();
                Ok(expr)
            }
            Some(Token::One) => {
                if self.lookahead(1) == Some(&Token::Of) {
                    self.advance(); // consume '1'
                    self.advance(); // consume 'of'
                    self.parse_of_scope(false)
                } else {
                    self.advance();
                    Ok(ConditionExpression::Identifier("1".into()))
                }
            }
            Some(Token::All) => {
                if self.lookahead(1) == Some(&Token::Of) {
                    self.advance(); // consume 'all'
                    self.advance(); // consume 'of'
                    self.parse_of_scope(true)
                } else {
                    self.advance();
                    Ok(ConditionExpression::Identifier("all".into()))
                }
            }
            Some(Token::Ident(name)) => {
                self.advance();
                Ok(ConditionExpression::Identifier(name))
            }
            // Allow reserved words as identifiers in primary position (edge cases)
            Some(Token::Them) => {
                self.advance();
                Ok(ConditionExpression::Identifier("them".into()))
            }
            Some(Token::Of) => {
                self.advance();
                Ok(ConditionExpression::Identifier("of".into()))
            }
            Some(other) => Err(Error::Condition(format!(
                "Unexpected token in expression: {other:?}"
            ))),
            None => Err(Error::Condition("Unexpected end of condition".into())),
        }
    }

    /// Parse the scope token after `… of`.
    fn parse_of_scope(&mut self, is_all: bool) -> Result<ConditionExpression, Error> {
        match self.peek().cloned() {
            Some(Token::Them) => {
                self.advance();
                Ok(if is_all {
                    ConditionExpression::AllOfThem
                } else {
                    ConditionExpression::OneOfThem
                })
            }
            Some(Token::Ident(pattern)) => {
                self.advance();
                Ok(if is_all {
                    ConditionExpression::AllOfPattern(pattern)
                } else {
                    ConditionExpression::OneOfPattern(pattern)
                })
            }
            other => Err(Error::Condition(format!(
                "Expected 'them' or pattern after 'of', got {other:?}"
            ))),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ConditionExpression::*;

    #[test]
    fn simple_identifier() {
        let expr = parse_condition("selection").unwrap();
        assert_eq!(expr, Identifier("selection".into()));
    }

    #[test]
    fn and_or_not() {
        let expr = parse_condition("sel1 and sel2 or sel3").unwrap();
        // `or` has lower precedence than `and`
        assert_eq!(
            expr,
            Or(
                Box::new(And(
                    Box::new(Identifier("sel1".into())),
                    Box::new(Identifier("sel2".into())),
                )),
                Box::new(Identifier("sel3".into())),
            )
        );
    }

    #[test]
    fn not_with_parentheses() {
        let expr = parse_condition("sel1 and not (sel2 or sel3)").unwrap();
        assert_eq!(
            expr,
            And(
                Box::new(Identifier("sel1".into())),
                Box::new(Not(Box::new(Or(
                    Box::new(Identifier("sel2".into())),
                    Box::new(Identifier("sel3".into())),
                )))),
            )
        );
    }

    #[test]
    fn one_of_them() {
        let expr = parse_condition("1 of them").unwrap();
        assert_eq!(expr, OneOfThem);
    }

    #[test]
    fn all_of_pattern() {
        let expr = parse_condition("all of selection*").unwrap();
        assert_eq!(expr, AllOfPattern("selection*".into()));
    }

    #[test]
    fn complex_condition() {
        let expr = parse_condition("1 of selection* and not 1 of filter*").unwrap();
        assert_eq!(
            expr,
            And(
                Box::new(OneOfPattern("selection*".into())),
                Box::new(Not(Box::new(OneOfPattern("filter*".into())))),
            )
        );
    }

    #[test]
    fn extended_correlation_condition() {
        let expr = parse_condition("rule_a and not rule_b and rule_c").unwrap();
        assert_eq!(
            expr,
            And(
                Box::new(And(
                    Box::new(Identifier("rule_a".into())),
                    Box::new(Not(Box::new(Identifier("rule_b".into())))),
                )),
                Box::new(Identifier("rule_c".into())),
            )
        );
    }

    #[test]
    fn empty_condition_errors() {
        assert!(parse_condition("").is_err());
    }

    #[test]
    fn unmatched_paren_errors() {
        assert!(parse_condition("(sel1 and sel2").is_err());
    }

    #[test]
    fn trailing_tokens_error() {
        let err = parse_condition("selection extra").unwrap_err();
        assert!(err.to_string().contains("Unexpected token"));
    }

    #[test]
    fn one_not_followed_by_of_is_identifier() {
        let expr = parse_condition("1 and sel").unwrap();
        assert_eq!(
            expr,
            And(
                Box::new(Identifier("1".into())),
                Box::new(Identifier("sel".into())),
            )
        );
    }

    #[test]
    fn all_not_followed_by_of_is_identifier() {
        let expr = parse_condition("all and sel").unwrap();
        assert_eq!(
            expr,
            And(
                Box::new(Identifier("all".into())),
                Box::new(Identifier("sel".into())),
            )
        );
    }

    #[test]
    fn them_in_primary_is_identifier() {
        let expr = parse_condition("them").unwrap();
        assert_eq!(expr, Identifier("them".into()));
    }

    #[test]
    fn of_in_primary_is_identifier() {
        let expr = parse_condition("of").unwrap();
        assert_eq!(expr, Identifier("of".into()));
    }

    #[test]
    fn unexpected_token_error() {
        // RParen without matching LParen triggers unexpected token
        let err = parse_condition(")").unwrap_err();
        assert!(err.to_string().contains("Unexpected token"));
    }

    #[test]
    fn unexpected_end_of_expression() {
        // `not` with nothing following
        let err = parse_condition("not").unwrap_err();
        assert!(err.to_string().contains("end of condition"));
    }

    #[test]
    fn all_of_them() {
        let expr = parse_condition("all of them").unwrap();
        assert_eq!(expr, AllOfThem);
    }

    #[test]
    fn error_after_of() {
        // `1 of` followed by an invalid token (e.g. `and`)
        let err = parse_condition("1 of and").unwrap_err();
        assert!(err.to_string().contains("Expected 'them' or pattern after 'of'"));
    }
}
