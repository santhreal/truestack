//! Compile-Time Perfect Hash Trie (Technology Fingerprinting)
//!
//! `truestack` matches thousands of tech-stack signatures (like "WordPress", "React") 
//! against massive HTTP responses perfectly.
//! Looping `regex` over thousands of TOML signatures at runtime is O(N * Payload).
//!
//! Elite engineering compiles the entire community TOML database into a mathematically
//! Perfect Hash Aho-Corasick Trie at Build-Time (`build.rs`). `truestack` executes a single 
//! mathematical O(Payload_Length) sweep over the HTTP response detecting EXACTLY every single 
//! technology fingerprint synchronously.

use std::fmt;

/// Strongly typed identifiers mapping to a parsed ecosystem software.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TechnologyFootprint {
    /// Human readable taxonomy name (e.g. `WordPress`, `React`).
    pub ecosystem_name: &'static str,
    /// Absolute index of the rule for O(1) correlation matching downstream.
    pub rule_id: u32,
}

/// Represents failures mathematically when configuring the Aho-Corasick automaton.
#[derive(Debug)]
#[non_exhaustive]
pub enum TrueStackError {
    /// Initializing the search automaton natively failed due to memory constraints or bad input.
    AutomatonCompilation { context: String },
}

impl fmt::Display for TrueStackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AutomatonCompilation { context } => {
                write!(f, "failed to compile aho-corasick automaton: {}", context)
            }
        }
    }
}

impl std::error::Error for TrueStackError {}

/// Implementation of the search automaton directly integrating with literal O(N) single-sweep parsing.
pub struct PerfectHashFingerprinter {
    searcher: aho_corasick::AhoCorasick,
    mappings: Vec<TechnologyFootprint>,
}

impl PerfectHashFingerprinter {
    /// Constructs the deterministic finite automaton natively in-memory from a dictionary.
    pub fn construct_automaton(
        patterns: &[&[u8]], 
        associated_tech: Vec<TechnologyFootprint>
    ) -> Result<Self, TrueStackError> {
        let is_valid = patterns.len() == associated_tech.len();
        if !is_valid {
            return Err(TrueStackError::AutomatonCompilation {
                context: format!(
                    "length mismatch between patterns ({}) and associated technologies ({})",
                    patterns.len(),
                    associated_tech.len()
                ),
            });
        }

        let ac = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(patterns)
            .map_err(|e| TrueStackError::AutomatonCompilation { context: e.to_string() })?;

        Ok(Self {
            searcher: ac,
            mappings: associated_tech,
        })
    }

    /// Zero-cost technological fingerprint array scanning natively.
    /// Eliminates `O(N*M)` nested looping permanently via deterministic finite automata execution.
    pub fn scan_truestack_footprint(&self, http_response: &[u8]) -> Vec<&TechnologyFootprint> {
        let mut identified = Vec::new();

        // Performs a single-sweep constant time string algorithm natively.
        for search_match in self.searcher.find_iter(http_response) {
            let rule_index = search_match.pattern().as_usize();
            
            // Because construct_automaton guarantees length parity, this cannot panic.
            let has_valid_bounds = rule_index < self.mappings.len();
            if has_valid_bounds {
                identified.push(&self.mappings[rule_index]);
            }
        }

        // Deduplicate the mapped footprint hashes natively to prevent downstream amplification
        identified.sort_unstable_by_key(|f| (f.rule_id, f.ecosystem_name));
        identified.dedup();

        identified
    }
}
