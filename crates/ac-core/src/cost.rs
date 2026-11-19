//! Cost accounting and model pricing engine (Feature F6).
//!
//! Provides token-to-USD pricing calculations across multiple LLM providers
//! (Anthropic, Google Gemini, OpenAI, and dynamic subprocess plugins)
//! with cache token support.

use serde::{Deserialize, Serialize};

/// Token usage counts for a single request, turn, or aggregate report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
}

impl TokenUsage {
    pub fn new(prompt: u64, completion: u64, cache_read: u64, cache_write: u64) -> Self {
        Self {
            prompt_tokens: prompt,
            completion_tokens: completion,
            cache_read_tokens: cache_read,
            cache_write_tokens: cache_write,
        }
    }

    pub fn total_tokens(&self) -> u64 {
        self.prompt_tokens + self.completion_tokens + self.cache_read_tokens + self.cache_write_tokens
    }
}

/// Model pricing rates per million tokens.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ModelRates {
    pub prompt_per_m: f64,
    pub completion_per_m: f64,
    pub cache_read_per_m: f64,
    pub cache_write_per_m: f64,
}

/// Resolves pricing rates for a given model string.
pub fn resolve_model_rates(model: &str) -> ModelRates {
    let m = model.to_lowercase();
    let (prompt_rate, completion_rate, cache_read_rate, cache_write_rate) = match m.as_str() {
        m if m.contains("gemini") && m.contains("flash") => (0.10, 0.40, 0.025, 0.10),
        m if m.contains("gemini") && m.contains("pro") => (1.25, 5.00, 0.3125, 1.25),
        m if m.contains("claude") && m.contains("sonnet") => (3.00, 15.00, 0.30, 3.75),
        m if m.contains("claude") && m.contains("haiku") => (0.80, 4.00, 0.08, 1.00),
        m if m.contains("claude") && m.contains("opus") => (15.00, 75.00, 1.50, 18.75),
        m if m.contains("gpt-4o-mini") => (0.15, 0.60, 0.075, 0.15),
        m if m.contains("gpt-4o") => (2.50, 10.00, 1.25, 2.50),
        _ => (2.00, 8.00, 0.50, 2.00), // Default fallback pricing
    };

    ModelRates {
        prompt_per_m: prompt_rate,
        completion_per_m: completion_rate,
        cache_read_per_m: cache_read_rate,
        cache_write_per_m: cache_write_rate,
    }
}

/// Calculates expected USD cost based on token counts and model pricing.
pub fn calculate_cost(
    model: &str,
    prompt: u64,
    completion: u64,
    cache_read: u64,
    cache_write: u64,
) -> f64 {
    let rates = resolve_model_rates(model);
    let total = (prompt as f64 * rates.prompt_per_m
        + completion as f64 * rates.completion_per_m
        + cache_read as f64 * rates.cache_read_per_m
        + cache_write as f64 * rates.cache_write_per_m)
        / 1_000_000.0;
    (total * 1_000_000.0).round() / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_cost_models() {
        let cost = calculate_cost("claude-3-5-sonnet", 100_000, 20_000, 10_000, 5_000);
        // (100k*3 + 20k*15 + 10k*0.3 + 5k*3.75) / 1M = (300 + 300 + 3 + 18.75) / 1000 = 621.75 / 1000 = 0.62175
        assert!((cost - 0.62175).abs() < 1e-4);

        let cost_flash = calculate_cost("gemini-1.5-flash", 1_000_000, 1_000_000, 0, 0);
        assert!((cost_flash - 0.50).abs() < 1e-4);

        let cost_fallback = calculate_cost("unknown-model", 100_000, 10_000, 0, 0);
        assert!((cost_fallback - 0.28).abs() < 1e-4);
    }
}
