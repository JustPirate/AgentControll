//! Persistent SQLite storage engine for token usage and budgets (Feature F6).
//!
//! Tracks cumulative token spend per session, project, and account,
//! and enforces configurable spending thresholds.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

use crate::cost::calculate_cost;
use crate::types::{BudgetRecord, TokenUsageRecord};

pub struct CostStore {
    conn: Connection,
}

impl CostStore {
    /// Opens or creates `cost.db` at the specified path.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory: {}", parent.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("opening cost db: {}", path.display()))?;

        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Opens an in-memory database (primarily for tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory cost db")?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS token_usage (
                 id                  TEXT PRIMARY KEY,
                 session_id          TEXT NOT NULL,
                 project_id          TEXT,
                 account_id          TEXT,
                 model               TEXT NOT NULL,
                 prompt_tokens       INTEGER NOT NULL,
                 completion_tokens   INTEGER NOT NULL,
                 cache_read_tokens   INTEGER NOT NULL DEFAULT 0,
                 cache_write_tokens  INTEGER NOT NULL DEFAULT 0,
                 cost_usd            REAL NOT NULL,
                 timestamp           TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_token_usage_session ON token_usage(session_id);
             CREATE INDEX IF NOT EXISTS idx_token_usage_project ON token_usage(project_id);
             CREATE INDEX IF NOT EXISTS idx_token_usage_account ON token_usage(account_id);

             CREATE TABLE IF NOT EXISTS budgets (
                 scope               TEXT PRIMARY KEY,
                 daily_max_usd       REAL,
                 session_max_usd     REAL,
                 warning_threshold   REAL NOT NULL DEFAULT 0.80,
                 enforcement_action  TEXT NOT NULL DEFAULT 'pause',
                 created_at          TEXT NOT NULL,
                 updated_at          TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS model_pricing (
                 model_pattern       TEXT PRIMARY KEY,
                 provider            TEXT NOT NULL,
                 prompt_per_m        REAL NOT NULL,
                 completion_per_m    REAL NOT NULL,
                 cache_read_per_m    REAL NOT NULL,
                 cache_write_per_m   REAL NOT NULL
             );",
        )?;
        Ok(())
    }

    /// Records token usage, computes USD cost, and stores record in SQLite.
    pub fn record_usage(
        &self,
        session_id: &str,
        project_id: Option<&str>,
        account_id: Option<&str>,
        model: &str,
        prompt: u64,
        completion: u64,
        cache_read: u64,
        cache_write: u64,
    ) -> Result<(String, f64)> {
        let cost = calculate_cost(model, prompt, completion, cache_read, cache_write);
        let id = ulid::Ulid::new().to_string();
        let ts = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT INTO token_usage (id, session_id, project_id, account_id, model, prompt_tokens, completion_tokens, cache_read_tokens, cache_write_tokens, cost_usd, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                session_id,
                project_id,
                account_id,
                model,
                prompt as i64,
                completion as i64,
                cache_read as i64,
                cache_write as i64,
                cost,
                ts,
            ],
        )?;

        Ok((id, cost))
    }

    /// Returns cumulative spend for a session, or across all sessions if `None`.
    pub fn get_total_spend(&self, session_id: Option<&str>) -> Result<f64> {
        let sql = match session_id {
            Some(_) => "SELECT COALESCE(SUM(cost_usd), 0.0) FROM token_usage WHERE session_id = ?1",
            None => "SELECT COALESCE(SUM(cost_usd), 0.0) FROM token_usage",
        };
        let cost: f64 = match session_id {
            Some(sid) => self.conn.query_row(sql, params![sid], |r| r.get(0))?,
            None => self.conn.query_row(sql, [], |r| r.get(0))?,
        };
        Ok((cost * 1_000_000.0).round() / 1_000_000.0)
    }

    /// Query token usage records with optional filters.
    pub fn query_records(
        &self,
        session_id: Option<&str>,
        project_id: Option<&str>,
        account_id: Option<&str>,
    ) -> Result<Vec<TokenUsageRecord>> {
        let mut query = "SELECT id, session_id, project_id, account_id, model, prompt_tokens, completion_tokens, cache_read_tokens, cache_write_tokens, cost_usd, timestamp FROM token_usage WHERE 1=1".to_string();
        let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(sid) = session_id {
            query.push_str(" AND session_id = ?");
            params_vec.push(sid.to_string().into());
        }
        if let Some(pid) = project_id {
            query.push_str(" AND project_id = ?");
            params_vec.push(pid.to_string().into());
        }
        if let Some(aid) = account_id {
            query.push_str(" AND account_id = ?");
            params_vec.push(aid.to_string().into());
        }
        query.push_str(" ORDER BY timestamp DESC");

        let mut stmt = self.conn.prepare(&query)?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(param_refs.as_slice(), |r| {
            let prompt_i: i64 = r.get(5)?;
            let comp_i: i64 = r.get(6)?;
            let cr_i: i64 = r.get(7)?;
            let cw_i: i64 = r.get(8)?;
            Ok(TokenUsageRecord {
                id: r.get(0)?,
                session_id: r.get(1)?,
                project_id: r.get(2)?,
                account_id: r.get(3)?,
                model: r.get(4)?,
                prompt_tokens: prompt_i as u64,
                completion_tokens: comp_i as u64,
                cache_read_tokens: cr_i as u64,
                cache_write_tokens: cw_i as u64,
                cost_usd: r.get(9)?,
                timestamp: r.get(10)?,
            })
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Sets or updates spending budget for a scope.
    pub fn set_budget(
        &self,
        scope: &str,
        daily_max_usd: Option<f64>,
        session_max_usd: Option<f64>,
    ) -> Result<()> {
        let ts = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO budgets (scope, daily_max_usd, session_max_usd, warning_threshold, enforcement_action, created_at, updated_at)
             VALUES (?1, ?2, ?3, 0.80, 'pause', ?4, ?4)
             ON CONFLICT(scope) DO UPDATE SET
               daily_max_usd = coalesce(?2, daily_max_usd),
               session_max_usd = coalesce(?3, session_max_usd),
               updated_at = ?4",
            params![scope, daily_max_usd, session_max_usd, ts],
        )?;
        Ok(())
    }

    /// Retrieves budget for a given scope.
    pub fn get_budget(&self, scope: &str) -> Result<Option<BudgetRecord>> {
        self.conn
            .query_row(
                "SELECT scope, daily_max_usd, session_max_usd, warning_threshold, enforcement_action, created_at, updated_at
                 FROM budgets WHERE scope = ?1",
                params![scope],
                |r| {
                    Ok(BudgetRecord {
                        scope: r.get(0)?,
                        daily_max_usd: r.get(1)?,
                        session_max_usd: r.get(2)?,
                        warning_threshold: r.get(3)?,
                        enforcement_action: r.get(4)?,
                        created_at: r.get(5)?,
                        updated_at: r.get(6)?,
                    })
                },
            )
            .optional()
            .context("querying budget")
    }

    /// Lists all configured budgets.
    pub fn list_budgets(&self) -> Result<Vec<BudgetRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT scope, daily_max_usd, session_max_usd, warning_threshold, enforcement_action, created_at, updated_at
             FROM budgets ORDER BY scope ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(BudgetRecord {
                scope: r.get(0)?,
                daily_max_usd: r.get(1)?,
                session_max_usd: r.get(2)?,
                warning_threshold: r.get(3)?,
                enforcement_action: r.get(4)?,
                created_at: r.get(5)?,
                updated_at: r.get(6)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }
}
