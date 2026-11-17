//! Reusable Session Templates & Presets (F10).
//!
//! Provides persistence (`TemplateStore`), thread-safe in-memory caching and resolution
//! (`TemplateManager`), and shared handle abstraction (`TemplateManagerHandle`).

use anyhow::{bail, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::info;

use crate::types::{Id, SessionTemplate};

/// Validate whether a template name is a valid slug.
/// Non-empty, alphanumeric + hyphens/underscores, max length 128.
pub fn is_valid_template_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return false;
    }
    trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ── Persistent Store ──────────────────────────────────────────────────────────

/// Persistent SQLite store for `SessionTemplate` entities.
pub struct TemplateStore {
    conn: Connection,
}

impl TemplateStore {
    /// Open or create an SQLite database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let conn = Connection::open(path)?;
        let s = Self { conn };
        s.init_schema()?;
        Ok(s)
    }

    /// Open an in-memory SQLite database (used for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let s = Self { conn };
        s.init_schema()?;
        Ok(s)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS templates (
                 id                   TEXT PRIMARY KEY,
                 name                 TEXT NOT NULL UNIQUE,
                 description          TEXT,
                 agent_type           TEXT NOT NULL,
                 default_task_prompt  TEXT,
                 account_tag          TEXT,
                 permission_mode      TEXT,
                 model                TEXT,
                 launch_options       TEXT,  -- Serialized JSON of AgyLaunchOptions
                 created_at           TEXT NOT NULL,
                 updated_at           TEXT NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_templates_name ON templates(name);
             CREATE INDEX IF NOT EXISTS idx_templates_agent_type ON templates(agent_type);",
        )?;
        Ok(())
    }

    /// Insert a new template into the store.
    pub fn insert(&self, template: &SessionTemplate) -> Result<()> {
        let launch_json = match &template.launch_options {
            Some(opts) => Some(serde_json::to_string(opts)?),
            None => None,
        };
        self.conn.execute(
            "INSERT INTO templates
             (id, name, description, agent_type, default_task_prompt, account_tag,
              permission_mode, model, launch_options, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                template.id.0,
                template.name,
                template.description,
                template.agent_type,
                template.default_task_prompt,
                template.account_tag,
                template.permission_mode,
                template.model,
                launch_json,
                template.created_at.to_rfc3339(),
                template.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Update an existing template in the store.
    pub fn update(&self, template: &SessionTemplate) -> Result<()> {
        let launch_json = match &template.launch_options {
            Some(opts) => Some(serde_json::to_string(opts)?),
            None => None,
        };
        let count = self.conn.execute(
            "UPDATE templates SET
             name = ?2,
             description = ?3,
             agent_type = ?4,
             default_task_prompt = ?5,
             account_tag = ?6,
             permission_mode = ?7,
             model = ?8,
             launch_options = ?9,
             updated_at = ?10
             WHERE id = ?1",
            params![
                template.id.0,
                template.name,
                template.description,
                template.agent_type,
                template.default_task_prompt,
                template.account_tag,
                template.permission_mode,
                template.model,
                launch_json,
                template.updated_at.to_rfc3339(),
            ],
        )?;
        if count == 0 {
            bail!("Template not found: {}", template.id);
        }
        Ok(())
    }

    /// Delete a template by its ID.
    pub fn delete(&self, id: &Id) -> Result<()> {
        let count = self
            .conn
            .execute("DELETE FROM templates WHERE id = ?1", params![id.0])?;
        if count == 0 {
            bail!("Template not found: {}", id);
        }
        Ok(())
    }

    /// Get a template by its ID.
    pub fn get(&self, id: &Id) -> Result<Option<SessionTemplate>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, description, agent_type, default_task_prompt, account_tag,
                    permission_mode, model, launch_options, created_at, updated_at
             FROM templates WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id.0])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_to_template(row)?))
        } else {
            Ok(None)
        }
    }

    /// Get a template by its name (case-insensitive).
    pub fn get_by_name(&self, name: &str) -> Result<Option<SessionTemplate>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, description, agent_type, default_task_prompt, account_tag,
                    permission_mode, model, launch_options, created_at, updated_at
             FROM templates WHERE name = ?1 COLLATE NOCASE",
        )?;
        let mut rows = stmt.query(params![name.trim()])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_to_template(row)?))
        } else {
            Ok(None)
        }
    }

    /// Load all templates from the store, ordered by creation time ascending.
    pub fn load_all(&self) -> Result<Vec<SessionTemplate>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, description, agent_type, default_task_prompt, account_tag,
                    permission_mode, model, launch_options, created_at, updated_at
             FROM templates ORDER BY created_at ASC",
        )?;
        let rows = stmt
            .query_map([], row_to_template)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Check whether a template exists with the given ID.
    pub fn exists(&self, id: &Id) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM templates WHERE id = ?1",
            params![id.0],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }
}

fn row_to_template(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionTemplate> {
    let id: String = row.get(0)?;
    let name: String = row.get(1)?;
    let description: Option<String> = row.get(2)?;
    let agent_type: String = row.get(3)?;
    let default_task_prompt: Option<String> = row.get(4)?;
    let account_tag: Option<String> = row.get(5)?;
    let permission_mode: Option<String> = row.get(6)?;
    let model: Option<String> = row.get(7)?;
    let launch_options_str: Option<String> = row.get(8)?;
    let created_at_str: String = row.get(9)?;
    let updated_at_str: String = row.get(10)?;

    let launch_options = launch_options_str.and_then(|s| serde_json::from_str(&s).ok());
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    Ok(SessionTemplate {
        id: Id(id),
        name,
        description,
        agent_type,
        default_task_prompt,
        account_tag,
        permission_mode,
        model,
        launch_options,
        created_at,
        updated_at,
    })
}

// ── In-Memory Manager ─────────────────────────────────────────────────────────

/// In-memory manager and caching layer for `SessionTemplate` entities.
pub struct TemplateManager {
    templates: HashMap<String, SessionTemplate>,
    store: TemplateStore,
}

impl TemplateManager {
    /// Create a new `TemplateManager` loading initial state from `store`.
    pub fn new(store: TemplateStore) -> Result<Self> {
        let all = store.load_all()?;
        let mut templates = HashMap::new();
        for t in all {
            templates.insert(t.id.0.clone(), t);
        }
        info!("TemplateManager loaded {} templates", templates.len());
        Ok(Self { templates, store })
    }

    /// Register / create a new template.
    ///
    /// Validates the slug name, checks for duplicate names, and persists to SQLite.
    pub fn create(&mut self, mut template: SessionTemplate) -> Result<Id> {
        let trimmed_name = template.name.trim().to_string();
        if !is_valid_template_name(&trimmed_name) {
            bail!("ValidationError: Template name must be a non-empty alphanumeric slug (hyphens and underscores allowed)");
        }
        template.name = trimmed_name.clone();

        if self.get_by_name(&template.name).is_some() {
            bail!(
                "Conflict: Template with name '{}' already exists",
                template.name
            );
        }

        if let Some(ref l) = template.launch_options {
            l.validate()
                .map_err(|e| anyhow::anyhow!("ValidationError: {e}"))?;
        }

        let id = template.id.clone();
        self.store.insert(&template)?;
        self.templates.insert(id.0.clone(), template);
        info!("Template created: id={}, name={}", id, trimmed_name);
        Ok(id)
    }

    /// Get a template by its ID.
    pub fn get(&self, id: &Id) -> Option<&SessionTemplate> {
        self.templates.get(&id.0)
    }

    /// Get a template by name (case-insensitive).
    pub fn get_by_name(&self, name: &str) -> Option<&SessionTemplate> {
        let needle = name.trim();
        self.templates
            .values()
            .find(|t| t.name.eq_ignore_ascii_case(needle))
    }

    /// Resolve a template by identifier (checks ID first, then name slug).
    pub fn resolve(&self, name_or_id: &str) -> Option<&SessionTemplate> {
        let needle = name_or_id.trim();
        if let Some(t) = self.templates.get(needle) {
            return Some(t);
        }
        self.get_by_name(needle)
    }

    /// List all templates ordered by creation time ascending.
    pub fn list(&self) -> Vec<&SessionTemplate> {
        let mut list: Vec<&SessionTemplate> = self.templates.values().collect();
        list.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        list
    }

    /// Update an existing template.
    pub fn update(&mut self, mut template: SessionTemplate) -> Result<()> {
        let id_str = template.id.0.clone();
        if !self.templates.contains_key(&id_str) {
            bail!("Template not found: {}", template.id);
        }

        let trimmed_name = template.name.trim().to_string();
        if !is_valid_template_name(&trimmed_name) {
            bail!("ValidationError: Template name must be a non-empty alphanumeric slug (hyphens and underscores allowed)");
        }
        template.name = trimmed_name;

        if let Some(existing) = self.get_by_name(&template.name) {
            if existing.id != template.id {
                bail!(
                    "Conflict: Template with name '{}' already exists",
                    template.name
                );
            }
        }

        if let Some(ref l) = template.launch_options {
            l.validate()
                .map_err(|e| anyhow::anyhow!("ValidationError: {e}"))?;
        }

        template.updated_at = Utc::now();
        self.store.update(&template)?;
        self.templates.insert(id_str, template);
        Ok(())
    }

    /// Delete a template by ID.
    pub fn delete(&mut self, id: &Id) -> Result<()> {
        if !self.templates.contains_key(&id.0) {
            bail!("Template not found: {}", id);
        }
        self.store.delete(id)?;
        self.templates.remove(&id.0);
        info!("Template deleted: {}", id);
        Ok(())
    }
}

// ── Thread-Safe Handle ────────────────────────────────────────────────────────

/// Thread-safe shared handle wrapping an `Arc<Mutex<TemplateManager>>`.
#[derive(Clone)]
pub struct TemplateManagerHandle(pub Arc<Mutex<TemplateManager>>);

impl TemplateManagerHandle {
    pub fn new(mgr: TemplateManager) -> Self {
        Self(Arc::new(Mutex::new(mgr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agy_launch::{AgyExecutionMode, AgyLaunchOptions, AgyPermissionMode};

    fn sample_template(name: &str) -> SessionTemplate {
        let mut t = SessionTemplate::new(name, "agy");
        t.description = Some("Sample test template".into());
        t.default_task_prompt = Some("Inspect repo and run tests".into());
        t.account_tag = Some("fast".into());
        t.permission_mode = Some("normal".into());
        t.model = Some("gemini-3.8-flash-medium".into());
        let mut launch = AgyLaunchOptions::default();
        launch.execution_mode = AgyExecutionMode::Plan;
        launch.permission_mode = AgyPermissionMode::Normal;
        launch.sandbox = true;
        t.launch_options = Some(launch);
        t
    }

    #[test]
    fn test_store_crud() {
        let store = TemplateStore::open_in_memory().unwrap();
        let t1 = sample_template("code-review");
        store.insert(&t1).unwrap();

        assert!(store.exists(&t1.id).unwrap());
        let loaded = store.get(&t1.id).unwrap().expect("template must exist");
        assert_eq!(loaded.name, "code-review");
        assert_eq!(loaded.agent_type, "agy");
        assert_eq!(
            loaded.launch_options.as_ref().unwrap().execution_mode,
            AgyExecutionMode::Plan
        );

        let by_name = store.get_by_name("CODE-REVIEW").unwrap().unwrap();
        assert_eq!(by_name.id, t1.id);

        let mut updated = t1.clone();
        updated.description = Some("Updated description".into());
        store.update(&updated).unwrap();
        let loaded2 = store.get(&t1.id).unwrap().unwrap();
        assert_eq!(loaded2.description.as_deref(), Some("Updated description"));

        store.delete(&t1.id).unwrap();
        assert!(!store.exists(&t1.id).unwrap());
        assert!(store.get(&t1.id).unwrap().is_none());
    }

    #[test]
    fn test_persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("templates.db");

        let t1 = sample_template("persisted-tmpl");
        {
            let store = TemplateStore::open(&db_path).unwrap();
            store.insert(&t1).unwrap();
        }

        {
            let store = TemplateStore::open(&db_path).unwrap();
            let all = store.load_all().unwrap();
            assert_eq!(all.len(), 1);
            assert_eq!(all[0].id, t1.id);
            assert_eq!(all[0].name, "persisted-tmpl");
            assert_eq!(
                all[0].default_task_prompt.as_deref(),
                Some("Inspect repo and run tests")
            );
        }
    }

    #[test]
    fn test_manager_resolve_by_id_and_name() {
        let store = TemplateStore::open_in_memory().unwrap();
        let mut mgr = TemplateManager::new(store).unwrap();

        let t = sample_template("fast-audit");
        let id = mgr.create(t.clone()).unwrap();

        // Resolve by ID
        let resolved_by_id = mgr.resolve(&id.0).expect("resolve by id failed");
        assert_eq!(resolved_by_id.name, "fast-audit");

        // Resolve by exact name
        let resolved_by_name = mgr.resolve("fast-audit").expect("resolve by name failed");
        assert_eq!(resolved_by_name.id, id);

        // Resolve by case-insensitive name
        let resolved_ci = mgr.resolve("FAST-AUDIT").expect("resolve CI failed");
        assert_eq!(resolved_ci.id, id);

        // Non-existent
        assert!(mgr.resolve("unknown-template").is_none());
    }

    #[test]
    fn test_duplicate_name_conflict_rejected() {
        let store = TemplateStore::open_in_memory().unwrap();
        let mut mgr = TemplateManager::new(store).unwrap();

        let t1 = sample_template("my-template");
        mgr.create(t1).unwrap();

        let t2 = sample_template("my-template");
        let err = mgr.create(t2).unwrap_err();
        assert!(err.to_string().contains("already exists"));

        // Case-insensitive duplicate rejection
        let t3 = sample_template("MY-TEMPLATE");
        let err3 = mgr.create(t3).unwrap_err();
        assert!(err3.to_string().contains("already exists"));
    }

    #[test]
    fn test_invalid_slug_name_rejected() {
        assert!(!is_valid_template_name(""));
        assert!(!is_valid_template_name("   "));
        assert!(!is_valid_template_name("name with spaces"));
        assert!(!is_valid_template_name("invalid/slash"));
        assert!(!is_valid_template_name("invalid@symbol"));

        assert!(is_valid_template_name("valid-slug"));
        assert!(is_valid_template_name("valid_slug_123"));
        assert!(is_valid_template_name("ValidSlug"));
    }
}
