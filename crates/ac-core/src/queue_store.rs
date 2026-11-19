//! Persistent SQLite storage engine for continuous session task queue (Feature F11).
//!
//! Manages task backlogs with priority scheduling (`ORDER BY priority DESC, created_at ASC`),
//! status tracking, and autonomous session dispatch.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

use crate::types::QueuedTaskRecord;

pub struct QueueStore {
    conn: Connection,
}

impl QueueStore {
    /// Opens or creates `queue.db` at the specified path.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory: {}", parent.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("opening queue db: {}", path.display()))?;

        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Opens an in-memory database (primarily for tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory queue db")?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS tasks (
                 id                  TEXT PRIMARY KEY,
                 title               TEXT NOT NULL,
                 prompt              TEXT,
                 priority            INTEGER NOT NULL DEFAULT 0,
                 status              TEXT NOT NULL DEFAULT 'pending',
                 session_id          TEXT,
                 project_id          TEXT,
                 created_at          TEXT NOT NULL,
                 started_at          TEXT,
                 completed_at        TEXT,
                 error               TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_tasks_status_priority ON tasks(status, priority DESC, created_at ASC);

             CREATE TABLE IF NOT EXISTS queue_meta (
                 key                 TEXT PRIMARY KEY,
                 value               TEXT NOT NULL
             );",
        )?;
        Ok(())
    }

    /// Enqueues a new task backlog item.
    pub fn enqueue(
        &self,
        title: &str,
        prompt: Option<&str>,
        priority: i32,
        project_id: Option<&str>,
    ) -> Result<String> {
        let id = ulid::Ulid::new().to_string();
        let ts = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT INTO tasks (id, title, prompt, priority, status, project_id, created_at)
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6)",
            params![id, title, prompt, priority, project_id, ts],
        )?;

        Ok(id)
    }

    /// Lists all tasks ordered by priority descending, then creation timestamp ascending.
    pub fn list(&self) -> Result<Vec<QueuedTaskRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, title, prompt, priority, status, session_id, project_id, created_at, started_at, completed_at, error
             FROM tasks ORDER BY priority DESC, created_at ASC",
        )?;

        let rows = stmt.query_map([], |r| {
            Ok(QueuedTaskRecord {
                id: r.get(0)?,
                title: r.get(1)?,
                prompt: r.get(2)?,
                priority: r.get(3)?,
                status: r.get(4)?,
                session_id: r.get(5)?,
                project_id: r.get(6)?,
                created_at: r.get(7)?,
                started_at: r.get(8)?,
                completed_at: r.get(9)?,
                error: r.get(10)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Fetches a task by ID.
    pub fn get(&self, id: &str) -> Result<Option<QueuedTaskRecord>> {
        self.conn
            .query_row(
                "SELECT id, title, prompt, priority, status, session_id, project_id, created_at, started_at, completed_at, error
                 FROM tasks WHERE id = ?1",
                params![id],
                |r| {
                    Ok(QueuedTaskRecord {
                        id: r.get(0)?,
                        title: r.get(1)?,
                        prompt: r.get(2)?,
                        priority: r.get(3)?,
                        status: r.get(4)?,
                        session_id: r.get(5)?,
                        project_id: r.get(6)?,
                        created_at: r.get(7)?,
                        started_at: r.get(8)?,
                        completed_at: r.get(9)?,
                        error: r.get(10)?,
                    })
                },
            )
            .optional()
            .context("querying task")
    }

    /// Cancels a task by ID.
    pub fn cancel(&self, id: &str) -> Result<bool> {
        let count = self.conn.execute(
            "UPDATE tasks SET status = 'cancelled' WHERE id = ?1",
            params![id],
        )?;
        Ok(count > 0)
    }

    /// Updates task status, timestamps, and error messages.
    pub fn update_status(
        &self,
        id: &str,
        status: &str,
        session_id: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        let ts = Utc::now().to_rfc3339();
        match status {
            "running" => {
                self.conn.execute(
                    "UPDATE tasks SET status = ?1, session_id = ?2, started_at = ?3 WHERE id = ?4",
                    params![status, session_id, ts, id],
                )?;
            }
            "completed" | "failed" => {
                self.conn.execute(
                    "UPDATE tasks SET status = ?1, completed_at = ?2, error = ?3 WHERE id = ?4",
                    params![status, ts, error, id],
                )?;
            }
            _ => {
                self.conn.execute(
                    "UPDATE tasks SET status = ?1 WHERE id = ?2",
                    params![status, id],
                )?;
            }
        }
        Ok(())
    }

    /// Claims the next highest priority pending task atomically.
    pub fn claim_next_priority(&self) -> Result<Option<QueuedTaskRecord>> {
        let next: Option<QueuedTaskRecord> = self.conn
            .query_row(
                "SELECT id, title, prompt, priority, status, session_id, project_id, created_at, started_at, completed_at, error
                 FROM tasks WHERE status = 'pending'
                 ORDER BY priority DESC, created_at ASC
                 LIMIT 1",
                [],
                |r| {
                    Ok(QueuedTaskRecord {
                        id: r.get(0)?,
                        title: r.get(1)?,
                        prompt: r.get(2)?,
                        priority: r.get(3)?,
                        status: r.get(4)?,
                        session_id: r.get(5)?,
                        project_id: r.get(6)?,
                        created_at: r.get(7)?,
                        started_at: r.get(8)?,
                        completed_at: r.get(9)?,
                        error: r.get(10)?,
                    })
                },
            )
            .optional()?;

        if let Some(ref task) = next {
            let ts = Utc::now().to_rfc3339();
            self.conn.execute(
                "UPDATE tasks SET status = 'running', started_at = ?1 WHERE id = ?2 AND status = 'pending'",
                params![ts, task.id],
            )?;
        }

        Ok(next)
    }
}
