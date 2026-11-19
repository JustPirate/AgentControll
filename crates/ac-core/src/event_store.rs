//! Append-only SQLite event store.
//!
//! The store owns two tables:
//!  - `events`   — all `AgentEvent`s in sequence-number order, never updated or deleted.
//!  - `snapshots`— periodic derived-state snapshots bound to a sequence number.
//!
//! On open, the store verifies that sequence numbers are gapless.

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::path::Path;

use crate::types::{
    AgentEvent, AuditIntegrityReport, EventKind, Id, IntegrityViolation,
};

pub const SCHEMA_VERSION: u32 = 2;

/// Genesis previous hash: 64 hexadecimal zeros representing the root anchor of the hash chain.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Computes the canonical SHA-256 hash for an audit log event:
/// `SHA-256(prev_hash || sequence_number || timestamp || event_type || payload)`.
pub fn compute_event_hash(
    prev_hash: &str,
    seq: u64,
    timestamp: &str,
    event_type: &str,
    payload: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    let seq_str = seq.to_string();
    hasher.update(seq_str.as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(event_type.as_bytes());
    hasher.update(payload.as_bytes());
    let digest = hasher.finalize();

    let mut hex_str = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex_str, "{:02x}", byte);
    }
    hex_str
}

/// Event store diagnostic and sequence integrity report (Phase 8).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrityReport {
    pub total_events: u64,
    pub max_seq: u64,
    pub gap_count: u64,
    pub schema_version: u32,
    pub is_valid: bool,
}

/// Append-only SQLite event store with cryptographic SHA-256 hash chaining (F7 / ADR-010).
pub struct EventStore {
    conn: Connection,
    last_seq: u64,
    last_hash: String,
}

impl EventStore {
    /// Open (or create) the event store at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating db directory: {}", parent.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("opening sqlite db: {}", path.display()))?;

        let mut store = Self {
            conn,
            last_seq: 0,
            last_hash: GENESIS_PREV_HASH.to_string(),
        };
        store.init_schema()?;
        store.migrate_schema()?;
        store.verify_sequence_integrity()?;
        store.load_last_seq_and_hash()?;
        Ok(store)
    }

    /// Open an in-memory event store (for tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory sqlite db")?;
        let mut store = Self {
            conn,
            last_seq: 0,
            last_hash: GENESIS_PREV_HASH.to_string(),
        };
        store.init_schema()?;
        store.migrate_schema()?;
        store.load_last_seq_and_hash()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn
            .execute_batch(&format!(
                "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;

             CREATE TABLE IF NOT EXISTS schema_meta (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );

             INSERT OR IGNORE INTO schema_meta (key, value)
             VALUES ('version', '{SCHEMA_VERSION}');

             CREATE TABLE IF NOT EXISTS events (
                 seq          INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_id     TEXT    NOT NULL UNIQUE,
                 version      INTEGER NOT NULL DEFAULT 1,
                 kind         TEXT    NOT NULL,
                 session_id   TEXT,
                 payload      TEXT    NOT NULL,
                 triggered_by TEXT    NOT NULL,
                 timestamp    TEXT    NOT NULL,
                 prev_hash    TEXT,
                 hash         TEXT
             );

             CREATE INDEX IF NOT EXISTS idx_events_session
                 ON events (session_id) WHERE session_id IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_events_kind
                 ON events (kind);
             CREATE INDEX IF NOT EXISTS idx_events_timestamp
                 ON events (timestamp);

             CREATE TABLE IF NOT EXISTS snapshots (
                 id           INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_seq    INTEGER NOT NULL,
                 payload      TEXT    NOT NULL,
                 created_at   TEXT    NOT NULL
             );",
            ))
            .context("initialising event store schema")?;
        Ok(())
    }

    /// Automatically migrate schema across versions and backfill cryptographic hash chains.
    fn migrate_schema(&mut self) -> Result<()> {
        let schema_ver_str: String = self
            .conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'version'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "1".to_string());
        let current_version: u32 = schema_ver_str.parse().unwrap_or(1);

        if current_version < 2 {
            // Check if columns exist
            let mut has_prev_hash = false;
            let mut has_hash = false;
            {
                let mut stmt = self.conn.prepare("PRAGMA table_info(events)")?;
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    let col_name: String = row.get(1)?;
                    if col_name == "prev_hash" {
                        has_prev_hash = true;
                    } else if col_name == "hash" {
                        has_hash = true;
                    }
                }
            }

            if !has_prev_hash {
                self.conn
                    .execute("ALTER TABLE events ADD COLUMN prev_hash TEXT", [])
                    .context("adding prev_hash column")?;
            }
            if !has_hash {
                self.conn
                    .execute("ALTER TABLE events ADD COLUMN hash TEXT", [])
                    .context("adding hash column")?;
            }

            // Backfill unhashed rows if any exist
            let unhashed_count: i64 = self
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE hash IS NULL",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);

            if unhashed_count > 0 {
                let tx = self.conn.transaction()?;
                let mut cur_seq: u64 = 0;
                let mut cur_hash = GENESIS_PREV_HASH.to_string();

                let anchor: Option<(i64, String)> = tx
                    .query_row(
                        "SELECT seq, hash FROM events WHERE hash IS NOT NULL ORDER BY seq DESC LIMIT 1",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()
                    .context("querying migration hash anchor")?;

                if let Some((seq, hash)) = anchor {
                    cur_seq = seq as u64;
                    cur_hash = hash;
                }

                struct UnhashedRow {
                    seq: u64,
                    kind: String,
                    timestamp: String,
                    payload: String,
                }

                let unhashed_rows: Vec<UnhashedRow> = {
                    let mut stmt = tx.prepare(
                        "SELECT seq, kind, timestamp, payload FROM events WHERE hash IS NULL ORDER BY seq ASC",
                    )?;
                    let rows = stmt.query_map([], |r| {
                        let seq: i64 = r.get(0)?;
                        Ok(UnhashedRow {
                            seq: seq as u64,
                            kind: r.get(1)?,
                            timestamp: r.get(2)?,
                            payload: r.get(3)?,
                        })
                    })?;
                    rows.collect::<rusqlite::Result<Vec<_>>>()?
                };

                for row in unhashed_rows {
                    if cur_seq > 0 && row.seq != cur_seq + 1 {
                        bail!("Sequence gap during migration at seq {}", row.seq);
                    }
                    let prev_hash = cur_hash;
                    let new_hash = compute_event_hash(
                        &prev_hash,
                        row.seq,
                        &row.timestamp,
                        &row.kind,
                        &row.payload,
                    );
                    tx.execute(
                        "UPDATE events SET prev_hash = ?1, hash = ?2 WHERE seq = ?3",
                        params![prev_hash, new_hash, row.seq as i64],
                    )?;
                    cur_hash = new_hash;
                    cur_seq = row.seq;
                }

                tx.execute(
                    "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('version', ?1)",
                    params![SCHEMA_VERSION.to_string()],
                )?;
                tx.commit()?;
            } else {
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('version', ?1)",
                    params![SCHEMA_VERSION.to_string()],
                )?;
            }
        }

        // Ensure index on hash column exists
        self.conn
            .execute("CREATE INDEX IF NOT EXISTS idx_events_hash ON events (hash)", [])
            .context("creating idx_events_hash")?;

        Ok(())
    }

    /// Load the last recorded sequence number and hash into the in-memory cache for O(1) appends.
    fn load_last_seq_and_hash(&mut self) -> Result<()> {
        let last: Option<(i64, Option<String>)> = self
            .conn
            .query_row(
                "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context("querying last event seq and hash")?;

        match last {
            Some((seq, Some(hash))) => {
                self.last_seq = seq as u64;
                self.last_hash = hash;
            }
            Some((seq, None)) => {
                self.last_seq = seq as u64;
                self.last_hash = GENESIS_PREV_HASH.to_string();
            }
            None => {
                self.last_seq = 0;
                self.last_hash = GENESIS_PREV_HASH.to_string();
            }
        }
        Ok(())
    }

    /// Verify that all sequence numbers in the events table are gapless.
    /// A gap means the log has been tampered with or is corrupt.
    fn verify_sequence_integrity(&self) -> Result<()> {
        let gap_count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM (
                 SELECT seq, LAG(seq, 1, 0) OVER (ORDER BY seq) AS prev
                 FROM events
             ) WHERE seq - prev > 1",
                [],
                |row| row.get(0),
            )
            .context("checking sequence integrity")?;

        if gap_count > 0 {
            bail!(
                "Event store integrity violation: {gap_count} sequence gap(s) detected. \
                 The event log may have been tampered with. \
                 Resolve before starting the daemon."
            );
        }
        Ok(())
    }

    /// Detailed diagnostic verification of event sequence integrity (Phase 8).
    pub fn verify_integrity(&self) -> Result<IntegrityReport> {
        let total_events: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap_or(0);
        let max_seq: Option<i64> = self
            .conn
            .query_row("SELECT MAX(seq) FROM events", [], |r| r.get(0))
            .unwrap_or(None);
        let gap_count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM (
                 SELECT seq, LAG(seq, 1, 0) OVER (ORDER BY seq) AS prev
                 FROM events
             ) WHERE seq - prev > 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let schema_ver_str: String = self
            .conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'version'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "1".to_string());
        let schema_version = schema_ver_str.parse().unwrap_or(1);

        Ok(IntegrityReport {
            total_events: total_events as u64,
            max_seq: max_seq.unwrap_or(0) as u64,
            gap_count: gap_count as u64,
            schema_version,
            is_valid: gap_count == 0,
        })
    }

    /// Append an event. Assigns sequence number and computes SHA-256 hash chain.
    pub fn append(&mut self, event: &mut AgentEvent) -> Result<u64> {
        let seq = self.last_seq + 1;
        let prev_hash = self.last_hash.clone();
        let kind_str = event.kind.to_string();
        let payload_str =
            serde_json::to_string(&event.payload).context("serialising event payload")?;
        let ts_str = event.timestamp.to_rfc3339();
        let session_id = event.session_id.as_ref().map(|id| id.0.as_str());

        let hash = compute_event_hash(&prev_hash, seq, &ts_str, &kind_str, &payload_str);

        self.conn.execute(
            "INSERT INTO events (seq, event_id, version, kind, session_id, payload, triggered_by, timestamp, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                seq as i64,
                event.id.0,
                event.version,
                kind_str,
                session_id,
                payload_str,
                event.triggered_by,
                ts_str,
                prev_hash,
                hash,
            ],
        )
        .context("appending event to store")?;

        event.seq = seq;
        event.prev_hash = Some(prev_hash);
        event.hash = Some(hash.clone());

        self.last_seq = seq;
        self.last_hash = hash;

        Ok(seq)
    }

    /// Append multiple events in a single atomic transaction for high throughput.
    pub fn append_batch(&mut self, events: &mut [AgentEvent]) -> Result<()> {
        let mut cur_seq = self.last_seq;
        let mut cur_hash = self.last_hash.clone();

        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events (seq, event_id, version, kind, session_id, payload, triggered_by, timestamp, prev_hash, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for event in events.iter_mut() {
                cur_seq += 1;
                let prev_hash = cur_hash.clone();
                let kind_str = event.kind.to_string();
                let payload_str =
                    serde_json::to_string(&event.payload).context("serialising event payload")?;
                let ts_str = event.timestamp.to_rfc3339();
                let session_id = event.session_id.as_ref().map(|id| id.0.as_str());

                let hash = compute_event_hash(&prev_hash, cur_seq, &ts_str, &kind_str, &payload_str);

                stmt.execute(params![
                    cur_seq as i64,
                    event.id.0,
                    event.version,
                    kind_str,
                    session_id,
                    payload_str,
                    event.triggered_by,
                    ts_str,
                    prev_hash,
                    hash,
                ])?;

                event.seq = cur_seq;
                event.prev_hash = Some(prev_hash);
                event.hash = Some(hash.clone());
                cur_hash = hash;
            }
        }
        tx.commit()?;

        self.last_seq = cur_seq;
        self.last_hash = cur_hash;
        Ok(())
    }

    /// Return the current maximum sequence number (0 if the store is empty).
    pub fn max_seq(&self) -> Result<u64> {
        let seq: Option<i64> = self
            .conn
            .query_row("SELECT MAX(seq) FROM events", [], |row| row.get(0))
            .context("querying max seq")?;
        Ok(seq.unwrap_or(0) as u64)
    }

    /// Return all events, in sequence order, optionally starting from `since_seq`.
    pub fn query(
        &self,
        since_seq: u64,
        session_id: Option<&Id>,
        limit: Option<u64>,
    ) -> Result<Vec<AgentEvent>> {
        let limit_clause = limit.map(|l| format!("LIMIT {l}")).unwrap_or_default();

        let rows = if let Some(sid) = session_id {
            let sql = format!(
                "SELECT seq, event_id, version, kind, session_id, payload, triggered_by, timestamp, prev_hash, hash \
                 FROM events WHERE seq > ?1 AND session_id = ?2 ORDER BY seq {limit_clause}"
            );
            let mut stmt = self.conn.prepare(&sql).context("preparing query")?;
            let rows = stmt
                .query_map(params![since_seq as i64, sid.0], row_to_event)
                .context("querying events")?
                .collect::<Result<Vec<_>, _>>()
                .context("collecting events")?;
            rows
        } else {
            let sql = format!(
                "SELECT seq, event_id, version, kind, session_id, payload, triggered_by, timestamp, prev_hash, hash \
                 FROM events WHERE seq > ?1 ORDER BY seq {limit_clause}"
            );
            let mut stmt = self.conn.prepare(&sql).context("preparing query")?;
            let rows = stmt
                .query_map(params![since_seq as i64], row_to_event)
                .context("querying events")?
                .collect::<Result<Vec<_>, _>>()
                .context("collecting events")?;
            rows
        };

        Ok(rows)
    }

    /// Return a single event by sequence number.
    pub fn get_by_seq(&self, seq: u64) -> Result<Option<AgentEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, event_id, version, kind, session_id, payload, triggered_by, timestamp, prev_hash, hash \
             FROM events WHERE seq = ?1",
        )?;
        let mut rows = stmt
            .query_map(params![seq as i64], row_to_event)
            .context("querying event by seq")?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Save a derived-state snapshot bound to the given event sequence number.
    pub fn save_snapshot(&mut self, event_seq: u64, payload: &serde_json::Value) -> Result<()> {
        let payload_str = serde_json::to_string(payload).context("serialising snapshot")?;
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO snapshots (event_seq, payload, created_at) VALUES (?1, ?2, ?3)",
                params![event_seq as i64, payload_str, now],
            )
            .context("saving snapshot")?;
        Ok(())
    }

    /// Load the latest snapshot, returning the event_seq it was taken at and
    /// the payload. Returns `None` if no snapshot exists.
    pub fn load_latest_snapshot(&self) -> Result<Option<(u64, serde_json::Value)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_seq, payload FROM snapshots ORDER BY event_seq DESC LIMIT 1")?;
        let mut rows = stmt.query_map([], |row| {
            let seq: i64 = row.get(0)?;
            let payload_str: String = row.get(1)?;
            Ok((seq as u64, payload_str))
        })?;
        match rows.next() {
            Some(r) => {
                let (seq, payload_str) = r?;
                let payload: serde_json::Value =
                    serde_json::from_str(&payload_str).context("deserialising snapshot")?;
                Ok(Some((seq, payload)))
            }
            None => Ok(None),
        }
    }

    /// Verify cryptographic hash-chain integrity of the event store (F7 / ADR-010).
    pub fn verify_hash_chain(&self) -> Result<AuditIntegrityReport> {
        verify_connection_hash_chain(&self.conn)
    }

    /// Read-only static verification of an audit log SQLite database on disk.
    /// Safely opens the database in read-only mode without modifying schemas or bailing on sequence gaps.
    pub fn verify_audit_log_at_path(path: &Path) -> Result<AuditIntegrityReport> {
        if !path.exists() {
            bail!("Database file does not exist: {}", path.display());
        }

        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)
            .with_context(|| format!("opening sqlite db read-only: {}", path.display()))?;

        verify_connection_hash_chain(&conn)
    }
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentEvent> {
    let seq: i64 = row.get(0)?;
    let event_id: String = row.get(1)?;
    let version: u16 = row.get(2)?;
    let kind_str: String = row.get(3)?;
    let session_id: Option<String> = row.get(4)?;
    let payload_str: String = row.get(5)?;
    let triggered_by: String = row.get(6)?;
    let timestamp_str: String = row.get(7)?;
    let prev_hash: Option<String> = row.get(8)?;
    let hash: Option<String> = row.get(9)?;

    let kind: EventKind = serde_json::from_value(serde_json::Value::String(kind_str.clone()))
        .unwrap_or_else(|_| EventKind::DaemonStarted); // fallback for unknown kinds during migration

    let payload: serde_json::Value =
        serde_json::from_str(&payload_str).unwrap_or(serde_json::Value::Null);

    let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    Ok(AgentEvent {
        seq: seq as u64,
        id: Id(event_id),
        version,
        kind,
        session_id: session_id.map(Id),
        payload,
        triggered_by,
        timestamp,
        prev_hash,
        hash,
    })
}

/// Internal core verification algorithm shared by live `EventStore` and static read-only inspection.
fn verify_connection_hash_chain(conn: &Connection) -> Result<AuditIntegrityReport> {
    let has_events: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='events'",
            [],
            |r| r.get(0),
        )
        .map(|c: i64| c > 0)
        .unwrap_or(false);

    if !has_events {
        return Ok(AuditIntegrityReport {
            is_valid: true,
            total_events: 0,
            verified_events: 0,
            first_seq: None,
            last_seq: None,
            genesis_hash: None,
            latest_hash: None,
            violations: Vec::new(),
        });
    }

    // Check if hash columns exist
    let mut has_hash_col = false;
    let mut has_prev_hash_col = false;
    {
        let mut pragma_stmt = conn.prepare("PRAGMA table_info(events)")?;
        let col_rows = pragma_stmt.query_map([], |r| r.get::<_, String>(1))?;
        for col in col_rows {
            let col = col?;
            if col == "hash" {
                has_hash_col = true;
            } else if col == "prev_hash" {
                has_prev_hash_col = true;
            }
        }
    }

    if !has_hash_col || !has_prev_hash_col {
        let total_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap_or(0);
        if total_count == 0 {
            return Ok(AuditIntegrityReport {
                is_valid: true,
                total_events: 0,
                verified_events: 0,
                first_seq: None,
                last_seq: None,
                genesis_hash: None,
                latest_hash: None,
                violations: Vec::new(),
            });
        } else {
            return Ok(AuditIntegrityReport {
                is_valid: false,
                total_events: total_count as u64,
                verified_events: 0,
                first_seq: Some(1),
                last_seq: Some(total_count as u64),
                genesis_hash: None,
                latest_hash: None,
                violations: vec![IntegrityViolation::InvalidGenesis {
                    seq: 1,
                    expected_prev_hash: GENESIS_PREV_HASH.to_string(),
                    actual_prev_hash: "missing hash columns (legacy v1 schema)".to_string(),
                }],
            });
        }
    }

    let mut violations = Vec::new();
    let mut total_events: u64 = 0;
    let mut verified_events: u64 = 0;
    let mut first_seq: Option<u64> = None;
    let mut last_seq: Option<u64> = None;
    let mut genesis_hash: Option<String> = None;
    let mut latest_hash: Option<String> = None;

    let mut expected_seq: u64 = 1;
    let mut expected_prev_hash = GENESIS_PREV_HASH.to_string();

    let mut stmt = conn.prepare(
        "SELECT seq, timestamp, kind, payload, prev_hash, hash
         FROM events
         ORDER BY seq ASC",
    )?;

    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        let seq = seq as u64;
        let ts_str: String = row.get(1)?;
        let kind_str: String = row.get(2)?;
        let payload_str: String = row.get(3)?;
        let actual_prev_hash: Option<String> = row.get(4)?;
        let actual_hash: Option<String> = row.get(5)?;

        if first_seq.is_none() {
            first_seq = Some(seq);
        }
        last_seq = Some(seq);
        total_events += 1;

        let mut row_valid = true;

        // Check 1: Sequence Continuity (SequenceGap)
        if seq != expected_seq {
            violations.push(IntegrityViolation::SequenceGap {
                expected_seq,
                actual_seq: seq,
            });
            row_valid = false;
        }

        let prev_hash_val = actual_prev_hash.unwrap_or_default();
        let hash_val = actual_hash.unwrap_or_default();

        // Check 2: Genesis Anchor (InvalidGenesis)
        if seq == 1 {
            if prev_hash_val != GENESIS_PREV_HASH {
                violations.push(IntegrityViolation::InvalidGenesis {
                    seq: 1,
                    expected_prev_hash: GENESIS_PREV_HASH.to_string(),
                    actual_prev_hash: prev_hash_val.clone(),
                });
                row_valid = false;
            }
        } else {
            // Check 3: Hash Chain Linkage (BrokenChain)
            if prev_hash_val != expected_prev_hash {
                violations.push(IntegrityViolation::BrokenChain {
                    seq,
                    expected_prev_hash: expected_prev_hash.clone(),
                    actual_prev_hash: prev_hash_val.clone(),
                });
                row_valid = false;
            }
        }

        // Check 4: Cryptographic Hash Computation (HashMismatch)
        let computed_hash = compute_event_hash(
            &prev_hash_val,
            seq,
            &ts_str,
            &kind_str,
            &payload_str,
        );

        if hash_val != computed_hash {
            violations.push(IntegrityViolation::HashMismatch {
                seq,
                expected_hash: computed_hash,
                actual_hash: hash_val.clone(),
            });
            row_valid = false;
        }

        if row_valid {
            verified_events += 1;
        }

        if genesis_hash.is_none() && !hash_val.is_empty() {
            genesis_hash = Some(hash_val.clone());
        }
        latest_hash = Some(hash_val.clone());

        // Error isolation / resynchronization:
        // Set expected_prev_hash to stored hash_val to avoid cascading errors to subsequent rows
        expected_prev_hash = hash_val;
        expected_seq = seq + 1;
    }

    // Check 5: Tail Truncation Check against snapshots table
    let has_snapshots: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='snapshots'",
            [],
            |r| r.get(0),
        )
        .map(|c: i64| c > 0)
        .unwrap_or(false);

    if has_snapshots {
        let max_snapshot_seq: Option<i64> = conn
            .query_row("SELECT MAX(event_seq) FROM snapshots", [], |r| r.get(0))
            .ok()
            .flatten();

        if let (Some(max_snap), Some(last)) = (max_snapshot_seq, last_seq) {
            if (max_snap as u64) > last {
                violations.push(IntegrityViolation::SequenceGap {
                    expected_seq: max_snap as u64,
                    actual_seq: last,
                });
            }
        } else if let (Some(max_snap), None) = (max_snapshot_seq, last_seq) {
            if max_snap > 0 {
                violations.push(IntegrityViolation::SequenceGap {
                    expected_seq: max_snap as u64,
                    actual_seq: 0,
                });
            }
        }
    }

    let is_valid = violations.is_empty();

    Ok(AuditIntegrityReport {
        is_valid,
        total_events,
        verified_events,
        first_seq,
        last_seq,
        genesis_hash,
        latest_hash,
        violations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentEvent, EventKind, Id};
    use serde_json::json;

    fn make_event(kind: EventKind, session_id: Option<Id>) -> AgentEvent {
        AgentEvent::new(kind, session_id, json!({"test": true}), "system")
    }

    #[test]
    fn append_and_query() {
        let mut store = EventStore::open_in_memory().unwrap();

        let mut e1 = make_event(EventKind::SessionCreated, Some(Id::from("s1")));
        let mut e2 = make_event(EventKind::SessionStarted, Some(Id::from("s1")));

        let seq1 = store.append(&mut e1).unwrap();
        let seq2 = store.append(&mut e2).unwrap();

        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);

        let events = store.query(0, None, None).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].seq, 2);
    }

    #[test]
    fn query_by_session() {
        let mut store = EventStore::open_in_memory().unwrap();

        let mut e1 = make_event(EventKind::SessionCreated, Some(Id::from("s1")));
        let mut e2 = make_event(EventKind::SessionCreated, Some(Id::from("s2")));
        let mut e3 = make_event(EventKind::SessionStarted, Some(Id::from("s1")));

        store.append(&mut e1).unwrap();
        store.append(&mut e2).unwrap();
        store.append(&mut e3).unwrap();

        let s1_events = store.query(0, Some(&Id::from("s1")), None).unwrap();
        assert_eq!(s1_events.len(), 2);

        let s2_events = store.query(0, Some(&Id::from("s2")), None).unwrap();
        assert_eq!(s2_events.len(), 1);
    }

    #[test]
    fn query_since_seq() {
        let mut store = EventStore::open_in_memory().unwrap();
        for i in 0..5 {
            let mut e = make_event(EventKind::DaemonStarted, None);
            e.payload = json!({"i": i});
            store.append(&mut e).unwrap();
        }
        let events = store.query(3, None, None).unwrap();
        assert_eq!(events.len(), 2); // seq 4 and 5
    }

    #[test]
    fn max_seq_empty() {
        let store = EventStore::open_in_memory().unwrap();
        assert_eq!(store.max_seq().unwrap(), 0);
    }

    #[test]
    fn snapshot_round_trip() {
        let mut store = EventStore::open_in_memory().unwrap();
        let payload = json!({"sessions": [], "accounts": []});
        store.save_snapshot(42, &payload).unwrap();

        let loaded = store.load_latest_snapshot().unwrap().unwrap();
        assert_eq!(loaded.0, 42);
        assert_eq!(loaded.1, payload);
    }

    #[test]
    fn get_by_seq() {
        let mut store = EventStore::open_in_memory().unwrap();
        let mut e = make_event(EventKind::SessionCreated, Some(Id::from("s1")));
        let seq = store.append(&mut e).unwrap();

        let loaded = store.get_by_seq(seq).unwrap().unwrap();
        assert_eq!(loaded.seq, seq);
        assert_eq!(loaded.session_id, Some(Id::from("s1")));
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        {
            let mut store = EventStore::open(&db_path).unwrap();
            let mut e = make_event(EventKind::SessionCreated, Some(Id::from("s1")));
            store.append(&mut e).unwrap();
        }

        // Reopen — should reconstruct successfully
        let store = EventStore::open(&db_path).unwrap();
        let events = store.query(0, None, None).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].hash.is_some());
    }

    #[test]
    fn hash_chain_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        {
            let mut store = EventStore::open(&db_path).unwrap();
            let mut e1 = make_event(EventKind::SessionCreated, Some(Id::from("s1")));
            store.append(&mut e1).unwrap();
        }

        {
            let mut store = EventStore::open(&db_path).unwrap();
            let mut e2 = make_event(EventKind::SessionStarted, Some(Id::from("s1")));
            store.append(&mut e2).unwrap();
            let report = store.verify_hash_chain().unwrap();
            assert!(report.is_valid);
            assert_eq!(report.total_events, 2);
        }
    }
}

#[cfg(test)]
mod audit_integrity_tests {
    use super::*;
    use crate::types::{AgentEvent, EventKind, Id, IntegrityViolation};
    use serde_json::json;

    fn make_test_event(kind: EventKind, session_id: Option<Id>, payload: serde_json::Value) -> AgentEvent {
        AgentEvent::new(kind, session_id, payload, "system")
    }

    #[test]
    fn test_hash_formula_determinism() {
        let prev_hash = GENESIS_PREV_HASH;
        let seq = 1;
        let timestamp = "2026-11-18T12:00:00Z";
        let kind = "session.created";
        let payload = r#"{"model":"claude"}"#;

        let hash1 = compute_event_hash(prev_hash, seq, timestamp, kind, payload);
        let hash2 = compute_event_hash(prev_hash, seq, timestamp, kind, payload);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));

        // Different seq produces different hash
        let hash3 = compute_event_hash(prev_hash, 2, timestamp, kind, payload);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_verify_empty_table() {
        let store = EventStore::open_in_memory().unwrap();
        let report = store.verify_hash_chain().unwrap();
        assert!(report.is_valid);
        assert_eq!(report.total_events, 0);
        assert_eq!(report.verified_events, 0);
        assert_eq!(report.first_seq, None);
        assert_eq!(report.last_seq, None);
        assert_eq!(report.genesis_hash, None);
        assert_eq!(report.latest_hash, None);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn test_verify_single_genesis_event() {
        let mut store = EventStore::open_in_memory().unwrap();
        let mut e = make_test_event(EventKind::SessionCreated, Some(Id::from("s1")), json!({"init": true}));
        let seq = store.append(&mut e).unwrap();

        assert_eq!(seq, 1);
        assert_eq!(e.prev_hash.as_deref(), Some(GENESIS_PREV_HASH));
        assert!(e.hash.is_some());

        let report = store.verify_hash_chain().unwrap();
        assert!(report.is_valid);
        assert_eq!(report.total_events, 1);
        assert_eq!(report.verified_events, 1);
        assert_eq!(report.first_seq, Some(1));
        assert_eq!(report.last_seq, Some(1));
        assert_eq!(report.genesis_hash, e.hash);
        assert_eq!(report.latest_hash, e.hash);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn test_verify_unbroken_chain() {
        let mut store = EventStore::open_in_memory().unwrap();
        let mut prev_h = GENESIS_PREV_HASH.to_string();

        for i in 1..=10 {
            let mut e = make_test_event(EventKind::DaemonStarted, None, json!({"step": i}));
            store.append(&mut e).unwrap();
            assert_eq!(e.prev_hash.as_deref(), Some(prev_h.as_str()));
            prev_h = e.hash.unwrap();
        }

        let report = store.verify_hash_chain().unwrap();
        assert!(report.is_valid);
        assert_eq!(report.total_events, 10);
        assert_eq!(report.verified_events, 10);
        assert_eq!(report.first_seq, Some(1));
        assert_eq!(report.last_seq, Some(10));
        assert_eq!(report.latest_hash, Some(prev_h));
        assert!(report.violations.is_empty());
    }

    #[test]
    fn test_tamper_modify_payload() {
        let mut store = EventStore::open_in_memory().unwrap();
        for i in 1..=5 {
            let mut e = make_test_event(EventKind::DaemonStarted, None, json!({"step": i}));
            store.append(&mut e).unwrap();
        }

        // Alter payload of seq 3 in place
        store
            .conn
            .execute("UPDATE events SET payload = ?1 WHERE seq = 3", params![r#"{"tampered":true}"#])
            .unwrap();

        let report = store.verify_hash_chain().unwrap();
        assert!(!report.is_valid);
        assert_eq!(report.total_events, 5);
        assert_eq!(report.verified_events, 4); // 1, 2, 4, 5 verified
        assert_eq!(report.violations.len(), 1);
        match &report.violations[0] {
            IntegrityViolation::HashMismatch { seq, .. } => {
                assert_eq!(*seq, 3);
            }
            other => panic!("expected HashMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_tamper_modify_payload_and_forge_hash() {
        let mut store = EventStore::open_in_memory().unwrap();
        for i in 1..=5 {
            let mut e = make_test_event(EventKind::DaemonStarted, None, json!({"step": i}));
            store.append(&mut e).unwrap();
        }

        // Read row 3 metadata
        let (prev_hash, ts, kind): (String, String, String) = store
            .conn
            .query_row("SELECT prev_hash, timestamp, kind FROM events WHERE seq = 3", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();

        let forged_payload = r#"{"tampered":true}"#;
        let forged_hash = compute_event_hash(&prev_hash, 3, &ts, &kind, forged_payload);

        // Update row 3 with forged payload and recomputed hash
        store
            .conn
            .execute(
                "UPDATE events SET payload = ?1, hash = ?2 WHERE seq = 3",
                params![forged_payload, forged_hash],
            )
            .unwrap();

        let report = store.verify_hash_chain().unwrap();
        assert!(!report.is_valid);
        // Row 3 passes HashMismatch because hash matches forged payload,
        // but Row 4 detects BrokenChain because its prev_hash doesn't match forged_hash!
        assert_eq!(report.violations.len(), 1);
        match &report.violations[0] {
            IntegrityViolation::BrokenChain { seq, .. } => {
                assert_eq!(*seq, 4);
            }
            other => panic!("expected BrokenChain at seq 4, got {:?}", other),
        }
    }

    #[test]
    fn test_tamper_delete_intermediate_row() {
        let mut store = EventStore::open_in_memory().unwrap();
        for i in 1..=5 {
            let mut e = make_test_event(EventKind::DaemonStarted, None, json!({"step": i}));
            store.append(&mut e).unwrap();
        }

        store.conn.execute("DELETE FROM events WHERE seq = 3", []).unwrap();

        let report = store.verify_hash_chain().unwrap();
        assert!(!report.is_valid);
        assert_eq!(report.total_events, 4);
        assert_eq!(report.violations.len(), 2);

        let has_seq_gap = report.violations.iter().any(|v| match v {
            IntegrityViolation::SequenceGap { expected_seq, actual_seq } => {
                *expected_seq == 3 && *actual_seq == 4
            }
            _ => false,
        });
        let has_broken_chain = report.violations.iter().any(|v| match v {
            IntegrityViolation::BrokenChain { seq, .. } => *seq == 4,
            _ => false,
        });

        assert!(has_seq_gap, "expected SequenceGap at seq 4");
        assert!(has_broken_chain, "expected BrokenChain at seq 4");
    }

    #[test]
    fn test_tamper_delete_genesis_row() {
        let mut store = EventStore::open_in_memory().unwrap();
        for i in 1..=5 {
            let mut e = make_test_event(EventKind::DaemonStarted, None, json!({"step": i}));
            store.append(&mut e).unwrap();
        }

        store.conn.execute("DELETE FROM events WHERE seq = 1", []).unwrap();

        let report = store.verify_hash_chain().unwrap();
        assert!(!report.is_valid);
        assert_eq!(report.total_events, 4);
        assert_eq!(report.first_seq, Some(2));

        let has_seq_gap = report.violations.iter().any(|v| match v {
            IntegrityViolation::SequenceGap { expected_seq, actual_seq } => {
                *expected_seq == 1 && *actual_seq == 2
            }
            _ => false,
        });
        assert!(has_seq_gap, "expected SequenceGap for missing genesis");
    }

    #[test]
    fn test_tamper_tail_truncation_with_snapshot() {
        let mut store = EventStore::open_in_memory().unwrap();
        for i in 1..=5 {
            let mut e = make_test_event(EventKind::DaemonStarted, None, json!({"step": i}));
            store.append(&mut e).unwrap();
        }

        // Save a snapshot anchored at event_seq 5
        store.save_snapshot(5, &json!({"state": "ok"})).unwrap();

        // Delete events 4 and 5 (truncating the tail)
        store.conn.execute("DELETE FROM events WHERE seq > 3", []).unwrap();

        let report = store.verify_hash_chain().unwrap();
        assert!(!report.is_valid);
        assert_eq!(report.total_events, 3);
        assert_eq!(report.last_seq, Some(3));

        let has_truncation_gap = report.violations.iter().any(|v| match v {
            IntegrityViolation::SequenceGap { expected_seq, actual_seq } => {
                *expected_seq == 5 && *actual_seq == 3
            }
            _ => false,
        });
        assert!(has_truncation_gap, "expected SequenceGap detecting tail truncation");
    }

    #[test]
    fn test_verify_audit_log_at_path_corrupted_db_does_not_bail() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("tampered_events.db");

        {
            let mut store = EventStore::open(&db_path).unwrap();
            for i in 1..=5 {
                let mut e = make_test_event(EventKind::DaemonStarted, None, json!({"step": i}));
                store.append(&mut e).unwrap();
            }
            // Introduce a sequence gap
            store.conn.execute("DELETE FROM events WHERE seq = 3", []).unwrap();
        }

        // Direct static verification must succeed with an Ok(report) where is_valid == false,
        // and must NOT panic or bail!
        let report = EventStore::verify_audit_log_at_path(&db_path).unwrap();
        assert!(!report.is_valid);
        assert_eq!(report.total_events, 4);
        assert!(!report.violations.is_empty());
    }

    #[test]
    fn test_append_batch_hash_chaining() {
        let mut store = EventStore::open_in_memory().unwrap();
        let mut events = (1..=5)
            .map(|i| make_test_event(EventKind::DaemonStarted, None, json!({"batch_idx": i})))
            .collect::<Vec<_>>();

        store.append_batch(&mut events).unwrap();

        assert_eq!(events[0].seq, 1);
        assert_eq!(events[0].prev_hash.as_deref(), Some(GENESIS_PREV_HASH));
        assert!(events[0].hash.is_some());

        for i in 1..5 {
            assert_eq!(events[i].seq, (i + 1) as u64);
            assert_eq!(events[i].prev_hash, events[i - 1].hash);
            assert!(events[i].hash.is_some());
        }

        let report = store.verify_hash_chain().unwrap();
        assert!(report.is_valid);
        assert_eq!(report.total_events, 5);
        assert_eq!(report.verified_events, 5);
    }

    #[test]
    fn test_v1_to_v2_migration_and_backfill() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("v1_events.db");

        // Manually construct a v1 database without prev_hash or hash columns
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO schema_meta (key, value) VALUES ('version', '1');
                 CREATE TABLE events (
                     seq INTEGER PRIMARY KEY AUTOINCREMENT,
                     event_id TEXT NOT NULL UNIQUE,
                     version INTEGER NOT NULL DEFAULT 1,
                     kind TEXT NOT NULL,
                     session_id TEXT,
                     payload TEXT NOT NULL,
                     triggered_by TEXT NOT NULL,
                     timestamp TEXT NOT NULL
                 );",
            )
            .unwrap();

            // Insert 3 unhashed events
            for i in 1..=3 {
                let ts = chrono::Utc::now().to_rfc3339();
                conn.execute(
                    "INSERT INTO events (seq, event_id, version, kind, session_id, payload, triggered_by, timestamp)
                     VALUES (?1, ?2, 1, 'daemon.started', NULL, '{\"legacy\":true}', 'system', ?3)",
                    params![i, format!("evt_{i}"), ts],
                )
                .unwrap();
            }
        }

        // Open with EventStore::open — should trigger automatic v1 -> v2 migration & backfill
        let mut store = EventStore::open(&db_path).unwrap();
        let report = store.verify_hash_chain().unwrap();
        assert!(report.is_valid);
        assert_eq!(report.total_events, 3);
        assert_eq!(report.verified_events, 3);
        assert_eq!(report.first_seq, Some(1));
        assert_eq!(report.last_seq, Some(3));

        // Append a new event on top of migrated chain
        let mut new_e = make_test_event(EventKind::SessionCreated, Some(Id::from("s1")), json!({"new": true}));
        let seq = store.append(&mut new_e).unwrap();
        assert_eq!(seq, 4);

        let report_after = store.verify_hash_chain().unwrap();
        assert!(report_after.is_valid);
        assert_eq!(report_after.total_events, 4);
    }
}
