"""SQLite persistence for local investigation cases and audit history."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

CASE_STATUSES = ("Open", "Under Review", "Escalated", "Closed")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _dataset_id(transactions: pd.DataFrame) -> str:
    relevant = {
        "txn_id", "timestamp", "sender", "receiver", "amount", "channel",
        "sender_country", "receiver_country", "sender_is_customer",
        "receiver_is_customer", "typology",
    }
    columns = sorted(relevant.intersection(transactions.columns))
    canonical = transactions[columns].sort_values("txn_id", kind="stable").reset_index(drop=True)
    material = pd.util.hash_pandas_object(canonical, index=False).values.tobytes()
    return hashlib.sha256(material).hexdigest()[:20]


def _case_id(dataset_id: str, customer: str, rule: str, txn_ids: list[str]) -> str:
    material = "\0".join((dataset_id, customer, rule, *sorted(set(txn_ids))))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


class CaseStore:
    """Persist alert snapshots, transaction evidence, notes, and case events."""

    def __init__(self, path: str | Path = "traceledger.db"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    dataset_id TEXT NOT NULL DEFAULT '',
                    customer TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    strength REAL NOT NULL,
                    amount REAL NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT,
                    txn_ids TEXT NOT NULL,
                    suspicious_txn_ids TEXT NOT NULL DEFAULT '[]',
                    risk_score REAL NOT NULL,
                    rule_score REAL NOT NULL,
                    anomaly REAL NOT NULL,
                    profile TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Open',
                    assigned_to TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS transactions (
                    dataset_id TEXT NOT NULL,
                    txn_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    receiver TEXT NOT NULL,
                    amount REAL NOT NULL,
                    channel TEXT NOT NULL,
                    sender_country TEXT NOT NULL,
                    receiver_country TEXT NOT NULL,
                    PRIMARY KEY(dataset_id, txn_id)
                );
                CREATE TABLE IF NOT EXISTS datasets (
                    dataset_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    dataset_id TEXT NOT NULL UNIQUE,
                    scanned_at TEXT NOT NULL,
                    transaction_count INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS notes (
                    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    investigator TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    old_value TEXT NOT NULL,
                    new_value TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cases_customer ON cases(customer);
                CREATE INDEX IF NOT EXISTS idx_notes_case ON notes(case_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_events_case ON audit_events(case_id, created_at);
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(cases)")}
            if "suspicious_txn_ids" not in columns:
                db.execute(
                    "ALTER TABLE cases ADD COLUMN suspicious_txn_ids TEXT NOT NULL DEFAULT '[]'"
                )
            if "dataset_id" not in columns:
                db.execute(
                    "ALTER TABLE cases ADD COLUMN dataset_id TEXT NOT NULL DEFAULT 'legacy'"
                )
            transaction_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(transactions)")
            }
            transaction_primary_key = {
                row["name"]: row["pk"]
                for row in db.execute("PRAGMA table_info(transactions)")
            }
            if (
                transaction_primary_key.get("dataset_id") != 1
                or transaction_primary_key.get("txn_id") != 2
            ):
                db.execute("ALTER TABLE transactions RENAME TO transactions_legacy")
                db.execute("""
                    CREATE TABLE transactions (
                        dataset_id TEXT NOT NULL,
                        txn_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        sender TEXT NOT NULL,
                        receiver TEXT NOT NULL,
                        amount REAL NOT NULL,
                        channel TEXT NOT NULL,
                        sender_country TEXT NOT NULL,
                        receiver_country TEXT NOT NULL,
                        PRIMARY KEY(dataset_id, txn_id)
                    )
                """)
                if "dataset_id" in transaction_columns:
                    db.execute("""
                        INSERT INTO transactions
                        SELECT dataset_id, txn_id, timestamp, sender, receiver, amount,
                               channel, sender_country, receiver_country
                        FROM transactions_legacy
                    """)
                else:
                    db.execute("""
                        INSERT INTO transactions
                        SELECT 'legacy', txn_id, timestamp, sender, receiver, amount,
                               channel, sender_country, receiver_country
                        FROM transactions_legacy
                    """)
                db.execute("DROP TABLE transactions_legacy")
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_transactions_sender
                ON transactions(dataset_id, sender, timestamp)
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_transactions_receiver
                ON transactions(dataset_id, receiver, timestamp)
            """)
            for row in db.execute(
                """SELECT dataset_id, COUNT(*) AS n FROM transactions
                   GROUP BY dataset_id"""
            ):
                db.execute(
                    """INSERT OR IGNORE INTO datasets
                       (dataset_id, scanned_at, transaction_count) VALUES (?, ?, ?)""",
                    (row["dataset_id"], _now(), row["n"]),
                )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def ingest_result(self, result) -> int:
        """Store scan evidence and create one stable case per customer/rule."""
        now = _now()
        created = 0
        dataset_id = _dataset_id(result.transactions)
        with self._connect() as db:
            transactions = result.transactions
            db.execute(
                """INSERT INTO datasets(dataset_id, scanned_at, transaction_count)
                   VALUES (?, ?, ?)
                   ON CONFLICT(dataset_id) DO UPDATE SET
                   scanned_at=excluded.scanned_at,
                   transaction_count=excluded.transaction_count""",
                (dataset_id, now, len(transactions)),
            )
            db.executemany(
                """INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(dataset_id, txn_id) DO UPDATE SET
                   timestamp=excluded.timestamp, sender=excluded.sender,
                   receiver=excluded.receiver, amount=excluded.amount,
                   channel=excluded.channel, sender_country=excluded.sender_country,
                   receiver_country=excluded.receiver_country""",
                [
                    (
                        dataset_id, str(row.txn_id), row.timestamp.isoformat(), str(row.sender),
                        str(row.receiver), float(row.amount), str(row.channel),
                        str(row.sender_country), str(row.receiver_country),
                    )
                    for row in transactions.itertuples(index=False)
                ],
            )
            for alert in result.alerts.itertuples(index=False):
                customer = str(alert.customer)
                txn_ids = [str(value) for value in alert.txn_ids]
                case_id = _case_id(dataset_id, customer, str(alert.rule), txn_ids)
                profile = result.customers.loc[customer]
                profile_json = json.dumps({
                    "transaction_count": int(profile["transaction_count"]),
                    "value_in": float(profile["value_in"]),
                    "value_out": float(profile["value_out"]),
                    "high_risk_transaction_count": int(profile["high_risk_transaction_count"]),
                    "high_risk_value": float(profile["high_risk_value"]),
                    "counterparty_count": int(profile["counterparty_count"]),
                    "activity_frequency_change": float(profile["activity_frequency_change"]),
                    "rule_evidence": str(profile["rule_evidence"]),
                    "anomaly_explanation": str(profile["anomaly_explanation"]),
                })
                is_new_case = db.execute(
                    "SELECT 1 FROM cases WHERE case_id = ?", (case_id,)
                ).fetchone() is None
                db.execute(
                    """INSERT INTO cases (
                        case_id, dataset_id, customer, rule, detail, strength, amount,
                        first_seen, last_seen, txn_ids, suspicious_txn_ids, risk_score,
                        rule_score, anomaly, profile, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(case_id) DO UPDATE SET
                        detail=excluded.detail, strength=excluded.strength,
                        amount=excluded.amount, first_seen=excluded.first_seen,
                        last_seen=excluded.last_seen, risk_score=excluded.risk_score,
                        suspicious_txn_ids=excluded.suspicious_txn_ids,
                        rule_score=excluded.rule_score, anomaly=excluded.anomaly,
                        profile=excluded.profile, updated_at=excluded.updated_at""",
                    (
                        case_id, dataset_id, customer, str(alert.rule), str(alert.detail),
                        float(alert.strength), float(alert.amount),
                        alert.first_seen.isoformat() if pd.notna(alert.first_seen) else "",
                        alert.last_seen.isoformat() if pd.notna(alert.last_seen) else "",
                        json.dumps(txn_ids), json.dumps([
                            str(value) for value in alert.suspicious_txn_ids
                        ]), float(profile["risk_score"]),
                        float(profile["rule_score"]), float(profile["anomaly"]),
                        profile_json, now, now,
                    ),
                )
                if is_new_case:
                    created += 1
                    db.execute(
                        """INSERT INTO audit_events
                           (case_id, actor, action, old_value, new_value, created_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (case_id, "TraceLedger", "Case created", "", "Open", now),
                    )
        return created

    def list_cases(self, status: str | None = None, limit: int = 200) -> list[dict]:
        with self._connect() as db:
            if status in CASE_STATUSES:
                rows = db.execute(
                    """SELECT * FROM cases WHERE status = ?
                       ORDER BY CASE status WHEN 'Escalated' THEN 0
                       WHEN 'Open' THEN 1 WHEN 'Under Review' THEN 2 ELSE 3 END,
                       risk_score DESC, updated_at DESC LIMIT ?""",
                    (status, limit),
                ).fetchall()
            else:
                rows = db.execute(
                    """SELECT * FROM cases
                       ORDER BY CASE status WHEN 'Escalated' THEN 0
                       WHEN 'Open' THEN 1 WHEN 'Under Review' THEN 2 ELSE 3 END,
                       risk_score DESC, updated_at DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
            return [self._case_dict(row) for row in rows]

    def get_case(self, case_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            return self._case_dict(row) if row else None

    @staticmethod
    def _case_dict(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["txn_ids"] = json.loads(item["txn_ids"])
        item["suspicious_txn_ids"] = json.loads(item["suspicious_txn_ids"])
        item["profile"] = json.loads(item["profile"])
        return item

    def transactions_for_case(
        self, txn_ids: list[str], dataset_id: str = "legacy"
    ) -> list[dict]:
        found = {}
        with self._connect() as db:
            for start in range(0, len(txn_ids), 500):
                batch = txn_ids[start:start + 500]
                if not batch:
                    continue
                placeholders = ",".join("?" for _ in batch)
                rows = db.execute(
                    f"""SELECT * FROM transactions WHERE dataset_id = ?
                        AND txn_id IN ({placeholders})""",
                    [dataset_id, *batch],
                ).fetchall()
                found.update({row["txn_id"]: dict(row) for row in rows})
        return [found[txn_id] for txn_id in txn_ids if txn_id in found]

    def customer_transactions(
        self, customer: str, dataset_id: str, limit: int = 200
    ) -> list[dict]:
        """Return the latest transactions involving a customer in one dataset."""
        with self._connect() as db:
            rows = db.execute(
                """SELECT * FROM transactions
                   WHERE dataset_id = ? AND (sender = ? OR receiver = ?)
                   ORDER BY timestamp DESC, txn_id DESC LIMIT ?""",
                (dataset_id, customer, customer, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def suspicious_transaction_ids(
        self, customer: str, dataset_id: str | None
    ) -> set[str]:
        """Return rule-evidence transaction IDs for one customer and dataset."""
        if dataset_id is None:
            return set()
        with self._connect() as db:
            rows = db.execute(
                """SELECT suspicious_txn_ids FROM cases
                   WHERE dataset_id = ? AND customer = ?""",
                (dataset_id, customer),
            ).fetchall()
        return {
            txn_id
            for row in rows
            for txn_id in json.loads(row["suspicious_txn_ids"])
        }

    def dashboard_data(self) -> dict:
        """Summarize the latest scan and recent case activity for the dashboard."""
        with self._connect() as db:
            latest = db.execute(
                """SELECT dataset_id, transaction_count FROM datasets
                   ORDER BY scanned_at DESC, dataset_seq DESC LIMIT 1"""
            ).fetchone()
            if latest is None:
                return {
                    "transactions": 0,
                    "alerts": 0,
                    "suspicious_customers": 0,
                    "risk_distribution": [],
                    "trends": [],
                    "recent_activity": [],
                }

            dataset_id = str(latest["dataset_id"])
            case_counts = db.execute(
                """SELECT COUNT(*) AS alerts, COUNT(DISTINCT customer) AS customers
                   FROM cases WHERE dataset_id = ?""",
                (dataset_id,),
            ).fetchone()
            risk_counts = db.execute(
                """SELECT
                       SUM(CASE WHEN risk_score < 34 THEN 1 ELSE 0 END) AS low,
                       SUM(CASE WHEN risk_score >= 34 AND risk_score < 67
                           THEN 1 ELSE 0 END) AS moderate,
                       SUM(CASE WHEN risk_score >= 67 THEN 1 ELSE 0 END) AS high
                   FROM cases WHERE dataset_id = ?""",
                (dataset_id,),
            ).fetchone()
            trend_rows = db.execute(
                """SELECT substr(COALESCE(NULLIF(last_seen, ''),
                           NULLIF(first_seen, ''), created_at), 1, 10) AS evidence_date,
                          COUNT(*) AS alerts, COUNT(DISTINCT customer) AS customers
                   FROM cases WHERE dataset_id = ?
                   GROUP BY evidence_date ORDER BY evidence_date DESC LIMIT 10""",
                (dataset_id,),
            ).fetchall()
            activity_rows = db.execute(
                """SELECT e.case_id, e.created_at, e.actor, e.action,
                          e.old_value, e.new_value, c.customer, c.rule
                   FROM audit_events AS e
                   JOIN cases AS c ON c.case_id = e.case_id
                   ORDER BY e.event_id DESC LIMIT 8"""
            ).fetchall()

        counts = {
            "low": int(risk_counts["low"] or 0),
            "moderate": int(risk_counts["moderate"] or 0),
            "high": int(risk_counts["high"] or 0),
        }
        total_cases = sum(counts.values())
        risk_distribution = [
            {"label": label, "key": key, "count": counts[key],
             "percent": round(counts[key] * 100 / total_cases) if total_cases else 0}
            for key, label in (
                ("low", "Low (0-33)"),
                ("moderate", "Moderate (34-66)"),
                ("high", "High (67-100)"),
            )
        ]
        trends = [dict(row) for row in reversed(trend_rows)]
        peak = max((int(row["alerts"]) for row in trends), default=0)
        for row in trends:
            row["bar_percent"] = round(int(row["alerts"]) * 100 / peak) if peak else 0

        return {
            "transactions": int(latest["transaction_count"]),
            "alerts": int(case_counts["alerts"]),
            "suspicious_customers": int(case_counts["customers"]),
            "risk_distribution": risk_distribution,
            "trends": trends,
            "recent_activity": [dict(row) for row in activity_rows],
        }

    def latest_dataset_id(self) -> str | None:
        with self._connect() as db:
            row = db.execute(
                """SELECT dataset_id FROM datasets
                   ORDER BY scanned_at DESC, dataset_seq DESC LIMIT 1"""
            ).fetchone()
        return str(row["dataset_id"]) if row else None

    def network_transactions(
        self, customer: str, flow: str, limit: int = 100, dataset_id: str | None = None
    ) -> list[dict]:
        dataset_id = dataset_id or self.latest_dataset_id()
        if dataset_id is None:
            return []
        if flow == "circular":
            with self._connect() as db:
                rows = db.execute(
                    """SELECT txn_ids FROM cases
                       WHERE dataset_id = ? AND customer = ? AND rule = 'round_trip'
                       ORDER BY updated_at DESC LIMIT 10""",
                    (dataset_id, customer),
                ).fetchall()
            ids = list(dict.fromkeys(
                txn_id for row in rows for txn_id in json.loads(row["txn_ids"])
            ))
            return self.transactions_for_case(ids[:limit], dataset_id)

        with self._connect() as db:
            if flow == "fan-in":
                query, params = (
                    """SELECT txn_id FROM transactions WHERE dataset_id = ? AND receiver = ?
                       ORDER BY timestamp DESC LIMIT ?""",
                    (dataset_id, customer, limit),
                )
            elif flow == "fan-out":
                query, params = (
                    """SELECT txn_id FROM transactions WHERE dataset_id = ? AND sender = ?
                       ORDER BY timestamp DESC LIMIT ?""",
                    (dataset_id, customer, limit),
                )
            else:
                query, params = (
                    """SELECT txn_id FROM transactions WHERE dataset_id = ?
                       AND (sender = ? OR receiver = ?)
                       ORDER BY timestamp DESC LIMIT ?""",
                    (dataset_id, customer, customer, limit),
                )
            rows = db.execute(query, params).fetchall()
        return self.transactions_for_case(
            [row["txn_id"] for row in rows], dataset_id
        )

    def update_case(
        self, case_id: str, status: str, assigned_to: str, actor: str
    ) -> bool:
        if status not in CASE_STATUSES:
            raise ValueError(f"Unknown case status: {status}")
        actor = actor.strip() or "Investigator"
        assigned_to = assigned_to.strip()
        now = _now()
        with self._connect() as db:
            row = db.execute(
                "SELECT status, assigned_to FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if row is None:
                return False
            db.execute(
                "UPDATE cases SET status = ?, assigned_to = ?, updated_at = ? WHERE case_id = ?",
                (status, assigned_to, now, case_id),
            )
            if row["status"] != status:
                db.execute(
                    """INSERT INTO audit_events
                       (case_id, actor, action, old_value, new_value, created_at)
                       VALUES (?, ?, 'Status changed', ?, ?, ?)""",
                    (case_id, actor, row["status"], status, now),
                )
            if row["assigned_to"] != assigned_to:
                db.execute(
                    """INSERT INTO audit_events
                       (case_id, actor, action, old_value, new_value, created_at)
                       VALUES (?, ?, 'Assignment changed', ?, ?, ?)""",
                    (case_id, actor, row["assigned_to"], assigned_to, now),
                )
        return True

    def add_note(self, case_id: str, investigator: str, note: str) -> bool:
        note = note.strip()
        investigator = investigator.strip() or "Investigator"
        if not note:
            raise ValueError("Investigation notes cannot be empty")
        now = _now()
        with self._connect() as db:
            exists = db.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if not exists:
                return False
            db.execute(
                "INSERT INTO notes(case_id, investigator, note, created_at) VALUES (?, ?, ?, ?)",
                (case_id, investigator, note, now),
            )
            db.execute(
                "UPDATE cases SET updated_at = ? WHERE case_id = ?", (now, case_id)
            )
            db.execute(
                """INSERT INTO audit_events
                   (case_id, actor, action, old_value, new_value, created_at)
                   VALUES (?, ?, 'Investigation note added', '', ?, ?)""",
                (case_id, investigator, note[:250], now),
            )
        return True

    def history(self, case_id: str) -> tuple[list[dict], list[dict]]:
        with self._connect() as db:
            notes = db.execute(
                "SELECT * FROM notes WHERE case_id = ? ORDER BY created_at DESC, note_id DESC",
                (case_id,),
            ).fetchall()
            events = db.execute(
                """SELECT * FROM audit_events WHERE case_id = ?
                   ORDER BY created_at DESC, event_id DESC""",
                (case_id,),
            ).fetchall()
        return [dict(row) for row in notes], [dict(row) for row in events]

    def customer_case_count(self, customer: str) -> int:
        with self._connect() as db:
            row = db.execute(
                "SELECT COUNT(*) AS n FROM cases WHERE customer = ?", (customer,)
            ).fetchone()
            return int(row["n"])

    def summary(self) -> dict[str, int]:
        with self._connect() as db:
            counts = {row["status"]: int(row["n"]) for row in db.execute(
                "SELECT status, COUNT(*) AS n FROM cases GROUP BY status"
            )}
        return {
            "total": sum(counts.values()),
            "open": counts.get("Open", 0),
            "review": counts.get("Under Review", 0),
            "escalated": counts.get("Escalated", 0),
            "closed": counts.get("Closed", 0),
        }
