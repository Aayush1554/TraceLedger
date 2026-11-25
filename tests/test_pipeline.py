import csv
import sqlite3
from io import BytesIO, StringIO

import pandas as pd

from traceledger import TYPOLOGIES, CaseStore, Monitor, RuleConfig, generate_transactions
from traceledger.cli import main


def test_generator_is_deterministic_and_labelled():
    a = generate_transactions(n_customers=200, days=30, seed=1)
    b = generate_transactions(n_customers=200, days=30, seed=1)
    pd.testing.assert_frame_equal(a, b)
    assert set(a["typology"]) - {"none"} == set(TYPOLOGIES)
    assert a["timestamp"].is_monotonic_increasing
    assert a["txn_id"].is_unique


def test_end_to_end_detection_quality():
    result = Monitor().run(generate_transactions(n_customers=600, seed=3))
    ev = result.evaluate()
    assert ev.loc["all alerts", "recall"] >= 0.9
    assert ev.loc["all alerts", "precision"] >= 0.6
    assert result.customers["risk_score"].between(0, 100).all()
    assert set(result.customers["status"]) <= {"alert", "anomaly_review", "clear"}
    assert result.customers["anomaly_explanation"].notna().all()
    assert {"transaction_count", "high_risk_value", "activity_frequency_change"} <= set(
        result.customers.columns
    )
    sweep = result.threshold_sweep((20, 50, 80))
    assert {"precision", "recall", "f1", "false_positive", "false_negative"} <= set(sweep.columns)
    assert result.confusion_matrix(50).shape == (2, 2)


def test_config_from_toml(tmp_path):
    p = tmp_path / "rules.toml"
    p.write_text('structuring_min_count = 5\nhigh_risk_countries = ["AA"]\n[weights]\nfan_in = 0.9\n')
    cfg = RuleConfig.from_toml(p)
    assert cfg.structuring_min_count == 5
    assert cfg.high_risk_countries == ("AA",)
    assert cfg.weights["fan_in"] == 0.9 and cfg.weights["structuring"] == 0.6
    assert cfg.dormant_inactive_days == 30


def test_csv_export_escapes_spreadsheet_formula_cells():
    from traceledger.web import _csv_safe

    assert _csv_safe(" =1+1") == "' =1+1"
    assert _csv_safe("ordinary account") == "ordinary account"


def test_cli_generate_and_scan(tmp_path, capsys):
    data = tmp_path / "t.csv"
    report = tmp_path / "r.html"
    alerts = tmp_path / "a.csv"
    assert main(["generate", "--out", str(data), "--customers", "200", "--days", "45"]) == 0
    assert main(["scan", str(data), "--report", str(report), "--alerts", str(alerts)]) == 0
    out = capsys.readouterr().out
    assert "Alerted customers" in out and "precision" in out
    assert "<table>" in report.read_text()
    assert len(pd.read_csv(alerts)) > 0


def test_case_store_persists_workflow_and_deduplicates_scan(tmp_path):
    result = Monitor().run(generate_transactions(n_customers=200, days=45, seed=6))
    store = CaseStore(tmp_path / "cases.db")
    created = store.ingest_result(result)
    cases = store.list_cases()
    assert created == len(result.alerts) == len(cases)
    assert store.ingest_result(result) == 0

    case = cases[0]
    original_timestamp = store.transactions_for_case(
        [case["txn_ids"][0]], case["dataset_id"]
    )[0]["timestamp"]
    customer_history = store.customer_transactions(case["customer"], case["dataset_id"])
    assert customer_history
    assert all(
        row["sender"] == case["customer"] or row["receiver"] == case["customer"]
        for row in customer_history
    )
    shifted = result.transactions.copy()
    shifted["timestamp"] += pd.Timedelta(days=1)
    shifted_result = Monitor().run(shifted)
    assert store.ingest_result(shifted_result) == len(shifted_result.alerts)
    shifted_case = next(
        item for item in store.list_cases()
        if item["customer"] == case["customer"] and item["rule"] == case["rule"]
        and item["dataset_id"] != case["dataset_id"]
    )
    shifted_timestamp = store.transactions_for_case(
        [case["txn_ids"][0]], shifted_case["dataset_id"]
    )[0]["timestamp"]
    assert shifted_timestamp != original_timestamp

    assert store.update_case(case["case_id"], "Under Review", "A. Investigator", "Reviewer")
    assert store.add_note(case["case_id"], "Reviewer", "Reviewed evidence against baseline.")
    updated = store.get_case(case["case_id"])
    notes, events = store.history(case["case_id"])
    assert updated["status"] == "Under Review"
    assert updated["assigned_to"] == "A. Investigator"
    assert notes[0]["note"] == "Reviewed evidence against baseline."
    assert {event["action"] for event in events} >= {
        "Status changed", "Assignment changed", "Investigation note added",
    }


def test_case_store_migrates_legacy_database(tmp_path):
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as db:
        db.executescript("""
            CREATE TABLE cases (
                case_id TEXT PRIMARY KEY, customer TEXT, rule TEXT, detail TEXT,
                strength REAL, amount REAL, first_seen TEXT, last_seen TEXT,
                txn_ids TEXT, risk_score REAL, rule_score REAL, anomaly REAL,
                profile TEXT, status TEXT, assigned_to TEXT, created_at TEXT, updated_at TEXT
            );
            CREATE TABLE transactions (
                txn_id TEXT PRIMARY KEY, timestamp TEXT, sender TEXT, receiver TEXT,
                amount REAL, channel TEXT, sender_country TEXT, receiver_country TEXT
            );
            INSERT INTO transactions VALUES
                ('T1', '2026-01-01T00:00:00', 'C00001', 'X1', 100, 'transfer', '', '');
            INSERT INTO cases VALUES (
                'legacy-case', 'C00001', 'fan_in', 'legacy evidence', 0.8, 100,
                '2026-01-01', '2026-01-01', '[\"T1\"]', 50, 0.5, 0.4,
                '{}', 'Open', '', '2026-01-01', '2026-01-01'
            );
        """)

    store = CaseStore(database)
    case = store.get_case("legacy-case")
    transactions = store.transactions_for_case(case["txn_ids"], case["dataset_id"])
    assert case["dataset_id"] == "legacy"
    assert transactions[0]["txn_id"] == "T1"
    assert store.latest_dataset_id() == "legacy"


def test_dashboard_scan_case_and_investigation_report(tmp_path):
    from traceledger.web import create_app

    app = create_app(tmp_path / "web.db")
    app.testing = True
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200 and b"TraceLedger" in response.data
    assert b"Case risk distribution" in response.data
    assert b"Recent case activity" in response.data
    assert app.config["CASE_STORE"].dashboard_data()["transactions"] == 0

    frame = generate_transactions(n_customers=200, days=45, seed=7)
    response = client.post(
        "/scan",
        data={"transactions": (BytesIO(frame.to_csv(index=False).encode()), "transactions.csv")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200 and b"created" in response.data
    case = app.config["CASE_STORE"].list_cases()[0]
    dashboard = app.config["CASE_STORE"].dashboard_data()
    assert dashboard["transactions"] == len(frame)
    assert dashboard["alerts"] == len(app.config["CASE_STORE"].list_cases())
    assert dashboard["suspicious_customers"] > 0
    assert sum(item["count"] for item in dashboard["risk_distribution"]) == dashboard["alerts"]
    assert 0 < sum(item["alerts"] for item in dashboard["trends"]) <= dashboard["alerts"]
    assert len(dashboard["trends"]) <= 10
    assert dashboard["recent_activity"][0]["action"] == "Case created"

    detail = client.get(f"/cases/{case['case_id']}")
    assert detail.status_code == 200 and b"Transaction network" in detail.data
    assert b"Transaction history" in detail.data and b"Export case CSV" in detail.data
    for flow in ("all", "fan-in", "fan-out"):
        network = client.get(f"/network?customer={case['customer']}&flow={flow}")
        assert network.status_code == 200 and b"Network explorer" in network.data
        if flow == "all":
            assert b"suspicious-edge" in network.data and b"network-node-link" in network.data
            assert f"dataset_id={case['dataset_id']}".encode() in network.data
    circular_case = next(
        (item for item in app.config["CASE_STORE"].list_cases() if item["rule"] == "round_trip"),
        None,
    )
    assert circular_case is not None
    circular = client.get(
        f"/network?customer={circular_case['customer']}&flow=circular"
    )
    assert circular.status_code == 200 and b"Circular" in circular.data
    update = client.post(
        f"/cases/{case['case_id']}/update",
        data={"status": "Under Review", "assigned_to": "Analyst", "investigator": "Reviewer"},
    )
    assert update.status_code == 302
    note = client.post(
        f"/cases/{case['case_id']}/notes",
        data={"investigator": "Reviewer", "note": "Reviewed source transaction evidence."},
    )
    assert note.status_code == 302
    report = client.get(f"/cases/{case['case_id']}/report")
    assert (
        report.status_code == 200
        and b"Investigation report" in report.data
        and b"Reviewed source transaction evidence." in report.data
        and b"Evidence role" in report.data
        and b"Print / save as PDF" in report.data
    )
    export = client.get(f"/cases/{case['case_id']}/transactions.csv")
    assert export.status_code == 200 and export.mimetype == "text/csv"
    assert b"transaction_id" in export.data and case["case_id"].encode() in export.data
    exported_rows = list(csv.DictReader(StringIO(export.data.decode("utf-8-sig"))))
    assert len(exported_rows) == len(case["txn_ids"])
    assert {row["evidence_role"] for row in exported_rows} <= {
        "Matched rule", "Context transaction",
    }
