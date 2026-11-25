"""Local Flask dashboard for transaction scanning and case investigation."""

from __future__ import annotations

import csv
import html
import math
import os
from collections import defaultdict
from io import BytesIO, StringIO
from pathlib import Path

import pandas as pd
from flask import Flask, abort, redirect, render_template, request, send_file, url_for

from .cases import CASE_STATUSES, CaseStore
from .monitor import Monitor
from .schema import SchemaError


def _network(
    transactions: list[dict],
    customer: str,
    suspicious_txn_ids: set[str] | None = None,
    dataset_id: str | None = None,
) -> dict:
    suspicious_txn_ids = suspicious_txn_ids or set()
    parties = list(dict.fromkeys(
        party for txn in transactions for party in (txn["sender"], txn["receiver"])
    ))
    if not parties:
        return {"nodes": [], "edges": [], "dataset_id": dataset_id}
    cx, cy = 440, 190
    radius = min(140, max(55, 33 * len(parties)))
    positions = {}
    for index, party in enumerate(parties):
        angle = -math.pi / 2 + 2 * math.pi * index / max(1, len(parties))
        positions[party] = {
            "x": round(cx + radius * math.cos(angle), 1),
            "y": round(cy + radius * math.sin(angle), 1),
            "label": party,
            "suspicious": party == customer,
        }
    pair_totals = defaultdict(int)
    for txn in transactions:
        pair_totals[(txn["sender"], txn["receiver"])] += 1
    pair_occurrences = defaultdict(int)
    edges = []
    for txn in transactions:
        sender = positions[txn["sender"]]
        receiver = positions[txn["receiver"]]
        pair = (txn["sender"], txn["receiver"])
        occurrence = pair_occurrences[pair]
        pair_occurrences[pair] += 1
        offset = 0 if occurrence == 0 else (
            ((occurrence + 1) // 2) * 22 * (1 if occurrence % 2 else -1)
        )
        dx = receiver["x"] - sender["x"]
        dy = receiver["y"] - sender["y"]
        distance = math.hypot(dx, dy) or 1
        control_x = (sender["x"] + receiver["x"]) / 2 - dy / distance * offset
        control_y = (sender["y"] + receiver["y"]) / 2 + dx / distance * offset
        edges.append({
            "txn_id": txn["txn_id"],
            "sender": sender,
            "receiver": receiver,
            "path": (
                f'M {sender["x"]} {sender["y"]} Q {control_x:.1f} {control_y:.1f} '
                f'{receiver["x"]} {receiver["y"]}'
            ),
            "label_x": round((sender["x"] + 2 * control_x + receiver["x"]) / 4, 1),
            "label_y": round((sender["y"] + 2 * control_y + receiver["y"]) / 4 - 5, 1),
            "amount": f'{txn["amount"]:,.2f}',
            "show_amount": pair_totals[pair] == 1,
            "timestamp": txn["timestamp"],
            "suspicious": txn["txn_id"] in suspicious_txn_ids,
        })
    return {
        "nodes": list(positions.values()),
        "edges": edges,
        "dataset_id": dataset_id,
    }


def _annotate_transactions(transactions: list[dict], suspicious_ids: set[str]) -> None:
    for transaction in transactions:
        transaction["is_suspicious"] = transaction["txn_id"] in suspicious_ids


def _csv_safe(value: object) -> object:
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{value}"
    return value


def _report_html(
    case: dict,
    transactions: list[dict],
    notes: list[dict],
    events: list[dict],
    previous_cases: int,
) -> str:
    generated = pd.Timestamp.now(tz="UTC").strftime("%d %b %Y %H:%M UTC")
    note_list = "".join(
        f"<li><b>{html.escape(note['investigator'])}</b> — "
        f"{html.escape(note['created_at'])}<br>{html.escape(note['note'])}</li>"
        for note in notes
    ) or "<li>No investigation notes recorded.</li>"
    audit_list = "".join(
        f"<li>{html.escape(event['created_at'])} · {html.escape(event['actor'])}: "
        f"{html.escape(event['action'])} "
        f"{html.escape(event['old_value'])} → {html.escape(event['new_value'])}</li>"
        for event in events
    ) or "<li>No case history recorded.</li>"
    return render_template(
        "case_report.html",
        case=case,
        transactions=transactions,
        notes_html=note_list,
        audit_html=audit_list,
        generated=generated,
        previous_cases=previous_cases,
        network=_network(
            transactions, case["customer"], set(case["suspicious_txn_ids"]),
            case["dataset_id"],
        ),
    )


def create_app(database: str | Path | None = None) -> Flask:
    app = Flask(__name__)
    app.config["CASE_STORE"] = CaseStore(
        database or os.environ.get("TRACELEDGER_DB", "traceledger.db")
    )
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

    @app.get("/")
    def dashboard():
        store: CaseStore = app.config["CASE_STORE"]
        selected_status = request.args.get("status", "")
        cases = store.list_cases(selected_status or None)
        return render_template(
            "dashboard.html",
            cases=cases,
            summary=store.summary(),
            dashboard=store.dashboard_data(),
            statuses=CASE_STATUSES,
            selected_status=selected_status,
            notice=request.args.get("notice", ""),
            error=request.args.get("error", ""),
        )

    @app.post("/scan")
    def scan():
        upload = request.files.get("transactions")
        if upload is None or not upload.filename:
            return redirect(url_for("dashboard", error="Choose a CSV file to scan."))
        if Path(upload.filename).suffix.lower() != ".csv":
            return redirect(url_for("dashboard", error="Upload a CSV transaction file."))
        try:
            frame = pd.read_csv(BytesIO(upload.read()))
            result = Monitor().run(frame)
        except (pd.errors.ParserError, UnicodeDecodeError, SchemaError, ValueError) as exc:
            return redirect(url_for("dashboard", error=f"Scan failed: {exc}"))
        store: CaseStore = app.config["CASE_STORE"]
        created = store.ingest_result(result)
        return redirect(url_for(
            "dashboard",
            notice=f"Scanned {len(result.transactions):,} transactions; "
                   f"created {created} new cases.",
        ))

    @app.get("/cases/<case_id>")
    def case_detail(case_id: str):
        store: CaseStore = app.config["CASE_STORE"]
        case = store.get_case(case_id)
        if case is None:
            abort(404)
        transactions = store.transactions_for_case(case["txn_ids"], case["dataset_id"])
        _annotate_transactions(transactions, set(case["suspicious_txn_ids"]))
        customer_history = store.customer_transactions(
            case["customer"], case["dataset_id"]
        )
        notes, events = store.history(case_id)
        return render_template(
            "case_detail.html",
            case=case,
            transactions=transactions,
            customer_history=customer_history,
            notes=notes,
            events=events,
            statuses=CASE_STATUSES,
            previous_cases=max(0, store.customer_case_count(case["customer"]) - 1),
            network=_network(
                transactions, case["customer"], set(case["suspicious_txn_ids"]),
                case["dataset_id"],
            ),
        )

    @app.get("/network")
    def network_explorer():
        customer = request.args.get("customer", "").strip()
        flow = request.args.get("flow", "all")
        if flow not in {"all", "fan-in", "fan-out", "circular"}:
            abort(400, "Invalid network view")
        store: CaseStore = app.config["CASE_STORE"]
        dataset_id = request.args.get("dataset_id") or store.latest_dataset_id()
        transactions = (
            store.network_transactions(customer, flow, dataset_id=dataset_id)
            if customer else []
        )
        suspicious_ids = store.suspicious_transaction_ids(customer, dataset_id)
        return render_template(
            "network.html",
            customer=customer,
            flow=flow,
            dataset_id=dataset_id,
            flows=("all", "fan-in", "fan-out", "circular"),
            network=_network(transactions, customer, suspicious_ids, dataset_id),
            transactions=transactions,
        )

    @app.post("/cases/<case_id>/update")
    def update_case(case_id: str):
        store: CaseStore = app.config["CASE_STORE"]
        status = request.form.get("status", "")
        if status not in CASE_STATUSES:
            abort(400, "Invalid case status")
        if not store.update_case(
            case_id,
            status,
            request.form.get("assigned_to", ""),
            request.form.get("investigator", ""),
        ):
            abort(404)
        return redirect(url_for("case_detail", case_id=case_id))

    @app.post("/cases/<case_id>/notes")
    def add_note(case_id: str):
        store: CaseStore = app.config["CASE_STORE"]
        try:
            exists = store.add_note(
                case_id,
                request.form.get("investigator", ""),
                request.form.get("note", ""),
            )
        except ValueError as exc:
            abort(400, str(exc))
        if not exists:
            abort(404)
        return redirect(url_for("case_detail", case_id=case_id))

    @app.get("/cases/<case_id>/report")
    def case_report(case_id: str):
        store: CaseStore = app.config["CASE_STORE"]
        case = store.get_case(case_id)
        if case is None:
            abort(404)
        transactions = store.transactions_for_case(case["txn_ids"], case["dataset_id"])
        _annotate_transactions(transactions, set(case["suspicious_txn_ids"]))
        notes, events = store.history(case_id)
        return _report_html(
            case,
            transactions,
            notes,
            events,
            max(0, store.customer_case_count(case["customer"]) - 1),
        )

    @app.get("/cases/<case_id>/transactions.csv")
    def case_csv_export(case_id: str):
        store: CaseStore = app.config["CASE_STORE"]
        case = store.get_case(case_id)
        if case is None:
            abort(404)
        transactions = store.transactions_for_case(case["txn_ids"], case["dataset_id"])
        suspicious_ids = set(case["suspicious_txn_ids"])
        fields = (
            "case_id", "customer", "rule", "detection_reason", "risk_score",
            "status", "assigned_to", "transaction_id", "timestamp", "sender",
            "receiver", "amount", "channel", "sender_country", "receiver_country",
            "evidence_role",
        )
        output = StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for transaction in transactions:
            row = {
                "case_id": case["case_id"],
                "customer": case["customer"],
                "rule": case["rule"],
                "detection_reason": case["detail"],
                "risk_score": case["risk_score"],
                "status": case["status"],
                "assigned_to": case["assigned_to"],
                "transaction_id": transaction["txn_id"],
                "timestamp": transaction["timestamp"],
                "sender": transaction["sender"],
                "receiver": transaction["receiver"],
                "amount": transaction["amount"],
                "channel": transaction["channel"],
                "sender_country": transaction["sender_country"],
                "receiver_country": transaction["receiver_country"],
                "evidence_role": (
                    "Matched rule" if transaction["txn_id"] in suspicious_ids
                    else "Context transaction"
                ),
            }
            writer.writerow({key: _csv_safe(value) for key, value in row.items()})
        return send_file(
            BytesIO(output.getvalue().encode("utf-8-sig")),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"traceledger-case-{case_id}.csv",
        )

    return app


def run_server(host: str = "127.0.0.1", port: int = 5000, database: str | Path | None = None):
    """Run the local investigation dashboard (loopback only by default)."""
    create_app(database).run(host=host, port=port, debug=False)
