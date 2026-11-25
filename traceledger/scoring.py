"""Customer-level behavioural features and anomaly scoring."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .config import RuleConfig

FEATURES = [
    "n_out",
    "n_in",
    "value_out",
    "value_in",
    "cash_in_share",
    "cash_out_share",
    "distinct_senders",
    "distinct_receivers",
    "foreign_share",
    "max_amount",
    "flow_through",
    "night_share",
    "transaction_count",
    "high_risk_transaction_count",
    "high_risk_value",
    "counterparty_count",
    "activity_frequency_change",
]


def customer_features(df: pd.DataFrame, cfg: RuleConfig) -> pd.DataFrame:
    """Summarise each customer's activity into one row of features."""
    home = _home(df)
    night = (df["timestamp"].dt.hour < 6) | (df["timestamp"].dt.hour >= 22)
    cash_amt = df["amount"].where(df["channel"] == "cash", 0.0)
    base = df.assign(night=night.astype(int), cash_amt=cash_amt)

    out = base[base["sender_is_customer"]].assign(
        customer=lambda d: d["sender"],
        foreign=lambda d: (~d["receiver_country"].isin(["", home])).astype(int))
    inc = base[base["receiver_is_customer"]].assign(
        customer=lambda d: d["receiver"],
        foreign=lambda d: (~d["sender_country"].isin(["", home])).astype(int))

    o = out.groupby("customer").agg(
        n_out=("txn_id", "size"),
        value_out=("amount", "sum"),
        max_out=("amount", "max"),
        distinct_receivers=("receiver", "nunique"),
        cash_out_value=("cash_amt", "sum"),
        foreign_out=("foreign", "sum"),
        night_out=("night", "sum"),
    )
    i = inc.groupby("customer").agg(
        n_in=("txn_id", "size"),
        value_in=("amount", "sum"),
        max_in=("amount", "max"),
        distinct_senders=("sender", "nunique"),
        cash_in_value=("cash_amt", "sum"),
        foreign_in=("foreign", "sum"),
        night_in=("night", "sum"),
    )
    f = o.join(i, how="outer").fillna(0.0)
    n_total = (f["n_out"] + f["n_in"]).replace(0, np.nan)
    f["cash_in_share"] = f["cash_in_value"] / f["value_in"].replace(0, np.nan)
    f["cash_out_share"] = f["cash_out_value"] / f["value_out"].replace(0, np.nan)
    f["foreign_share"] = (f["foreign_out"] + f["foreign_in"]) / n_total
    f["night_share"] = (f["night_out"] + f["night_in"]) / n_total
    f["max_amount"] = f[["max_out", "max_in"]].max(axis=1)
    f["flow_through"] = np.minimum(f["value_out"], f["value_in"]) / np.maximum(
        f[["value_out", "value_in"]].max(axis=1), 1.0)
    f["transaction_count"] = f["n_out"] + f["n_in"]
    high_risk = df["sender_country"].isin(cfg.high_risk_countries) | df[
        "receiver_country"
    ].isin(cfg.high_risk_countries)
    hr_out = df[high_risk & df["sender_is_customer"]].groupby("sender").agg(
        high_risk_out_count=("txn_id", "size"), high_risk_out_value=("amount", "sum")
    )
    hr_in = df[high_risk & df["receiver_is_customer"]].groupby("receiver").agg(
        high_risk_in_count=("txn_id", "size"), high_risk_in_value=("amount", "sum")
    )
    high_risk_features = hr_out.rename_axis("customer").join(
        hr_in.rename_axis("customer"), how="outer"
    ).fillna(0.0)
    f = f.join(high_risk_features, how="left")
    for column in ("high_risk_out_count", "high_risk_in_count",
                   "high_risk_out_value", "high_risk_in_value"):
        f[column] = f[column].fillna(0.0)
    f["high_risk_transaction_count"] = (
        f["high_risk_out_count"] + f["high_risk_in_count"]
    )
    f["high_risk_value"] = f["high_risk_out_value"] + f["high_risk_in_value"]
    f["counterparty_count"] = f["distinct_senders"] + f["distinct_receivers"]

    midpoint = df["timestamp"].min() + (
        df["timestamp"].max() - df["timestamp"].min()
    ) / 2
    recent = df[df["timestamp"] > midpoint]
    earlier = df[df["timestamp"] <= midpoint]
    recent_counts = pd.concat([
        recent.loc[recent["sender_is_customer"], "sender"],
        recent.loc[recent["receiver_is_customer"], "receiver"],
    ]).value_counts()
    earlier_counts = pd.concat([
        earlier.loc[earlier["sender_is_customer"], "sender"],
        earlier.loc[earlier["receiver_is_customer"], "receiver"],
    ]).value_counts()
    f["activity_frequency_change"] = (
        (recent_counts.reindex(f.index, fill_value=0) + 1)
        / (earlier_counts.reindex(f.index, fill_value=0) + 1)
    )
    f = f.fillna(0.0)
    f.index.name = "customer"
    return f[FEATURES]


def _home(df: pd.DataFrame) -> str:
    """The most common customer-side country, treated as the home market."""
    sc = df.loc[df["sender_is_customer"], "sender_country"]
    mode = sc[sc != ""].mode()
    return str(mode.iloc[0]) if len(mode) else ""


def anomaly_scores(features: pd.DataFrame, cfg: RuleConfig) -> pd.Series:
    """Isolation-forest anomaly score per customer, as a percentile in [0, 1].

    Higher means more unusual relative to the rest of the book.
    """
    if len(features) < 10:
        return pd.Series(0.0, index=features.index, name="anomaly")
    x = features.copy()
    for col in ("n_out", "n_in", "value_out", "value_in", "distinct_senders",
                "distinct_receivers", "max_amount", "transaction_count",
                "high_risk_transaction_count", "high_risk_value", "counterparty_count"):
        x[col] = np.log1p(x[col])
    x = StandardScaler().fit_transform(x)
    model = IsolationForest(n_estimators=300, random_state=cfg.random_state, n_jobs=1)
    model.fit(x)
    raw = -model.score_samples(x)
    return pd.Series(raw, index=features.index).rank(pct=True).rename("anomaly")


def anomaly_explanations(features: pd.DataFrame, limit: int = 3) -> pd.Series:
    """Describe unusual feature values; these heuristics are not SHAP values."""
    medians = features.median()
    spread = features.quantile(0.75) - features.quantile(0.25)
    spread = spread.where(spread > 0, features.std().replace(0, 1.0))
    deviation = (features - medians) / spread.replace(0, 1.0)
    labels = {
        "n_out": "outgoing frequency",
        "n_in": "incoming frequency",
        "value_out": "outgoing volume",
        "value_in": "incoming volume",
        "distinct_senders": "sender diversity",
        "distinct_receivers": "receiver diversity",
        "foreign_share": "foreign exposure",
        "max_amount": "largest transaction",
        "flow_through": "flow-through ratio",
        "night_share": "night-time activity",
        "high_risk_transaction_count": "high-risk corridor activity",
        "high_risk_value": "high-risk corridor value",
        "counterparty_count": "counterparty count",
        "activity_frequency_change": "recent frequency change",
    }
    explanations = {}
    for customer, deviations in deviation.iterrows():
        unusual = deviations[deviations > 1.0].sort_values(ascending=False)
        reasons = [
            f"{labels.get(name, name)} ({features.at[customer, name]:,.2f}; "
            f"book median {medians[name]:,.2f})"
            for name in unusual.index[:limit]
        ]
        explanations[customer] = (
            "; ".join(reasons) or "No single feature was markedly above the book median"
        )
    return pd.Series(explanations, dtype=str, name="anomaly_explanation")
