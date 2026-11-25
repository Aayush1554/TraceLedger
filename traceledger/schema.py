"""Input validation and normalisation."""

from __future__ import annotations

import numpy as np
import pandas as pd

from .config import RuleConfig

REQUIRED = ("txn_id", "timestamp", "sender", "receiver", "amount", "channel")
OPTIONAL_DEFAULTS = {"sender_country": "", "receiver_country": "", "currency": ""}


class SchemaError(ValueError):
    """Raised when a transaction table is missing required columns or values."""


def prepare(df: pd.DataFrame, config: RuleConfig) -> pd.DataFrame:
    """Validate a transaction table and return a normalised copy.

    The returned frame is sorted by time and always has the boolean columns
    ``sender_is_customer`` and ``receiver_is_customer``.
    """
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise SchemaError(f"Missing required columns: {missing}")
    if df.empty:
        raise SchemaError("Transaction table must contain at least one row")

    out = df.copy()
    missing_values = out[list(REQUIRED)].isna().any(axis=1)
    if missing_values.any():
        raise SchemaError(f"{int(missing_values.sum())} rows have missing required values")
    for column in ("sender_is_customer", "receiver_is_customer"):
        if column in out and out[column].isna().any():
            raise SchemaError(f"{int(out[column].isna().sum())} rows have missing {column} values")
    for col, default in OPTIONAL_DEFAULTS.items():
        if col not in out.columns:
            out[col] = default
        out[col] = out[col].fillna(default).astype(str)

    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce")
    out["amount"] = pd.to_numeric(out["amount"], errors="coerce")
    bad = out["timestamp"].isna() | out["amount"].isna() | ~np.isfinite(out["amount"])
    if bad.any():
        raise SchemaError(f"{int(bad.sum())} rows have an unreadable timestamp or amount")
    if (out["amount"] < 0).any():
        raise SchemaError("Amounts must be non-negative; record direction with sender/receiver")

    for col in ("txn_id", "sender", "receiver", "channel"):
        out[col] = out[col].astype(str)
    out["channel"] = out["channel"].str.lower()
    blank = out[["txn_id", "sender", "receiver", "channel"]].apply(
        lambda column: column.str.strip().eq("")
    ).any(axis=1)
    if blank.any():
        raise SchemaError(f"{int(blank.sum())} rows have blank transaction identifiers or parties")
    if out["txn_id"].duplicated().any():
        raise SchemaError("Transaction identifiers must be unique")

    pattern = config.customer_pattern
    if "sender_is_customer" not in out.columns:
        out["sender_is_customer"] = out["sender"].str.match(pattern)
    if "receiver_is_customer" not in out.columns:
        out["receiver_is_customer"] = out["receiver"].str.match(pattern)
    out["sender_is_customer"] = out["sender_is_customer"].astype(bool)
    out["receiver_is_customer"] = out["receiver_is_customer"].astype(bool)

    return out.sort_values("timestamp", kind="stable").reset_index(drop=True)
