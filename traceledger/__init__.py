"""TraceLedger: explainable AML monitoring and financial investigation tools."""

__version__ = "0.2.0"

from .cases import CASE_STATUSES, CaseStore
from .config import RuleConfig
from .monitor import Monitor, MonitoringResult
from .rules import RULES, Alert
from .schema import SchemaError
from .synth import TYPOLOGIES, SynthConfig, generate_transactions

__all__ = [
    "CASE_STATUSES",
    "RULES",
    "TYPOLOGIES",
    "Alert",
    "CaseStore",
    "Monitor",
    "MonitoringResult",
    "RuleConfig",
    "SchemaError",
    "SynthConfig",
    "__version__",
    "generate_transactions",
]
