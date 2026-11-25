"""Shared contracts for the unified Analysis workspace."""

from hst.analysis.contracts import (
    AnalysisInput,
    AnalysisLocation,
    AnalysisRunSummary,
    AnalysisSession,
    ConnectionAnalysisInput,
    SimulationAnalysisInput,
    adapt_legacy_assessment,
)

__all__ = [
    "AnalysisInput",
    "AnalysisLocation",
    "AnalysisRunSummary",
    "AnalysisSession",
    "ConnectionAnalysisInput",
    "SimulationAnalysisInput",
    "adapt_legacy_assessment",
]
