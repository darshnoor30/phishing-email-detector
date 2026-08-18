"""Public API for the explainable phishing email detector."""

from .engine import AnalysisResult, Indicator, analyze_email

__all__ = ["AnalysisResult", "Indicator", "analyze_email"]
