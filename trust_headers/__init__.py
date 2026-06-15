"""Trust-Headers email analysis package."""

from .analysis import analyze_email
from .models import AnalysisResult, ParsedEmail
from .parser import parse_email

__all__ = ["AnalysisResult", "ParsedEmail", "analyze_email", "parse_email"]
