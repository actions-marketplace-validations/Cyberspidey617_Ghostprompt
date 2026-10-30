"""GhostPrompt — find hidden prompt injections before your AI agent does."""
__version__ = "0.1.0"

from .scanner import Finding, ScanResult, scan_paths, scan_text  # noqa: E402

__all__ = ["Finding", "ScanResult", "scan_paths", "scan_text", "__version__"]
