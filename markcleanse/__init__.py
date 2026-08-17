"""markcleanse — AI provenance and watermark forensics for images and documents."""

from .result import Finding, FileReport, Tier, Verdict
from .scan import ScanOptions, ScanResult, scan_bytes, scan_file, scan_paths

__version__ = "0.1.0"

__all__ = [
    "Finding", "FileReport", "Tier", "Verdict",
    "ScanOptions", "ScanResult", "scan_bytes", "scan_file", "scan_paths",
    "__version__",
]
