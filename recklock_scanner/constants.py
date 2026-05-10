"""Shared constants for ReckLock Discover."""

# PyPI / CLI release version (keep in sync with pyproject.toml [project].version).
SCANNER_VERSION = "1.0.4"

# Expected value for metadata.registry_version in exported manifests (ReckLock Registry).
MANIFEST_REGISTRY_VERSION = "0.1.0"

MAX_FILE_BYTES = 1_048_576  # 1 MiB cap per file
MAX_FILES = 50_000

DEFAULT_JSON_FILENAME = "recklock_discover_scan_report.json"
# Human-facing Markdown outputs (executive summary vs full narrative).
DEFAULT_SUMMARY_MARKDOWN_FILENAME = "recklock_discover_summary_of_findings.md"
DEFAULT_DETAILS_MARKDOWN_FILENAME = "recklock_discover_details_of_findings.md"

DEFAULT_EXPORT_DIRNAME = "recklock_manifest_exports"
