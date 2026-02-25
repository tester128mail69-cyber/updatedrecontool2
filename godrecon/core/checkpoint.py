"""Checkpoint management for GODRECON scan progress.

Provides functions to persist and restore scan state so that interrupted
scans can be resumed without re-running already-completed modules.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List


def save_checkpoint(
    domain: str,
    completed_modules: List[str],
    results: Dict[str, Any],
) -> str:
    """Save scan progress to a JSON checkpoint file.

    The checkpoint is written to
    ``~/.godrecon/checkpoints/<domain>_<timestamp>.json``.

    Args:
        domain: The scan target domain.
        completed_modules: List of module names that have completed.
        results: Mapping of module name to its result data.

    Returns:
        Absolute path to the saved checkpoint file.
    """
    checkpoint_dir = Path.home() / ".godrecon" / "checkpoints"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    timestamp = int(time.time())
    filename = f"{domain}_{timestamp}.json"
    filepath = checkpoint_dir / filename

    checkpoint_data: Dict[str, Any] = {
        "domain": domain,
        "timestamp": timestamp,
        "completed_modules": completed_modules,
        "results": results,
    }

    with open(filepath, "w") as f:
        json.dump(checkpoint_data, f, indent=2, default=str)

    return str(filepath)


def load_checkpoint(filepath: str) -> Dict[str, Any]:
    """Load a checkpoint from a JSON file.

    Args:
        filepath: Path to the checkpoint file.

    Returns:
        Dictionary containing ``domain``, ``timestamp``,
        ``completed_modules``, and ``results`` keys.
    """
    with open(filepath) as f:
        return json.load(f)
