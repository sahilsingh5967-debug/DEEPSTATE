"""
Persistent Lightweight Experiment History Log Manager for Demonstration Lab 2.0.
Stores experiment metadata in data/pcaps/generated/experiments_history.json.
"""

import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
GENERATED_DIR = PROJECT_ROOT / "data" / "pcaps" / "generated"
GENERATED_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = GENERATED_DIR / "experiments_history.json"


def load_history() -> List[Dict[str, Any]]:
    """Loads experiment history list from JSON file."""
    if not HISTORY_FILE.exists():
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_history(history: List[Dict[str, Any]]) -> None:
    """Saves experiment history list to JSON file."""
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception as err:
        print(f"Error saving experiment history: {err}")


def save_experiment_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Appends a new experiment record to history and saves to disk."""
    history = load_history()
    # Replace existing if ID matches, else prepend
    exp_id = record.get("experiment_id")
    history = [r for r in history if r.get("experiment_id") != exp_id]
    history.insert(0, record)

    # Keep last 50 experiments
    if len(history) > 50:
        history = history[:50]

    save_history(history)
    return record


def list_experiments() -> List[Dict[str, Any]]:
    """Returns all recorded experiments in reverse chronological order."""
    return load_history()


def get_experiment(experiment_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single experiment record by ID."""
    history = load_history()
    for exp in history:
        if exp.get("experiment_id") == experiment_id:
            return exp
    return None
