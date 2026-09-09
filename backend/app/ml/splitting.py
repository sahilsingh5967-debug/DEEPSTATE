"""
Leakage-Safe Dataset Splitting Module.
Phase 11.3 — AI-Powered IPsec VPN Protocol Analyzer.

Executes deterministic 70% Train / 15% Validation / 15% Test dataset splitting.
Supports strict Capture / Session-level grouped splitting to prevent multi-flow session leakage across splits.
Strips forbidden predictive identifiers from ML feature matrices.
"""

import random
from typing import Dict, Any, List, Tuple
from backend.app.ml.features import ML_FEATURE_COLUMNS, METADATA_COLUMNS

# Identifiers that MUST be excluded from ML feature vectors to prevent target leakage
FORBIDDEN_PREDICTIVE_IDENTIFIERS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "flow_id",
    "capture_id",
    "session_id",
    "dataset_id",
    "traffic_class",
    "behavioral_class"
]


def split_records_session_level(
    records: List[Dict[str, Any]],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_seed: int = 42
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Splits records into train, validation, and test sets at the Capture/Session ID level.
    Guarantees NO capture/session ID appears in more than one split, preventing session-level feature leakage.
    """
    if abs((train_ratio + val_ratio + test_ratio) - 1.0) > 1e-4:
        raise ValueError("Train, val, and test ratios must sum to 1.0")

    # Group records by unique capture/session ID
    sessions_map: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        sid = r.get("capture_id") or r.get("session_id") or r.get("pcap_source") or "UNKNOWN_SESSION"
        if sid not in sessions_map:
            sessions_map[sid] = []
        sessions_map[sid].append(r)

    unique_session_ids = sorted(list(sessions_map.keys()))
    rng = random.Random(random_seed)
    rng.shuffle(unique_session_ids)

    n_total = len(unique_session_ids)
    n_train = max(1, int(n_total * train_ratio))
    n_val = max(1, int(n_total * val_ratio)) if n_total >= 3 else 0

    train_ids = set(unique_session_ids[:n_train])
    val_ids = set(unique_session_ids[n_train : n_train + n_val]) if n_val > 0 else set()
    test_ids = set(unique_session_ids[n_train + n_val :])

    train_records = []
    val_records = []
    test_records = []

    for sid, session_recs in sessions_map.items():
        if sid in train_ids:
            train_records.extend(session_recs)
        elif sid in val_ids:
            val_records.extend(session_recs)
        elif sid in test_ids:
            test_records.extend(session_recs)

    # Strict Verification: Ensure zero session ID overlap
    assert len(train_ids & val_ids) == 0, "Train and Val share session IDs!"
    assert len(train_ids & test_ids) == 0, "Train and Test share session IDs!"
    assert len(val_ids & test_ids) == 0, "Val and Test share session IDs!"

    return {
        "train": train_records,
        "val": val_records,
        "test": test_records
    }


def split_records_flow_level(
    records: List[Dict[str, Any]],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_seed: int = 42
) -> Dict[str, List[Dict[str, Any]]]:
    """
    DEPRECATED (Legacy Splitter): Splits records at the 5-tuple flow ID level.
    Maintained for backward compatibility. Prefer split_records_session_level for Phase 11 pipelines.
    """
    if abs((train_ratio + val_ratio + test_ratio) - 1.0) > 1e-4:
        raise ValueError("Train, val, and test ratios must sum to 1.0")

    # Group records by unique flow_id
    flows_map: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        fid = r.get("flow_id", "UNKNOWN_FLOW")
        if fid not in flows_map:
            flows_map[fid] = []
        flows_map[fid].append(r)

    unique_flow_ids = sorted(list(flows_map.keys()))
    rng = random.Random(random_seed)
    rng.shuffle(unique_flow_ids)

    n_total = len(unique_flow_ids)
    n_train = int(n_total * train_ratio)
    n_val = int(n_total * val_ratio)

    train_ids = set(unique_flow_ids[:n_train])
    val_ids = set(unique_flow_ids[n_train : n_train + n_val])
    test_ids = set(unique_flow_ids[n_train + n_val :])

    train_records = []
    val_records = []
    test_records = []

    for fid, flow_recs in flows_map.items():
        if fid in train_ids:
            train_records.extend(flow_recs)
        elif fid in val_ids:
            val_records.extend(flow_recs)
        elif fid in test_ids:
            test_records.extend(flow_recs)

    # Verification: Ensure zero flow ID overlap
    assert len(train_ids & val_ids) == 0, "Train and Val share flow IDs!"
    assert len(train_ids & test_ids) == 0, "Train and Test share flow IDs!"
    assert len(val_ids & test_ids) == 0, "Val and Test share flow IDs!"

    return {
        "train": train_records,
        "val": val_records,
        "test": test_records
    }


def prepare_ml_matrices(records: List[Dict[str, Any]]) -> Tuple[List[List[float]], List[str], List[Dict[str, Any]]]:
    """
    Extracts (X, y, metadata) matrices from feature records.
    Strips forbidden predictive identifiers from X.
    """
    X = []
    y = []
    metadata = []

    for r in records:
        # Extract predictive feature vector ONLY
        feature_vector = [float(r.get(col, 0.0)) for col in ML_FEATURE_COLUMNS]
        target_label = str(r.get("behavioral_class") or r.get("traffic_class", "UNKNOWN_UNCLASSIFIED"))
        meta = {col: r.get(col) for col in METADATA_COLUMNS if col in r}

        X.append(feature_vector)
        y.append(target_label)
        metadata.append(meta)

    return X, y, metadata
