"""
FastAPI router endpoints for DEEPSTATE Demonstration Laboratory & IPsec Testbed 2.0.
Exposes profile registries, testbed status, custom experiment validation/execution, and history tracking.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel, Field

from scripts.testbed.profile_registry import (
    get_all_profiles, get_profile, get_all_traffic_profiles, get_traffic_profile
)
from scripts.testbed.profile_runner import get_testbed_status
from scripts.testbed.capture_manager import execute_testbed_capture, execute_custom_experiment_capture
from scripts.testbed.experiment_model import (
    CONFIG_OPTIONS, EDUCATIONAL_KNOWLEDGE_BASE, EXPERIMENT_PRESETS,
    ExperimentConfig, validate_experiment_config
)
from scripts.testbed.experiment_history import list_experiments, get_experiment, save_experiment_record
from backend.app.analyzers.protocol_analyzer import analyze_pcap


router = APIRouter()
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent


class CaptureRequest(BaseModel):
    profile_id: str = Field(..., json_schema_extra={"example": "TEST-002"}, description="Target IPsec Profile ID (e.g. TEST-001, TEST-002, TEST-003)")
    traffic_profile: str = Field("ICMP", json_schema_extra={"example": "UDP"}, description="Traffic generation type: ICMP, UDP, or TCP")
    duration: int = Field(5, ge=1, le=60, description="Traffic generation duration in seconds")
    packet_count: int = Field(20, ge=1, le=500, description="Total packet count to generate")
    port: Optional[int] = Field(None, description="Optional custom destination port for UDP/TCP traffic")


# --- Phase 9A-1 Endpoint Compatibility ---

@router.get("/profiles", tags=["Testbed"])
def list_ipsec_profiles() -> List[Dict[str, Any]]:
    """Returns all registered IPsec demonstration profiles."""
    return get_all_profiles()


@router.get("/traffic-profiles", tags=["Testbed"])
def list_traffic_profiles() -> List[Dict[str, Any]]:
    """Returns all registered traffic generation profiles."""
    return get_all_traffic_profiles()


@router.get("/status", tags=["Testbed"])
def get_status() -> Dict[str, Any]:
    """Returns current operational status of the live IPsec StrongSwan Docker testbed."""
    return get_testbed_status()


@router.post("/capture", tags=["Testbed"])
def create_capture(request: CaptureRequest) -> Dict[str, Any]:
    """
    Executes complete testbed demonstration flow for predefined profiles.
    """
    profile = get_profile(request.profile_id)
    if not profile:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid or unregistered profile_id: '{request.profile_id}'."
        )

    traffic_prof = get_traffic_profile(request.traffic_profile)
    if not traffic_prof:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid or unregistered traffic_profile: '{request.traffic_profile}'."
        )

    try:
        result = execute_testbed_capture(
            profile_id=request.profile_id,
            traffic_profile_id=request.traffic_profile,
            duration=request.duration,
            packet_count=request.packet_count,
            port=request.port
        )
        return result
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Testbed capture execution failed: {str(err)}")


# --- Phase 9A-2 Operator-Controlled Demonstration Lab 2.0 Endpoints ---

@router.get("/config/options", tags=["Demonstration Lab 2.0"])
def get_experiment_options() -> Dict[str, Any]:
    """
    Returns supported IPsec configuration options, presets, and educational knowledge base.
    """
    return {
        "options": CONFIG_OPTIONS,
        "presets": list(EXPERIMENT_PRESETS.values()),
        "educational_kb": EDUCATIONAL_KNOWLEDGE_BASE
    }


@router.post("/validate", tags=["Demonstration Lab 2.0"])
def validate_experiment(config: ExperimentConfig) -> Dict[str, Any]:
    """
    Validates custom operator experiment configuration before execution.
    """
    return validate_experiment_config(config)


@router.post("/experiment", tags=["Demonstration Lab 2.0"])
def execute_experiment(config: ExperimentConfig) -> Dict[str, Any]:
    """
    Executes custom operator IPsec experiment:
    Validate -> Initiate Tunnel -> Capture PCAP -> Generate Traffic -> Finalize -> Return Metadata.
    """
    val_res = validate_experiment_config(config)
    if not val_res["valid"]:
        raise HTTPException(status_code=400, detail=f"Experiment validation failed: {', '.join(val_res['errors'])}")

    try:
        metadata = execute_custom_experiment_capture(config)
        return metadata
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Experiment execution failed: {str(err)}")


@router.get("/experiments", tags=["Demonstration Lab 2.0"])
def get_experiment_history() -> List[Dict[str, Any]]:
    """
    Returns persistent experiment execution history.
    """
    return list_experiments()


@router.get("/experiments/{experiment_id}", tags=["Demonstration Lab 2.0"])
def get_single_experiment(experiment_id: str) -> Dict[str, Any]:
    """
    Retrieves a single experiment record by ID.
    """
    exp = get_experiment(experiment_id)
    if not exp:
        raise HTTPException(status_code=404, detail=f"Experiment '{experiment_id}' not found.")
    return exp


@router.post("/experiments/{experiment_id}/analyze", tags=["Demonstration Lab 2.0"])
def analyze_experiment_record(experiment_id: str) -> Dict[str, Any]:
    """
    Hands off an experiment's generated PCAP artifact directly to the DEEPSTATE /api/v1/analyze pipeline.
    """
    exp = get_experiment(experiment_id)
    if not exp:
        raise HTTPException(status_code=404, detail=f"Experiment '{experiment_id}' not found.")

    file_path = exp.get("file_path")
    if not file_path:
        raise HTTPException(status_code=400, detail=f"Experiment '{experiment_id}' has no associated PCAP file path.")

    abs_path = PROJECT_ROOT / file_path
    if not abs_path.exists():
        raise HTTPException(status_code=404, detail=f"Experiment PCAP file not found at path: {file_path}")

    # Invoke existing DEEPSTATE analytical pipeline
    analysis_res = analyze_pcap(str(abs_path))
    res_dict = analysis_res.model_dump() if hasattr(analysis_res, "model_dump") else analysis_res.dict()

    # Update experiment history record status
    exp["analysis_status"] = "analyzed"
    exp["latest_analysis"] = {
        "analysis_id": res_dict.get("analysis_id"),
        "security_score": res_dict.get("security_assessment", {}).get("security_score"),
        "overall_status": res_dict.get("security_assessment", {}).get("overall_status"),
        "dominant_class": res_dict.get("traffic_classification", {}).get("dominant_class"),
        "confidence": res_dict.get("traffic_classification", {}).get("confidence")
    }
    save_experiment_record(exp)

    return res_dict
