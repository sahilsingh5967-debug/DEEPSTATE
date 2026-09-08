from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException
from backend.app.core.config import settings
from backend.app.models.schemas import HealthResponse, AnalysisRequest, AnalysisResult
from backend.app.analyzers.protocol_analyzer import analyze_pcap

router = APIRouter()

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent


@router.get("/health", response_model=HealthResponse, tags=["Health"])
def get_health() -> HealthResponse:
    """
    Machine-readable health status endpoint.
    Verifies that the backend operational environment is healthy.
    """
    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )


@router.get("/pcaps", tags=["Analysis"])
def list_available_pcaps() -> List[Dict[str, Any]]:
    """
    Returns list of available preset PCAP files for demonstration and testing.
    """
    pcaps: List[Dict[str, Any]] = []

    real_dir = PROJECT_ROOT / "data" / "pcaps" / "real"
    if real_dir.exists():
        for f in sorted(real_dir.glob("*.pcap")):
            pcaps.append({
                "id": f.name,
                "name": f"{f.name} (Real IPsec Testbed)",
                "category": "Real IPsec Ground Truth",
                "file_path": str(f.relative_to(PROJECT_ROOT)),
                "absolute_path": str(f),
                "size_bytes": f.stat().st_size
            })

    synth_dir = PROJECT_ROOT / "data" / "pcaps" / "synthetic"
    if synth_dir.exists():
        for f in sorted(synth_dir.glob("*.pcap")):
            pcaps.append({
                "id": f.name,
                "name": f"{f.name} (Synthetic Fixture)",
                "category": "Synthetic Fixtures",
                "file_path": str(f.relative_to(PROJECT_ROOT)),
                "absolute_path": str(f),
                "size_bytes": f.stat().st_size
            })

    return pcaps


@router.post("/analyze", response_model=AnalysisResult, tags=["Analysis"])
def analyze_pcap_endpoint(request: AnalysisRequest) -> AnalysisResult:
    """
    Executes unified IPsec VPN analysis pipeline (Protocol Analysis + Security Assessment + ML Traffic Classification).
    """
    if request.source_type == "pcap_file":
        if not request.file_path:
            raise HTTPException(status_code=400, detail="file_path is required when source_type is 'pcap_file'")
        
        target_path = Path(request.file_path)
        if not target_path.is_absolute():
            target_path = PROJECT_ROOT / target_path

        if not target_path.exists():
            raise HTTPException(status_code=404, detail=f"PCAP file not found at path: {request.file_path}")

        return analyze_pcap(str(target_path))
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported source_type: {request.source_type}")
