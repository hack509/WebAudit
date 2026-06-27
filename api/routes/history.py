"""
History route — GET /api/v1/history.
"""

from fastapi import APIRouter, Query

from api.models import HistoryResponse
from storage.history import list_audits

router = APIRouter(tags=["history"])


@router.get("/history", response_model=HistoryResponse)
async def get_history(limit: int = Query(default=50, le=500, description="Max records to return")):
    """Return the N most recent audit records."""
    records = list_audits(limit=limit)
    audits = [
        {
            "id": r.id,
            "url": r.url,
            "started_at": r.started_at,
            "completed_at": r.completed_at,
            "status": r.status,
            "global_score": r.global_score,
            "global_grade": r.global_grade,
            "error": r.error,
        }
        for r in records
    ]
    return HistoryResponse(total=len(audits), audits=audits)
