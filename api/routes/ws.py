"""
WebSocket route — GET /api/v1/ws/audit/{task_id}

Pushes real-time audit progress events to connected clients.
The background audit task publishes events via the module-level
`publish_event()` function; the WebSocket handler forwards them.

Protocol (server → client, JSON):
    {"event": "status",   "status": "running", "task_id": "..."}
    {"event": "module",   "module": "backend",  "status": "running"}
    {"event": "module",   "module": "backend",  "status": "completed",
     "score": 78.5, "grade": "C", "findings": 12}
    {"event": "complete", "global_score": 81.0, "global_grade": "B"}
    {"event": "error",    "message": "..."}
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from utils.logger import get_logger

logger = get_logger("api.ws")
router = APIRouter(tags=["websocket"])

# task_id → list of async queues (one per connected client)
_subscribers: dict[str, list[asyncio.Queue[Any]]] = defaultdict(list)


def publish_event(task_id: str, event: dict) -> None:
    """Called from the audit background task to push events to subscribers."""
    for q in _subscribers.get(task_id, []):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


@router.websocket("/ws/audit/{task_id}")
async def audit_progress(websocket: WebSocket, task_id: str) -> None:
    """Stream audit progress for a given task_id."""
    await websocket.accept()

    queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=128)
    _subscribers[task_id].append(queue)
    logger.debug(f"WS client connected for task {task_id}")

    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Heartbeat so the connection stays alive
                await websocket.send_json({"event": "ping"})
                continue

            await websocket.send_json(event)

            # Terminal events — close the connection
            if event.get("event") in ("complete", "error"):
                break

    except WebSocketDisconnect:
        logger.debug(f"WS client disconnected for task {task_id}")
    except Exception as e:
        logger.warning(f"WS error for task {task_id}: {e}")
    finally:
        _subscribers[task_id].remove(queue)
        if not _subscribers[task_id]:
            del _subscribers[task_id]
