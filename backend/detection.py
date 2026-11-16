"""Background detector: polls the rule-14 packet counter (plan section 5.1).

Started in the FastAPI lifespan. Each tick calls ``Workflow.poll_counter``,
which reads the counter through the shared lab lock and opens an incident
when the counter rose and no incident is open.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from backend.workflow import Workflow

log = logging.getLogger("backend.detection")


class Detector:
    def __init__(self, workflow: Workflow, interval: float) -> None:
        self.workflow = workflow
        self.interval = interval
        self._task: Optional[asyncio.Task] = None
        self._last_error: Optional[str] = None

    async def tick(self) -> None:
        try:
            await self.workflow.poll_counter()
            if self._last_error:
                log.info("Detector recovered")
            self._last_error = None
        except asyncio.CancelledError:
            raise
        except Exception as e:  # keep polling; log each distinct error once
            msg = str(e)
            if msg != self._last_error:
                log.warning("Detector could not read the rule-14 counter: %s", msg)
            self._last_error = msg

    async def run(self) -> None:
        while True:
            await self.tick()
            await asyncio.sleep(self.interval)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self.run(), name="rule14-detector")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
