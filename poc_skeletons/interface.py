from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class PoCResult:
    success: bool
    proof_type: str
    proof_evidence: str
    timestamp: str


class PoCInterface(Protocol):
    chain_id: str
    target_service: str

    def setup(
        self,
        target_ip: str,
        target_port: int,
        *,
        context: dict[str, object],
    ) -> None: ...

    def execute(self) -> PoCResult: ...

    def cleanup(self) -> None: ...
