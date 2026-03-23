"""LLM cost estimation and tracking."""
from __future__ import annotations

import json
import os
from pathlib import Path

# Pricing per 1M tokens (USD) as of 2026-03
_PRICING: dict[str, dict[str, float]] = {
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
    "claude-sonnet-4-6-20250827": {"input": 3.00, "output": 15.00},
    "claude-opus-4-6-20250826": {"input": 15.00, "output": 75.00},
}


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost in USD for a single LLM call."""
    pricing = _PRICING.get(model, {"input": 3.0, "output": 15.0})
    return (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000


def check_budget(run_dir: Path) -> tuple[bool, float, float]:
    """Check if LLM budget allows more calls. Returns (allowed, spent, budget)."""
    budget_str = os.environ.get("AIEDGE_LLM_BUDGET_USD")
    if not budget_str:
        return True, 0.0, float("inf")
    try:
        budget = float(budget_str)
    except ValueError:
        return True, 0.0, float("inf")

    cost_path = run_dir / "stages" / "llm_cost" / "cost_summary.json"
    spent = 0.0
    if cost_path.is_file():
        try:
            data = json.loads(cost_path.read_text(encoding="utf-8"))
            spent = float(data.get("total_cost_usd", 0.0))
        except Exception:
            pass
    return spent < budget, spent, budget


def record_cost(run_dir: Path, model: str, input_tokens: int, output_tokens: int) -> None:
    """Record LLM cost to cost_summary.json."""
    cost_dir = run_dir / "stages" / "llm_cost"
    cost_dir.mkdir(parents=True, exist_ok=True)
    cost_path = cost_dir / "cost_summary.json"

    existing: dict[str, object] = {}
    if cost_path.is_file():
        try:
            existing = json.loads(cost_path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}

    call_cost = estimate_cost(model, input_tokens, output_tokens)
    total = float(existing.get("total_cost_usd", 0.0)) + call_cost  # type: ignore[arg-type]
    calls = int(existing.get("total_calls", 0)) + 1  # type: ignore[arg-type]
    total_input = int(existing.get("total_input_tokens", 0)) + input_tokens  # type: ignore[arg-type]
    total_output = int(existing.get("total_output_tokens", 0)) + output_tokens  # type: ignore[arg-type]

    summary = {
        "total_cost_usd": round(total, 6),
        "total_calls": calls,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "last_model": model,
        "last_call_cost_usd": round(call_cost, 6),
    }
    cost_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
