"""Reference driver for extended-refusal fine-tuning (abliteration-resistant refusal).

**Reference scaffold — excluded from the test matrix by design.** It imports
``torch`` / ``transformers`` / ``trl`` / ``peft`` (the ``[research,finetune]`` extras)
and is never collected by CI. The library's only CI-gated, tested contribution is the
verification step (:func:`refusal_distribution_score`); this script wires a recipe the
operator of a *trusted node* runs externally. See
``docs/recipes/extended_refusal_finetuning.md`` for the full recipe and
``docs/internal/abliteration_threat_model.md`` for the threat it closes.

The library makes no claim to harden models — it documents this recipe and *measures*
the outcome. Producing hardened weights is the operator's responsibility.

Usage
-----
::

    pip install 'constitutional-swarm[research,finetune]'

    python scripts/finetune_extended_refusal.py \
        --model meta-llama/Llama-3.1-8B-Instruct \
        --refusal-data refusal.jsonl \
        --retain-data retain.jsonl \
        --output ./hardened-model \
        --probe-layers 8 12 16 20 24

Each ``*.jsonl`` file holds one ``{"prompt": ..., "response": ...}`` record per line
(see the recipe's *Dataset shape* table). On completion the script extracts refusal
directions at the probed layers and prints the distribution score: ~0 means
single-direction (abliteration-fragile), ~1 means distributed (hardened).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from constitutional_swarm.eval.monotonic_mas.abliteration_detector import (  # noqa: E402
    refusal_direction,
    refusal_distribution_score,
)

if TYPE_CHECKING:  # heavy deps are guard-imported inside main(); keep import-light
    import numpy as np


def _load_jsonl(path: str) -> list[dict[str, Any]]:
    """Load ``{"prompt", "response"}`` records, one JSON object per line."""
    records: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _to_chat_text(record: dict[str, Any]) -> str:
    """Flatten a record into a single training string (model-agnostic fallback)."""
    return f"{record['prompt']}\n{record['response']}"


def _require_heavy_deps() -> Any:
    """Import the training stack, with an actionable error if the extras are absent."""
    try:
        import torch  # noqa: F401
        from datasets import Dataset
        from peft import LoraConfig
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from trl import SFTConfig, SFTTrainer
    except ImportError as exc:  # pragma: no cover - exercised only by operators
        msg = (
            "extended-refusal fine-tuning needs the training extras; install with "
            "`pip install 'constitutional-swarm[research,finetune]'`"
        )
        raise SystemExit(msg) from exc
    return {
        "Dataset": Dataset,
        "LoraConfig": LoraConfig,
        "AutoModelForCausalLM": AutoModelForCausalLM,
        "AutoTokenizer": AutoTokenizer,
        "SFTConfig": SFTConfig,
        "SFTTrainer": SFTTrainer,
    }


def _extract_layer_directions(
    model: Any,
    tokenizer: Any,
    refusal: list[dict[str, Any]],
    retain: list[dict[str, Any]],
    probe_layers: list[int],
) -> np.ndarray:
    """Difference-of-means refusal direction at each probed layer.

    Runs the model with ``output_hidden_states=True`` over the harmful (refusal) and
    benign (retain) prompts, takes the last-token hidden state at each probed layer,
    and returns an ``(len(probe_layers), d_model)`` stack of unit refusal directions —
    exactly the input :func:`refusal_distribution_score` expects.
    """
    import numpy as np
    import torch

    def _last_token_hidden(prompts: list[str]) -> list[np.ndarray]:
        per_layer: list[list[np.ndarray]] = [[] for _ in probe_layers]
        for prompt in prompts:
            enc = tokenizer(prompt, return_tensors="pt").to(model.device)
            with torch.no_grad():
                out = model(**enc, output_hidden_states=True)
            for idx, layer in enumerate(probe_layers):
                vec = out.hidden_states[layer][0, -1].float().cpu().numpy()
                per_layer[idx].append(vec)
        return [np.asarray(rows) for rows in per_layer]

    harmful_by_layer = _last_token_hidden([r["prompt"] for r in refusal])
    harmless_by_layer = _last_token_hidden([r["prompt"] for r in retain])
    return np.vstack(
        [
            refusal_direction(harmful_by_layer[i], harmless_by_layer[i])
            for i in range(len(probe_layers))
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, help="HF model id or local path")
    parser.add_argument(
        "--refusal-data", required=True, help="JSONL of harmful->refusal records"
    )
    parser.add_argument(
        "--retain-data", required=True, help="JSONL of benign->helpful records"
    )
    parser.add_argument(
        "--output", default="./hardened-model", help="output dir for weights"
    )
    parser.add_argument("--method", choices=("lora", "full"), default="lora")
    parser.add_argument("--lr", type=float, default=1e-4)
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument(
        "--probe-layers",
        type=int,
        nargs="+",
        default=[8, 12, 16, 20, 24],
        help="layers to extract refusal directions from for the verification score",
    )
    parser.add_argument(
        "--skip-train",
        action="store_true",
        help="only run the distribution-score verification on --model (no fine-tuning)",
    )
    args = parser.parse_args(argv)

    deps = _require_heavy_deps()
    tokenizer = deps["AutoTokenizer"].from_pretrained(args.model)
    model = deps["AutoModelForCausalLM"].from_pretrained(
        args.model, output_hidden_states=True
    )

    refusal = _load_jsonl(args.refusal_data)
    retain = _load_jsonl(args.retain_data)

    if not args.skip_train:
        train_records = refusal + retain
        dataset = deps["Dataset"].from_dict(
            {"text": [_to_chat_text(r) for r in train_records]}
        )
        peft_config = (
            deps["LoraConfig"](r=32, lora_alpha=64, task_type="CAUSAL_LM")
            if args.method == "lora"
            else None
        )
        trainer = deps["SFTTrainer"](
            model=model,
            train_dataset=dataset,
            peft_config=peft_config,
            args=deps["SFTConfig"](
                output_dir=args.output,
                learning_rate=args.lr,
                num_train_epochs=args.epochs,
            ),
        )
        trainer.train()
        trainer.save_model(args.output)
        print(f"saved hardened model to {args.output}")

    # Verification (the CI-safe, library-owned part of the recipe).
    directions = _extract_layer_directions(
        model, tokenizer, refusal, retain, args.probe_layers
    )
    score = refusal_distribution_score(directions)
    print(
        json.dumps(
            {
                "refusal_distribution_score": round(score, 4),
                "probe_layers": args.probe_layers,
            }
        )
    )
    print(
        "~0 = single-direction (abliteration-fragile); "
        "~1 = distributed (extended-refusal hardened)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
