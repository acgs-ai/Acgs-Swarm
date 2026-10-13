"""Create authored synthetic records locally; no model, optimizer or service."""

import argparse
import json
from pathlib import Path

from .decisions import DecisionAttempts, build_envelope, fixture_coverage
from .evidence import Access, EvidenceStore, Scope
from .prompt_ledger import PromptLedger, dataset_manifest, full_manifest
from .records import sha


def generate(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    req = {
        "schema_version": 1,
        "case_id": "synthetic-spelling-review",
        "instruction": "Recommend a read-only review capability. Never launch work.",
        "state": "Authored fixture: a spelling correction in a procedure.",
        "options": [
            {"id": role, "role": role, "meaning": meaning}
            for role, meaning in (
                ("docs", "Review documentation wording"),
                ("tests", "Review declared unit-test behavior"),
                ("code", "Review specified implementation"),
                ("escalate", "Scope or evidence is insufficient"),
            )
        ],
        "identity": {
            "model": "recorded-synthetic-v1",
            "model_revision": "fixture-v1",
            "config_digest": "1" * 64,
            "schema_digest": "2" * 64,
            "adapter_digest": "3" * 64,
            "weights_digest": None,
            "tokenizer_digest": None,
        },
        "gate": {
            "metric": "answer_confidence",
            "thresholds": {"choice:3-5": 0.8},
            "calibrated": False,
        },
    }
    raw = {
        "type": "choice",
        "choice": "docs",
        "probabilities": {"docs": 0.8, "tests": 0.1, "code": 0.05, "escalate": 0.05},
        "answer_confidence": 0.8,
        "confidence": 0.5,
        "coverage": fixture_coverage(req),
        "selection_provenance": "full_option_pool",
    }
    decision = build_envelope(req, raw)
    DecisionAttempts(output / "decisions.db").append(
        "attempt-1", req["case_id"], "success", json.dumps(raw)
    )
    scope = Scope("synthetic-tenant", "synthetic-project", "task", "task", "run")
    store = EvidenceStore(output / "evidence.db")
    records = []
    for order, value in ((1, "review every 30 days"), (2, "review every 7 days")):
        text = f"Authored fixture revision {order}: {value}"
        record = {
            "evidence_id": f"e{order}",
            "source_locator": "fixture://procedure",
            "source_revision": f"r{order}",
            "revision_order": order,
            "source_text": text,
            "content_sha256": sha(text.encode()),
            "claim_key": "review-interval",
            "claim_value": value,
            "claim_type": "observed_fact",
            "observed_at_ms": order * 10,
            "valid_from_ms": order * 10,
            "valid_to_ms": None,
            "authority_class": "authored_fixture",
            "extraction_version": "gold-v1",
            "provenance": [],
        }
        store.append(scope, record)
        records.append(record)
    ctx = Access(
        scope,
        100,
        {(r["source_locator"], r["source_revision"]) for r in records},
        {
            (r["source_locator"], r["source_revision"]): r["content_sha256"]
            for r in records
        },
    )
    old = store.query(ctx, "review-interval", cutoff=15, valid_at=15)
    current = store.query(ctx, "review-interval", cutoff=100, valid_at=50)
    store.revoke(scope, "revoke-e2", "e2", 70, 70, "Authored revocation fixture")
    consumed = store.consume(current, ctx)
    families = [
        {
            "family_id": f"family-{i}",
            "source_family": f"source-{i}",
            "pattern": f"pattern-{i}",
            "split": "train" if i < 20 else "selection" if i < 30 else "test",
            "tasks": [
                {
                    "task_id": f"task-{i}-{j}",
                    "paraphrase": f"Authored synthetic maintenance fixture {i}, variant {j}",
                    "expected": "authored fixture outcome",
                }
                for j in range(2)
            ],
        }
        for i in range(60)
    ]
    dataset = dataset_manifest(families)
    config = {
        "task_instruction": "Review the authored fixture.",
        "system_instruction": "Read-only synthetic harness.",
        "policy_digest": "a" * 64,
        "tool_schema_digest": "b" * 64,
        "evaluator_digest": "c" * 64,
    }
    runtime = {
        "model": "1" * 64,
        "decoding": "2" * 64,
        "source_snapshot": "4" * 64,
        "memory_snapshot": "5" * 64,
    }
    ledger = PromptLedger(output / "prompts.db")
    experiment = ledger.create_experiment("synthetic-demo", dataset, config, runtime)

    def manifest(candidate, arm, seed):
        return full_manifest(
            candidate=candidate,
            dataset=dataset.digest,
            evaluator=config["evaluator_digest"],
            policy=config["policy_digest"],
            tool_schema=config["tool_schema_digest"],
            namespace={"experiment": "synthetic-demo", "arm": arm, "seed": seed},
            **runtime,
        )

    for arm in ("P1", "P2"):
        candidate = ledger.register_candidate(
            "synthetic-demo",
            arm,
            0,
            {"task_instruction": f"Authored {arm} prompt fixture."},
        ).data["candidate_digest"]
        for family in families[20:30]:
            for task in family["tasks"]:
                attempt = ledger.reserve(
                    "synthetic-demo",
                    arm,
                    0,
                    candidate,
                    task["task_id"],
                    "selection",
                    manifest(candidate, arm, 0),
                )
                ledger.finish(
                    attempt,
                    score=1,
                    status="success",
                    raw_output="Authored passing result; no task/model executed.",
                    failure_type=None,
                )
    frozen = ledger.freeze_selection("synthetic-demo")
    for arm in ("P0", "P1", "P2"):
        candidate = frozen.data[arm]
        for family in families[30:]:
            for task in family["tasks"]:
                attempt = ledger.reserve(
                    "synthetic-demo",
                    arm,
                    0,
                    candidate,
                    task["task_id"],
                    "test",
                    manifest(candidate, arm, 0),
                )
                ledger.finish(
                    attempt,
                    score=1,
                    status="success",
                    raw_output="Authored passing holdout record; no model quality measured.",
                    failure_type=None,
                )
    snapshot = {
        "mode": "authored_synthetic_only",
        "decision": decision.data,
        "as_known_then": old.data,
        "before_revocation": current.data,
        "consume_after_revocation": consumed.data,
        "prompt_experiment": experiment.data,
        "selection_freeze": frozen.data,
        "prompt_counts": ledger.counts("synthetic-demo"),
        "final_status": ledger.final_status("synthetic-demo"),
        "promotion": ledger.promotion_status("synthetic-demo"),
        "model_calls_executed": 0,
        "quality_conclusion": "none; all scores and expectations are authored fixtures",
    }
    (output / "synthetic-records.json").write_text(
        json.dumps(snapshot, indent=2) + "\n"
    )
    return snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Fresh directory; existing paths are refused",
    )
    args = parser.parse_args()
    snapshot = generate(args.output)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "mode": snapshot["mode"],
                "model_calls_executed": 0,
                "counts": snapshot["prompt_counts"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
