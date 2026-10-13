"""Offline immutable prompt/evaluator/data ledger. Records never invoke an optimizer."""

import json
import uuid

from .records import (
    ContractError,
    Database,
    FrozenRecord,
    append_only,
    canonical,
    hash_id,
    identity,
    integer,
    number,
    sha,
)

LedgerError = ContractError
MANIFEST_FIELDS = {
    "candidate",
    "model",
    "decoding",
    "dataset",
    "source_snapshot",
    "memory_snapshot",
    "evaluator",
    "policy",
    "tool_schema",
}
CONFIG_FIELDS = {
    "task_instruction",
    "system_instruction",
    "policy_digest",
    "tool_schema_digest",
    "evaluator_digest",
}
PHASE_SPLIT = {
    "train": "train",
    "reflection": "train",
    "selection": "selection",
    "test": "test",
}
FAILURES = {
    "correctness",
    "schema",
    "stale_or_unsupported_evidence",
    "correct_policy_denial",
    "incorrect_abstention",
    "policy_violation",
    "scope_violation",
    "approval_violation",
    "infrastructure",
    "evaluator_mismatch",
}
SEVERE = {
    "policy_violation",
    "scope_violation",
    "approval_violation",
    "evaluator_mismatch",
}


def dataset_manifest(families):
    if not isinstance(families, list) or len(families) != 60:
        raise LedgerError("Fixture dataset requires 60 declared families")
    seen_families = set()
    seen_tasks = set()
    groups = {}
    counts = {"train": 0, "selection": 0, "test": 0}
    for f in families:
        if set(f) != {"family_id", "source_family", "pattern", "split", "tasks"}:
            raise LedgerError("Dataset family schema mismatch")
        for k in ("family_id", "source_family", "pattern"):
            identity(f[k])
        if f["family_id"] in seen_families or f["split"] not in counts:
            raise LedgerError("Family identity/split collision")
        seen_families.add(f["family_id"])
        counts[f["split"]] += 1
        for field in ("source_family", "pattern"):
            key = (field, f[field])
            old = groups.setdefault(key, f["split"])
            if old != f["split"]:
                raise LedgerError(
                    "Related source/template families cannot cross splits"
                )
        if len(f["tasks"]) != 2:
            raise LedgerError("Two frozen paraphrases per family are required")
        for t in f["tasks"]:
            if set(t) != {"task_id", "paraphrase", "expected"}:
                raise LedgerError("Frozen task schema mismatch")
            identity(t["task_id"])
            if t["task_id"] in seen_tasks:
                raise LedgerError("Duplicate task ID")
            seen_tasks.add(t["task_id"])
            if (
                not isinstance(t["paraphrase"], str)
                or not t["paraphrase"]
                or not isinstance(t["expected"], str)
            ):
                raise LedgerError("Task and authored expectation required")
    if counts != {"train": 20, "selection": 10, "test": 30}:
        raise LedgerError("Frozen 20/10/30 family split required")
    return FrozenRecord.seal(
        {
            "protocol": "offline_dataset/v1",
            "families": families,
            "family_counts": counts,
            "labels_origin": "authored_synthetic",
            "independent_sampling_claim": False,
        }
    )


def full_manifest(*, namespace, **components):
    if set(components) != MANIFEST_FIELDS:
        raise LedgerError("Complete full-manifest components required")
    for value in components.values():
        hash_id(value)
    if not isinstance(namespace, dict) or set(namespace) != {
        "experiment",
        "arm",
        "seed",
    }:
        raise LedgerError("Explicit arm/seed namespace required")
    identity(namespace["experiment"])
    if (
        namespace["arm"] not in ("P0", "P1", "P2")
        or type(namespace["seed"]) is not int
        or namespace["seed"] not in (0, 1, 2)
    ):
        raise LedgerError("Unknown frozen arm/seed")
    return FrozenRecord.seal(
        {
            **components,
            "namespace": namespace,
            "protocol": "offline_full_manifest/v1",
            "execution_mode": "recorded_outcomes_only",
        }
    )


TABLES = (
    "experiments",
    "candidates",
    "registrations",
    "reservations",
    "results",
    "cache",
    "cache_hits",
    "freezes",
    "proposals",
)
SCHEMA = """
CREATE TABLE IF NOT EXISTS experiments (id TEXT PRIMARY KEY,body TEXT NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS candidates (digest TEXT PRIMARY KEY,body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS registrations (
 experiment TEXT NOT NULL,arm TEXT NOT NULL,seed INTEGER NOT NULL,candidate TEXT NOT NULL,
 ordinal INTEGER NOT NULL,PRIMARY KEY(experiment,arm,seed,candidate));
CREATE TABLE IF NOT EXISTS reservations (
 id TEXT PRIMARY KEY,experiment TEXT NOT NULL,arm TEXT NOT NULL,seed INTEGER NOT NULL,
 candidate TEXT NOT NULL,task_id TEXT NOT NULL,phase TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS results (attempt_id TEXT PRIMARY KEY,body TEXT NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY,body TEXT NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cache_hits (id TEXT PRIMARY KEY,experiment TEXT NOT NULL,key TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS freezes (experiment TEXT PRIMARY KEY,body TEXT NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS proposals (id TEXT PRIMARY KEY,experiment TEXT NOT NULL,arm TEXT NOT NULL,
 seed INTEGER NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL);
""" + "".join(append_only(t) for t in TABLES)


class PromptLedger(Database):
    def __init__(self, path):
        super().__init__(path, SCHEMA)

    @staticmethod
    def decode(row):
        if row is None:
            raise LedgerError("Immutable record unavailable")
        columns = tuple(row.keys())
        if "digest" in columns and sha(row["body"].encode()) != row["digest"]:
            raise LedgerError("Immutable record checksum mismatch")
        return json.loads(row["body"])

    def experiment_in(self, db, experiment):
        return self.decode(
            db.execute("SELECT * FROM experiments WHERE id=?", (experiment,)).fetchone()
        )

    def create_experiment(self, experiment, dataset, configuration, runtime_identity):
        identity(experiment)
        dataset = (
            dataset if isinstance(dataset, FrozenRecord) else dataset_manifest(dataset)
        )
        dataset_manifest(dataset.data["families"])
        if set(configuration) != CONFIG_FIELDS:
            raise LedgerError("Exact immutable base configuration required")
        if set(runtime_identity) != {
            "model",
            "decoding",
            "source_snapshot",
            "memory_snapshot",
        }:
            raise LedgerError("Frozen model/decoding/source/memory identities required")
        for digest in runtime_identity.values():
            hash_id(digest)
        for field in ("policy_digest", "tool_schema_digest", "evaluator_digest"):
            hash_id(configuration[field])
        if not all(
            isinstance(configuration[k], str) and configuration[k]
            for k in ("task_instruction", "system_instruction")
        ):
            raise LedgerError("Frozen prompt strings required")
        record = FrozenRecord.seal(
            {
                "protocol": "offline_prompt_experiment/v1",
                "experiment": experiment,
                "dataset": dataset.data,
                "dataset_digest": dataset.digest,
                "base_configuration": configuration,
                "runtime_identity": runtime_identity,
                "evaluation_contract": {
                    "mode": "recorded_outcomes_only",
                    "failure_scoring": "first_attempt_zero_on_error_v1",
                    "selection_suite_tasks": 20,
                    "choice_rule": "highest_score_then_shorter_utf8_prompt_then_digest",
                    "promotion": "not_evaluated",
                },
                "budgets": {
                    "search_per_arm_seed": 240,
                    "search_total": 1440,
                    "final_total": 180,
                    "overall": 1620,
                    "candidate_slots_per_arm_seed": 4,
                    "recorded_proposer_tokens_per_arm_seed": 16000,
                },
            }
        )
        with self.connect(True) as db:
            old = db.execute(
                "SELECT * FROM experiments WHERE id=?", (experiment,)
            ).fetchone()
            if old:
                if old["body"] != record.serialized:
                    raise LedgerError("Experiment manifest cannot change")
                return record
            db.execute(
                "INSERT INTO experiments VALUES(?,?,?)",
                (experiment, record.serialized, record.digest),
            )
            baseline = FrozenRecord.seal(
                {
                    "protocol": "offline_candidate/v1",
                    "configuration": configuration,
                    "prompt_sha256": sha(configuration["task_instruction"].encode()),
                    "base_configuration_digest": sha(canonical(configuration).encode()),
                }
            )
            db.execute(
                "INSERT OR IGNORE INTO candidates VALUES(?,?)",
                (baseline.digest, baseline.serialized),
            )
            db.execute(
                "INSERT INTO registrations VALUES(?,?,?,?,?)",
                (experiment, "P0", 0, baseline.digest, 0),
            )
            for arm in ("P1", "P2"):
                for seed in (0, 1, 2):
                    db.execute(
                        "INSERT INTO registrations VALUES(?,?,?,?,?)",
                        (experiment, arm, seed, baseline.digest, 0),
                    )
        return record

    def register_candidate(self, experiment, arm, seed, proposal):
        with self.connect(True) as db:
            exp = self.experiment_in(db, experiment)
            if db.execute(
                "SELECT 1 FROM freezes WHERE experiment=?", (experiment,)
            ).fetchone():
                raise LedgerError("Candidate artifacts are frozen before holdout")
            if (
                arm not in ("P0", "P1", "P2")
                or type(seed) is not int
                or seed not in (0, 1, 2)
                or (arm == "P0" and seed != 0)
            ):
                raise LedgerError("Unknown arm/seed")
            if set(proposal) != {"task_instruction"}:
                raise LedgerError("Only the task_instruction prompt slot may change")
            prompt = proposal["task_instruction"]
            if (
                not isinstance(prompt, str)
                or not prompt.strip()
                or len(prompt.encode()) > 4096
            ):
                raise LedgerError("Prompt slot exceeds bounded UTF-8 limit")
            config = {**exp["base_configuration"], "task_instruction": prompt}
            if arm == "P0" and config != exp["base_configuration"]:
                raise LedgerError("P0 baseline is immutable")
            record = FrozenRecord.seal(
                {
                    "protocol": "offline_candidate/v1",
                    "configuration": config,
                    "prompt_sha256": sha(prompt.encode()),
                    "base_configuration_digest": sha(
                        canonical(exp["base_configuration"]).encode()
                    ),
                }
            )
            digest = record.digest
            old = db.execute(
                "SELECT 1 FROM registrations WHERE experiment=? AND arm=? AND seed=? AND candidate=?",
                (experiment, arm, seed, digest),
            ).fetchone()
            if old:
                return FrozenRecord.seal(
                    {"candidate_digest": digest, "artifact": record.data}
                )
            count = db.execute(
                "SELECT COUNT(*) FROM registrations WHERE experiment=? AND arm=? AND seed=?",
                (experiment, arm, seed),
            ).fetchone()[0]
            if count >= (1 if arm == "P0" else 4):
                raise LedgerError("No candidate slots remain")
            db.execute(
                "INSERT OR IGNORE INTO candidates VALUES(?,?)",
                (digest, record.serialized),
            )
            db.execute(
                "INSERT INTO registrations VALUES(?,?,?,?,?)",
                (experiment, arm, seed, digest, count),
            )
            return FrozenRecord.seal(
                {"candidate_digest": digest, "artifact": record.data}
            )

    def candidate(self, digest):
        with self.connect() as db:
            row = db.execute(
                "SELECT digest,body FROM candidates WHERE digest=?", (digest,)
            ).fetchone()
            return FrozenRecord.seal(self.decode(row))

    @staticmethod
    def task(exp, task_id):
        for family in exp["dataset"]["families"]:
            for task in family["tasks"]:
                if task["task_id"] == task_id:
                    return family, task
        raise LedgerError("Task unavailable in immutable dataset")

    def dataset_view(self, experiment, role, split=None):
        with self.connect() as db:
            exp = self.experiment_in(db, experiment)
            if role == "proposer":
                if split not in (None, "train"):
                    raise LedgerError("Proposer cannot read selection/test data")
                split = "train"
            elif role == "evaluator":
                if split not in ("train", "selection", "test"):
                    raise LedgerError("Explicit evaluator split required")
                if (
                    split == "test"
                    and not db.execute(
                        "SELECT 1 FROM freezes WHERE experiment=?", (experiment,)
                    ).fetchone()
                ):
                    raise LedgerError("Holdout inaccessible before candidate freeze")
            else:
                raise LedgerError("Unknown offline role")
            return FrozenRecord.seal(
                {
                    "families": [
                        f for f in exp["dataset"]["families"] if f["split"] == split
                    ],
                    "access_boundary": "logical_offline_api_not_OS_security",
                }
            )

    def reserve(
        self, experiment, arm, seed, candidate, task_id, phase, manifest, retry_of=None
    ):
        body = manifest.data if isinstance(manifest, FrozenRecord) else manifest
        checked = full_manifest(
            namespace=body["namespace"], **{k: body[k] for k in MANIFEST_FIELDS}
        )
        if checked.data != body:
            raise LedgerError("Manifest protocol/mode mismatch")
        with self.connect(True) as db:
            exp = self.experiment_in(db, experiment)
            if arm == "P0" and phase != "test":
                raise LedgerError("P0 consumes only its frozen final allowance")
            if not db.execute(
                "SELECT 1 FROM registrations WHERE experiment=? AND arm=? AND seed=? AND candidate=?",
                (experiment, arm, seed, candidate),
            ).fetchone():
                raise LedgerError("Candidate registration mismatch")
            family, task = self.task(exp, task_id)
            if phase not in PHASE_SPLIT or family["split"] != PHASE_SPLIT[phase]:
                raise LedgerError("Family/split/phase isolation violation")
            if body["namespace"] != {
                "experiment": experiment,
                "arm": arm,
                "seed": seed,
            }:
                raise LedgerError("Arm/seed namespace mismatch")
            if (
                body["candidate"] != candidate
                or body["dataset"] != exp["dataset_digest"]
                or body["evaluator"] != exp["base_configuration"]["evaluator_digest"]
                or body["policy"] != exp["base_configuration"]["policy_digest"]
                or body["tool_schema"]
                != exp["base_configuration"]["tool_schema_digest"]
                or any(body[k] != v for k, v in exp["runtime_identity"].items())
            ):
                raise LedgerError(
                    "Manifest does not match the complete frozen experiment identity"
                )
            frozen = db.execute(
                "SELECT * FROM freezes WHERE experiment=?", (experiment,)
            ).fetchone()
            if phase == "test":
                if (
                    not frozen
                    or self.decode(frozen).get(arm) != candidate
                    or self.decode(frozen)["selected_seeds"][arm] != seed
                ):
                    raise LedgerError(
                        "Only the selected frozen arm artifact may consume holdout"
                    )
            elif frozen:
                raise LedgerError("Search/selection is closed after candidate freeze")
            count = db.execute(
                "SELECT COUNT(*) FROM reservations WHERE experiment=?", (experiment,)
            ).fetchone()[0]
            if count >= 1620:
                raise LedgerError("Inclusive overall task execution cap exhausted")
            if phase == "test":
                n = db.execute(
                    "SELECT COUNT(*) FROM reservations WHERE experiment=? AND phase='test'",
                    (experiment,),
                ).fetchone()[0]
                if n >= 180:
                    raise LedgerError("Final allowance includes failures and retries")
            else:
                n = db.execute(
                    "SELECT COUNT(*) FROM reservations WHERE experiment=? AND phase!='test'",
                    (experiment,),
                ).fetchone()[0]
                per = db.execute(
                    "SELECT COUNT(*) FROM reservations WHERE experiment=? AND arm=? AND seed=? AND phase!='test'",
                    (experiment, arm, seed),
                ).fetchone()[0]
                if n >= 1440 or per >= 240:
                    raise LedgerError("Search/reflection allowance exhausted")
            if retry_of:
                previous = db.execute(
                    "SELECT * FROM reservations WHERE id=?", (retry_of,)
                ).fetchone()
                if not previous or (
                    previous["experiment"],
                    previous["arm"],
                    previous["seed"],
                    previous["candidate"],
                    previous["task_id"],
                    previous["phase"],
                ) != (experiment, arm, seed, candidate, task_id, phase):
                    raise LedgerError(
                        "Retry must preserve original case/arm/seed/phase lineage"
                    )
            attempt = str(uuid.uuid4())
            record = FrozenRecord.seal(
                {
                    "attempt_id": attempt,
                    "experiment": experiment,
                    "arm": arm,
                    "seed": seed,
                    "candidate_digest": candidate,
                    "task_id": task_id,
                    "family_id": family["family_id"],
                    "phase": phase,
                    "manifest": body,
                    "manifest_digest": checked.digest,
                    "retry_of": retry_of,
                    "checkpoint_namespace": sha(
                        canonical([experiment, arm, seed, task_id, attempt]).encode()
                    ),
                    "expected_behavior": task["expected"],
                    "model_calls_executed": 0,
                }
            )
            db.execute(
                "INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    attempt,
                    experiment,
                    arm,
                    seed,
                    candidate,
                    task_id,
                    phase,
                    record.serialized,
                    record.digest,
                ),
            )
            return attempt

    def finish(self, attempt_id, score, status, raw_output, failure_type):
        number(score)
        if status not in (
            "success",
            "correct_denial",
            "failure",
            "timeout",
            "malformed",
            "refusal",
            "infrastructure",
        ):
            raise LedgerError("Unknown recorded result status")
        if failure_type is not None and failure_type not in FAILURES:
            raise LedgerError("Typed failure category required")
        if status not in ("success", "correct_denial") and (
            score != 0 or failure_type is None
        ):
            raise LedgerError(
                "Prespecified failure scoring retains zero/error outcomes"
            )
        if status == "correct_denial" and failure_type != "correct_policy_denial":
            raise LedgerError("Correct denials must stay distinct")
        if not isinstance(raw_output, str) or len(raw_output.encode()) > 50000:
            raise LedgerError("Retain a bounded original recorded output")
        with self.connect(True) as db:
            reservation = db.execute(
                "SELECT * FROM reservations WHERE id=?", (attempt_id,)
            ).fetchone()
            source = self.decode(reservation)
            frozen = db.execute(
                "SELECT 1 FROM freezes WHERE experiment=?", (source["experiment"],)
            ).fetchone()
            completed = db.execute(
                "SELECT 1 FROM results WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if frozen and source["phase"] != "test" and not completed:
                raise LedgerError(
                    "Search outcomes cannot arrive after selection freeze"
                )
            result = FrozenRecord.seal(
                {
                    **source,
                    "score": score,
                    "status": status,
                    "raw_output": raw_output,
                    "raw_output_sha256": sha(raw_output.encode()),
                    "failure_type": failure_type,
                    "evaluator_digest": source["manifest"]["evaluator"],
                    "source_snapshot_digest": source["manifest"]["source_snapshot"],
                    "model_identity_digest": source["manifest"]["model"],
                    "evidence_references": [
                        {
                            "kind": "source_snapshot",
                            "digest": source["manifest"]["source_snapshot"],
                        },
                        {
                            "kind": "task",
                            "task_id": source["task_id"],
                            "family_id": source["family_id"],
                        },
                    ],
                    "remediation_hypothesis": None
                    if failure_type in (None, "correct_policy_denial")
                    else f"Check the recorded {failure_type} discrepancy against its frozen source and evaluator.",
                    "promotion": "not_evaluated",
                }
            )
            old = db.execute(
                "SELECT * FROM results WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if old:
                if old["body"] != result.serialized:
                    raise LedgerError("Completed result cannot be rewritten")
                return result
            db.execute(
                "INSERT INTO results VALUES(?,?,?)",
                (attempt_id, result.serialized, result.digest),
            )
            return result

    @staticmethod
    def cache_key(manifest, split, task_id):
        body = manifest.data if isinstance(manifest, FrozenRecord) else manifest
        if split not in ("train", "selection", "test"):
            raise LedgerError("Explicit cache split required")
        identity(task_id)
        return sha(
            canonical(
                {"full_manifest": body, "split": split, "task_id": task_id}
            ).encode()
        )

    def cache_put(self, attempt_id):
        with self.connect(True) as db:
            result = self.decode(
                db.execute(
                    "SELECT * FROM results WHERE attempt_id=?", (attempt_id,)
                ).fetchone()
            )
            split = PHASE_SPLIT[result["phase"]]
            key = self.cache_key(result["manifest"], split, result["task_id"])
            body = canonical(result)
            digest = sha(body.encode())
            old = db.execute("SELECT body FROM cache WHERE key=?", (key,)).fetchone()
            if old:
                if old[0] != body:
                    raise LedgerError("Full-manifest cache entry cannot be overwritten")
                return
            db.execute("INSERT INTO cache VALUES(?,?,?)", (key, body, digest))

    def cache_get(self, manifest, split, task_id, role):
        if role == "proposer" and split != "train":
            raise LedgerError("Proposer cannot consume heldout/selection cache")
        if role not in ("proposer", "evaluator"):
            raise LedgerError("Unknown cache role")
        key = self.cache_key(manifest, split, task_id)
        with self.connect(True) as db:
            row = db.execute("SELECT * FROM cache WHERE key=?", (key,)).fetchone()
            if not row:
                return None
            result = self.decode(row)
            db.execute(
                "INSERT INTO cache_hits VALUES(?,?,?)",
                (str(uuid.uuid4()), result["experiment"], key),
            )
            return FrozenRecord.seal(result)

    def feedback(self, experiment, role, *, arm, seed):
        if role != "proposer":
            raise LedgerError("Only declared proposer feedback is supported")
        if arm not in ("P1", "P2") or type(seed) is not int or seed not in (0, 1, 2):
            raise LedgerError("Explicit search-arm/seed feedback namespace required")
        with self.connect() as db:
            self.experiment_in(db, experiment)
            records = []
            for row in db.execute(
                "SELECT results.* FROM results JOIN reservations ON results.attempt_id=reservations.id WHERE reservations.experiment=? AND reservations.arm=? AND reservations.seed=? AND reservations.phase IN ('train','reflection') ORDER BY reservations.rowid",
                (experiment, arm, seed),
            ):
                result = self.decode(row)
                records.append(
                    result
                    if arm == "P2"
                    else {
                        k: result[k]
                        for k in (
                            "attempt_id",
                            "candidate_digest",
                            "task_id",
                            "family_id",
                            "phase",
                            "score",
                            "status",
                            "model_calls_executed",
                        )
                    }
                )
            return FrozenRecord.seal(
                {
                    "records": records,
                    "holdout_feedback": "inaccessible",
                    "arm": arm,
                    "seed": seed,
                    "feedback_mode": "typed_evidence" if arm == "P2" else "scalar",
                }
            )

    def freeze_selection(self, experiment):
        with self.connect(True) as db:
            old = db.execute(
                "SELECT * FROM freezes WHERE experiment=?", (experiment,)
            ).fetchone()
            if old:
                return FrozenRecord.seal(self.decode(old))
            exp = self.experiment_in(db, experiment)
            if db.execute(
                "SELECT 1 FROM reservations LEFT JOIN results ON reservations.id=results.attempt_id WHERE reservations.experiment=? AND results.attempt_id IS NULL LIMIT 1",
                (experiment,),
            ).fetchone():
                raise LedgerError(
                    "All reserved outcomes must finish before selection freeze"
                )
            required = {
                t["task_id"]
                for f in exp["dataset"]["families"]
                if f["split"] == "selection"
                for t in f["tasks"]
            }
            chosen = {}
            selected_seeds = {"P0": 0}
            baseline = db.execute(
                "SELECT candidate FROM registrations WHERE experiment=? AND arm='P0'",
                (experiment,),
            ).fetchone()
            if not baseline:
                raise LedgerError("Frozen P0 baseline required")
            chosen["P0"] = baseline[0]
            for arm in ("P1", "P2"):
                eligible = []
                for registration in db.execute(
                    "SELECT * FROM registrations WHERE experiment=? AND arm=?",
                    (experiment, arm),
                ):
                    candidate = registration["candidate"]
                    seed = registration["seed"]
                    all_results = [
                        self.decode(row)
                        for row in db.execute(
                            "SELECT results.* FROM results JOIN reservations ON results.attempt_id=reservations.id WHERE reservations.experiment=? AND reservations.arm=? AND reservations.seed=? AND reservations.candidate=? ORDER BY reservations.rowid",
                            (experiment, arm, seed, candidate),
                        )
                    ]
                    if any(r["failure_type"] in SEVERE for r in all_results):
                        continue
                    first = {}
                    for result in all_results:
                        if (
                            result["phase"] == "selection"
                            and result["retry_of"] is None
                        ):
                            first.setdefault(result["task_id"], result)
                    if set(first) != required:
                        continue
                    score = sum(r["score"] for r in first.values()) / len(required)
                    artifact = self.decode(
                        db.execute(
                            "SELECT * FROM candidates WHERE digest=?", (candidate,)
                        ).fetchone()
                    )
                    size = len(artifact["configuration"]["task_instruction"].encode())
                    eligible.append((-score, size, candidate, seed))
                if not eligible:
                    raise LedgerError(
                        "Incomplete/noncompliant candidates cannot compete on smaller denominators"
                    )
                winner = min(eligible)
                chosen[arm] = winner[2]
                selected_seeds[arm] = winner[3]
            record = FrozenRecord.seal(
                {
                    **chosen,
                    "runtime_identity": exp["runtime_identity"],
                    "selected_seeds": selected_seeds,
                    "selected_manifests": {
                        arm: full_manifest(
                            candidate=candidate,
                            dataset=exp["dataset_digest"],
                            evaluator=exp["base_configuration"]["evaluator_digest"],
                            policy=exp["base_configuration"]["policy_digest"],
                            tool_schema=exp["base_configuration"]["tool_schema_digest"],
                            namespace={
                                "experiment": experiment,
                                "arm": arm,
                                "seed": selected_seeds[arm],
                            },
                            **exp["runtime_identity"],
                        ).data
                        for arm, candidate in chosen.items()
                    },
                    "protocol": "offline_selection_freeze/v1",
                    "choice_basis": "complete_selection_only",
                    "test_labels_used": False,
                    "promotion": "not_evaluated",
                }
            )
            db.execute(
                "INSERT INTO freezes VALUES(?,?,?)",
                (experiment, record.serialized, record.digest),
            )
            return record

    def counts(self, experiment):
        with self.connect() as db:
            count = db.execute(
                "SELECT COUNT(*) FROM reservations WHERE experiment=?", (experiment,)
            ).fetchone()[0]
            missing = db.execute(
                "SELECT COUNT(*) FROM reservations LEFT JOIN results ON reservations.id=results.attempt_id WHERE reservations.experiment=? AND results.attempt_id IS NULL",
                (experiment,),
            ).fetchone()[0]
            proposals = [
                self.decode(r)
                for r in db.execute(
                    "SELECT * FROM proposals WHERE experiment=?", (experiment,)
                )
            ]
            return {
                "task_executions": count,
                "incomplete_reservations": missing,
                "cache_hits": db.execute(
                    "SELECT COUNT(*) FROM cache_hits WHERE experiment=?", (experiment,)
                ).fetchone()[0],
                "recorded_proposer_tokens": sum(
                    p["recorded_tokens"] for p in proposals
                ),
                "recorded_proposal_events": len(proposals),
                "model_calls_executed": 0,
                "budget_unit": "recorded_fixture_execution_reservations",
            }

    def record_proposal(
        self, experiment, arm, seed, proposal_id, raw, tokens, failure_type
    ):
        identity(proposal_id)
        integer(tokens)
        if arm not in ("P1", "P2") or type(seed) is not int or seed not in (0, 1, 2):
            raise LedgerError("Unknown search arm/seed")
        if failure_type is not None and failure_type not in FAILURES:
            raise LedgerError("Typed proposal failure required")
        if not isinstance(raw, str) or len(raw.encode()) > 50000:
            raise LedgerError("Bounded original recorded proposal required")
        record = FrozenRecord.seal(
            {
                "experiment": experiment,
                "arm": arm,
                "seed": seed,
                "proposal_id": proposal_id,
                "raw_recorded_proposal": raw,
                "recorded_tokens": tokens,
                "failure_type": failure_type,
                "actual_model_calls": 0,
                "actual_model_tokens": 0,
                "actual_model_cost": 0,
            }
        )
        with self.connect(True) as db:
            self.experiment_in(db, experiment)
            if db.execute(
                "SELECT 1 FROM freezes WHERE experiment=?", (experiment,)
            ).fetchone():
                raise LedgerError("Proposals cannot consume sealed-test feedback")
            old = db.execute(
                "SELECT * FROM proposals WHERE id=?", (proposal_id,)
            ).fetchone()
            if old:
                if old["body"] != record.serialized:
                    raise LedgerError("Proposal identity collision")
                return record
            used = sum(
                self.decode(row)["recorded_tokens"]
                for row in db.execute(
                    "SELECT * FROM proposals WHERE experiment=? AND arm=? AND seed=?",
                    (experiment, arm, seed),
                )
            )
            if used + tokens > 16000:
                raise LedgerError("Recorded proposer-token allocation exhausted")
            db.execute(
                "INSERT INTO proposals VALUES(?,?,?,?,?,?)",
                (proposal_id, experiment, arm, seed, record.serialized, record.digest),
            )
            return record

    def final_status(self, experiment):
        with self.connect() as db:
            exp = self.experiment_in(db, experiment)
            required = {
                t["task_id"]
                for f in exp["dataset"]["families"]
                if f["split"] == "test"
                for t in f["tasks"]
            }
            frozen = db.execute(
                "SELECT * FROM freezes WHERE experiment=?", (experiment,)
            ).fetchone()
            if not frozen:
                return "not_opened"
            selected = self.decode(frozen)
            for arm in ("P0", "P1", "P2"):
                tasks = {
                    r["task_id"]
                    for r in db.execute(
                        "SELECT reservations.task_id FROM reservations JOIN results ON reservations.id=results.attempt_id WHERE reservations.experiment=? AND reservations.arm=? AND reservations.candidate=? AND reservations.phase='test'",
                        (experiment, arm, selected[arm]),
                    )
                }
                if tasks != required:
                    return "incomplete_inconclusive"
            return "recorded_matrix_complete_not_model_quality"

    def promotion_status(self, experiment):
        with self.connect() as db:
            self.experiment_in(db, experiment)
        return "not_evaluated"
