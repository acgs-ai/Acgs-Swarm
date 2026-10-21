#!/usr/bin/env python3
"""Generate the additive APCC-1 duration revision from hash-pinned v1 inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INPUTS = {
    "matrix.v1.json": "f919446ca5fae99d2297161959e0017250c402e542275a369b55b8281d158721",
    "raw-result.schema.json": "7d869fd99381cd0ec65a1e9780ddf82b9a0700f11319c371f7b909a60a44fbae",
}


def generated_payloads(source: Path) -> dict[str, bytes]:
    values = {}
    for name, expected in INPUTS.items():
        raw = (source / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"frozen input hash mismatch: {name}")
        values[name] = json.loads(raw)
    matrix = values["matrix.v1.json"]
    matrix["revision"] = "apcc-1.matrix.v2"
    matrix["performance_duration_policy"] = (
        "max-base-duration-ceil-minimum-operations-over-target-rate"
    )
    schema = values["raw-result.schema.json"]
    schema["$id"] = (
        "https://constitutional-swarm.local/schemas/apcc-1/raw-result.v2.json"
    )
    schema["properties"]["matrix_revision"]["const"] = "apcc-1.matrix.v2"
    schema["properties"]["schema_version"]["const"] = "apcc-1.raw-result.v2"
    matrix_raw = (
        json.dumps(matrix, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    schema["properties"]["matrix_sha256"]["const"] = hashlib.sha256(
        matrix_raw
    ).hexdigest()
    duration_clause = schema["allOf"][4]["then"]
    duration_clause["properties"]["workload_evidence"]["properties"][
        "duration_seconds"
    ] = {"enum": [30, 100, 1000]}
    duration_clause["allOf"] = [
        {
            "if": {"properties": {"target_rate_per_second": {"const": rate}}},
            "then": {
                "properties": {
                    "workload_evidence": {
                        "properties": {"duration_seconds": {"const": duration}}
                    }
                }
            },
        }
        for rate, duration in ((10, 1000), (100, 100), (500, 30))
    ]
    return {
        name: (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n"
        ).encode("utf-8")
        for name, value in (
            ("matrix.v2.json", matrix),
            ("raw-result.v2.schema.json", schema),
        )
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "experiments" / "apcc-1")
    parser.add_argument("--output", type=Path, default=ROOT / "experiments" / "apcc-1")
    parser.add_argument(
        "--check", action="store_true", help="Verify outputs without writing"
    )
    parser.add_argument(
        "--replace", action="store_true", help="Regenerate differing v2 outputs"
    )
    args = parser.parse_args()
    for name, raw in generated_payloads(args.source).items():
        path = args.output / name
        if args.check:
            if not path.is_file() or path.read_bytes() != raw:
                raise SystemExit(f"generated output differs: {path}")
        else:
            args.output.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                raise SystemExit(f"refusing symlink output: {path}")
            if path.exists() and path.read_bytes() != raw and not args.replace:
                raise SystemExit(f"refusing to replace differing output: {path}")
            if args.replace:
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=f".{name}.", dir=args.output
                )
                temporary = Path(temporary_name)
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(raw)
                    temporary.chmod(0o644)
                    os.replace(temporary, path)
                finally:
                    temporary.unlink(missing_ok=True)
            elif not path.exists():
                with path.open("xb") as stream:
                    stream.write(raw)
                path.chmod(0o644)
        print(f"{hashlib.sha256(raw).hexdigest()}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
