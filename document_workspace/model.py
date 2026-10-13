"""Deterministic lexical comparison. Source instructions are never executed."""

import difflib
import hashlib
import json

MODEL_ID = "synthetic-line-diff-v1"
MAX_CHANGES = 12


class ComparisonCancelled(Exception):
    pass


def check(callback):
    if callback and callback():
        raise ComparisonCancelled()


def excerpts(text):
    snippet = " ".join(text.split()[:12])[:160]
    return snippet + (" …" if snippet != " ".join(text.split()) else "")


def bounded_opcodes(a, b, cancel=None):
    check(cancel)
    if len(a) * len(b) <= 1_000_000:
        # Small inputs get granular changes. Large inputs use a linear scan:
        # repeated lines must never turn the 50KB contract into unbounded work.
        return difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()
    start, end = 0, 0
    while start < min(len(a), len(b)) and a[start] == b[start]:
        if start % 256 == 0:
            check(cancel)
        start += 1
    while end < min(len(a), len(b)) - start and a[-end - 1] == b[-end - 1]:
        if end % 256 == 0:
            check(cancel)
        end += 1
    j, l = len(a) - end, len(b) - end
    if start == j and start == l:
        return []
    kind = "insert" if start == j else "delete" if start == l else "replace"
    return [(kind, start, j, start, l)]


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def evidence(source, lines, start, end):
    raw = source["text"].encode("utf-8")
    a = len("".join(lines[:start]).encode("utf-8"))
    b = len("".join(lines[:end]).encode("utf-8"))
    return {
        "source_id": source["id"],
        "source_sha256": source["file_sha256"],
        "start": a,
        "end": b,
        "quote": raw[a:b].decode("utf-8"),
        "comparison_anchor": a == b,
        "locator": source["locator"] + f"?start={a}&end={b}",
    }


def changes(sources, cancel=None):
    old, new = sources
    a, b = old["text"].splitlines(keepends=True), new["text"].splitlines(keepends=True)
    result = []
    for count, (kind, i, j, k, l) in enumerate(bounded_opcodes(a, b, cancel)):
        if count % 64 == 0:
            check(cancel)
        if kind == "equal":
            continue
        before, after = evidence(old, a, i, j), evidence(new, b, k, l)
        result.append(
            {
                "id": f"claim-{len(result) + 1}",
                "kind": kind,
                "statement": {
                    "replace": f"Replaced “{excerpts(before['quote'])}” with “{excerpts(after['quote'])}”.",
                    "insert": f"Added “{excerpts(after['quote'])}” to the current text.",
                    "delete": f"Removed “{excerpts(before['quote'])}” from the current text.",
                }[kind],
                "support": "deterministic_lexical_comparison",
                "evidence": [before, after],
            }
        )
    if not result:
        result = [
            {
                "id": "claim-1",
                "kind": "unchanged",
                "statement": "The submitted texts are identical.",
                "support": "deterministic_lexical_comparison",
                "evidence": [evidence(old, a, 0, len(a)), evidence(new, b, 0, len(b))],
            }
        ]
    return result


def compare(sources, cancel=None):
    claims = changes(sources, cancel)
    # The brief contains only neutral comparison statements. Exact source text
    # lives in structured claim records and is rendered as escaped text by React.
    text = "# Changes\n\n"
    for c in claims[:MAX_CHANGES]:
        text += f"- [{c['id']}] {c['statement']}\n"
        for role, ref in zip(("prior", "current"), c["evidence"], strict=True):
            text += (
                f"  - {role}: [{ref['source_id']}]({ref['locator']}) · "
                f"SHA-256 {ref['source_sha256']} · UTF-8 bytes {ref['start']}:{ref['end']}.\n"
            )
    text += (
        "\n\n# Operational implications\n\n"
        "Inference: a human should assess whether the textual changes affect procedure execution. "
        "No operational impact, owner, deadline or commitment is established by this fixture.\n\n"
        "# Open questions\n\n"
        "Do the compared passages express the intended procedure? Are approvals or missing context needed?\n"
    )
    return {
        "model_id": MODEL_ID,
        "text": text,
        "claims": claims,
        "semantic_evaluation": "human_required",
        "comparison_complete": len(claims) <= MAX_CHANGES,
    }


def validate(sources, payload):
    errors = []
    try:
        text = payload["text"]
        if not isinstance(text, str) or not text.strip():
            errors.append("empty_output")
        if len(text.split()) > 1200:
            errors.append("word_limit")
        if any(
            section not in text
            for section in (
                "# Changes",
                "# Operational implications",
                "# Open questions",
            )
        ):
            errors.append("missing_section")
        for s in sources:
            if digest(s["text"].encode("utf-8")) != s["file_sha256"]:
                errors.append("source_integrity")
        expected = compare(sources)
        # Resolving a reference alone is insufficient. For this deliberately
        # narrow adapter, accept only the recomputed lexical change statements.
        # This does not evaluate the procedure's real-world meaning.
        if payload["claims"] != expected["claims"]:
            errors.append("unsupported_claim_or_citation")
        if text != expected["text"] or payload["model_id"] != MODEL_ID:
            errors.append("unqualified_fixture_output")
        if not payload["comparison_complete"] or not expected["comparison_complete"]:
            errors.append("too_many_changes_for_bounded_brief")
    except (KeyError, TypeError, ValueError, UnicodeError):
        errors.append("invalid_document_schema")
    return sorted(set(errors))
