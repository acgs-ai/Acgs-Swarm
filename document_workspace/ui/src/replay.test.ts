import assert from "node:assert/strict";
import { test } from "node:test";
import { reconcileSnapshot, replay } from "./replay.js";

test("deduplicates confirmed event IDs without losing cursor", () => {
	assert.deepEqual(
		replay({ cursor: 2, incomplete: false }, [2, 3], 3, "complete"),
		{ cursor: 3, incomplete: false },
	);
});
test("a replay hole remains incomplete after reconnect", () => {
	const gap = replay({ cursor: 1, incomplete: false }, [3], 3, "complete");
	assert.equal(gap.incomplete, true);
	assert.equal(replay(gap, [4], 4, "complete").incomplete, true);
});
test("a server-reported gap or lost final event cannot appear complete", () => {
	assert.equal(
		replay({ cursor: 1, incomplete: false }, [2], 3, "complete").incomplete,
		true,
	);
	assert.equal(
		replay({ cursor: 0, incomplete: false }, [1], 1, "incomplete_evidence")
			.incomplete,
		true,
	);
});

test("only a complete non-regressing server snapshot repairs a replay hole", () => {
	const gap = replay({ cursor: 1, incomplete: false }, [3], 3, "complete");
	assert.equal(reconcileSnapshot(gap, [1, 3], 3, "complete").incomplete, true);
	assert.equal(
		reconcileSnapshot(gap, [1, 2, 3], 3, "incomplete_evidence").incomplete,
		true,
	);
	assert.equal(reconcileSnapshot(gap, [1, 2], 2, "complete").incomplete, true);
	assert.deepEqual(reconcileSnapshot(gap, [1, 2, 3], 3, "complete"), {
		cursor: 3,
		incomplete: false,
	});
});
