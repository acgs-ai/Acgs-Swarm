export type ReplayState = { cursor: number; incomplete: boolean };
export function reconcileSnapshot(
	state: ReplayState,
	ids: number[],
	serverCursor: number,
	integrity: string,
): ReplayState {
	const complete =
		integrity === "complete" &&
		serverCursor >= state.cursor &&
		Number.isSafeInteger(serverCursor) &&
		serverCursor >= 0 &&
		ids.length === serverCursor &&
		ids.every((id, index) => id === index + 1);
	return {
		cursor: Math.max(state.cursor, serverCursor),
		incomplete: !complete,
	};
}
export function replay(
	state: ReplayState,
	ids: number[],
	serverCursor: number,
	integrity: string,
): ReplayState {
	let cursor = state.cursor;
	let incomplete = state.incomplete || integrity !== "complete";
	for (const id of ids) {
		if (id <= cursor) continue;
		if (id !== cursor + 1) incomplete = true;
		cursor = id;
	}
	if (cursor !== serverCursor) incomplete = true;
	return { cursor: Math.max(cursor, serverCursor), incomplete };
}
