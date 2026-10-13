import { StrictMode, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { reconcileSnapshot, replay, type ReplayState } from "./replay";
import "./style.css";

type Source = {
	id: string;
	role: string;
	name: string;
	text: string;
	file_sha256: string;
};
type Evidence = {
	source_id: string;
	source_sha256: string;
	start: number;
	end: number;
	quote: string;
	comparison_anchor: boolean;
	locator: string;
};
type Claim = {
	id: string;
	kind: string;
	statement: string;
	evidence: Evidence[];
};
type Event = { seq: number; kind: string };
type Snapshot = {
	run: {
		id: string;
		execution: string;
		quality: string;
		review: string;
		review_version: number;
		review_expires: number | null;
		cancellation: string;
		authority: string;
		policy: string;
		peers: string;
		delivery: string;
	};
	sources: Source[];
	artifact: {
		id: string;
		text: string;
		file_sha256: string;
		claims: Claim[];
		quality_errors: string[];
	} | null;
	cursor: number;
	integrity: string;
	events: Event[];
	attempts: { id: string; generation: number; status: string }[];
	review_record: {
		feedback: string;
		reviewer: string;
		decision: string;
		file_sha256: string;
	} | null;
};
const base = "/api/workspaces/local/runs";
const key = () => crypto.randomUUID();
const launchStorageKey = "acgs-local-reviewer-pending-launch";
function retainedLaunchKey() {
	const existing = sessionStorage.getItem(launchStorageKey);
	if (existing) return existing;
	return key();
}
const words = (value: string) => value.replaceAll("_", " ");

class ReadError extends Error {
	constructor(
		message: string,
		public status: number,
	) {
		super(message);
	}
}

async function read<T>(url: string, signal?: AbortSignal): Promise<T> {
	const r = await fetch(url, { signal, cache: "no-store" });
	if (!r.ok)
		throw new ReadError(
			(await r.json()).detail || "Could not read saved state",
			r.status,
		);
	return r.json();
}

function App() {
	const [session, setSession] = useState<{ csrf: string } | null>(null);
	const [token, setToken] = useState("");
	const [prior, setPrior] = useState(
		"Check the intake queue.\nRecord the result.\n",
	);
	const [current, setCurrent] = useState(
		"Check the intake queue twice.\nRecord the result.\n",
	);
	const [names, setNames] = useState({
		prior: "prior.md",
		current: "current.md",
	});
	const [runId, setRunId] = useState(
		new URLSearchParams(location.search).get("run") || "",
	);
	const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
	const [connection, setConnection] = useState("Connecting");
	const [incomplete, setIncomplete] = useState(false);
	const [busy, setBusy] = useState(false);
	const [message, setMessage] = useState("");
	const [feedback, setFeedback] = useState("");
	const cursor = useRef<ReplayState | null>(null);
	const [initialLaunchKey] = useState(retainedLaunchKey);
	const launchKey = useRef(initialLaunchKey);
	const [pendingLaunch, setPendingLaunch] = useState<string | null>(() =>
		sessionStorage.getItem(launchStorageKey),
	);
	const [recoveringLaunch, setRecoveringLaunch] = useState(
		!!pendingLaunch && !runId,
	);
	const reviewCommand = useRef<{ body: string; key: string } | null>(null);
	const cancelKey = useRef(key());

	useEffect(() => {
		const abort = new AbortController();
		read<{ csrf: string }>("/api/session", abort.signal)
			.then(setSession)
			.catch(() => {});
		return () => abort.abort();
	}, []);

	useEffect(() => {
		if (!session || runId || !pendingLaunch) return;
		const abort = new AbortController();
		let timer: ReturnType<typeof setTimeout>;
		setRecoveringLaunch(true);
		async function resolve() {
			try {
				const admitted = await read<{ id: string; execution: string }>(
					`/api/workspaces/local/launches/${encodeURIComponent(pendingLaunch || "")}`,
					abort.signal,
				);
				if (abort.signal.aborted) return;
				const url = new URL(location.href);
				url.searchParams.set("run", admitted.id);
				history.replaceState(null, "", url);
				sessionStorage.removeItem(launchStorageKey);
				setPendingLaunch(null);
				setRecoveringLaunch(false);
				setRunId(admitted.id);
				setMessage(
					"Recovered the saved comparison. Reading its exact source versions.",
				);
			} catch (e) {
				if (abort.signal.aborted) return;
				if (e instanceof ReadError && e.status === 404) {
					setPendingLaunch(null);
					setRecoveringLaunch(false);
					setMessage(
						"No admitted run was found for the pending launch. Restore the original inputs before retrying with the same key.",
					);
				} else if (e instanceof ReadError && e.status === 401) {
					setSession(null);
					setMessage("Open a local session to recover the pending comparison.");
				} else {
					setMessage(
						"Checking the pending comparison. Reconnect to resolve its saved state before launching.",
					);
					timer = setTimeout(resolve, 1000);
				}
			}
		}
		void resolve();
		return () => {
			abort.abort();
			clearTimeout(timer);
		};
	}, [session, runId, pendingLaunch]);

	useEffect(() => {
		cursor.current = null;
		setIncomplete(false);
		setSnapshot(null);
		setConnection(runId ? "Connecting" : "No task selected");
		cancelKey.current = key();
		reviewCommand.current = null;
	}, [runId]);

	useEffect(() => {
		if (!session || !runId) return;
		const abort = new AbortController();
		let timer: ReturnType<typeof setTimeout>;
		async function poll() {
			try {
				if (cursor.current) {
					const events = await read<{
						events: Event[];
						cursor: number;
						integrity: string;
					}>(
						base +
							"/" +
							encodeURIComponent(runId) +
							"/events?after=" +
							cursor.current.cursor,
						abort.signal,
					);
					cursor.current = replay(
						cursor.current,
						events.events.map((e) => e.seq),
						events.cursor,
						events.integrity,
					);
				}
				const snap = await read<Snapshot>(
					`${base}/${encodeURIComponent(runId)}`,
					abort.signal,
				);
				if (abort.signal.aborted) return;
				cursor.current = reconcileSnapshot(
					cursor.current || { cursor: 0, incomplete: false },
					snap.events.map((e) => e.seq),
					snap.cursor,
					snap.integrity,
				);
				setSnapshot(snap);
				const oldSource = snap.sources.find((s) => s.role === "prior");
				const newSource = snap.sources.find((s) => s.role === "current");
				if (oldSource && newSource) {
					setPrior(oldSource.text);
					setCurrent(newSource.text);
					setNames({ prior: oldSource.name, current: newSource.name });
				}
				setIncomplete(cursor.current.incomplete);
				setConnection("Connected");
			} catch (e) {
				if (!abort.signal.aborted) {
					setConnection("Disconnected · retrying");
					if (e instanceof ReadError && e.status === 401) {
						setSession(null);
						setMessage(
							"The local session ended. Open a new session to reconnect to this saved task.",
						);
					}
				}
			} finally {
				if (!abort.signal.aborted) timer = setTimeout(poll, 1000);
			}
		}
		void poll();
		return () => {
			abort.abort();
			clearTimeout(timer);
		};
	}, [session, runId]);

	async function command(path: string, body: object) {
		const r = await fetch(path, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-CSRF-Token": session?.csrf || "",
			},
			body: JSON.stringify(body),
		});
		if (!r.ok)
			throw new Error((await r.json()).detail || "Command was not accepted");
		return r.json();
	}

	async function login(e: React.FormEvent) {
		e.preventDefault();
		setBusy(true);
		setMessage("");
		try {
			const r = await fetch("/api/session", {
				method: "POST",
				headers: { Authorization: `Bearer ${token}` },
			});
			if (!r.ok)
				throw new Error(
					"Check the ephemeral session token printed by the local server.",
				);
			setSession(await r.json());
			setToken("");
			setMessage("Local session opened.");
		} catch (e) {
			setMessage(String(e));
		} finally {
			setBusy(false);
		}
	}

	async function launch(e: React.FormEvent) {
		e.preventDefault();
		if (recoveringLaunch) return;
		sessionStorage.setItem(launchStorageKey, launchKey.current);
		setBusy(true);
		setMessage("");
		try {
			const r = await command(base, {
				key: launchKey.current,
				sources: {
					prior: { name: names.prior, text: prior },
					current: { name: names.current, text: current },
				},
			});
			sessionStorage.removeItem(launchStorageKey);
			setPendingLaunch(null);
			setRecoveringLaunch(false);
			const url = new URL(location.href);
			url.searchParams.set("run", r.id);
			history.replaceState(null, "", url);
			setRunId(r.id);
			setMessage(
				"Comparison saved to the queue. The separate worker can continue after you close this page.",
			);
		} catch (e) {
			setMessage(`${String(e)} Retry preserves this launch key.`);
		} finally {
			setBusy(false);
		}
	}

	async function chooseFile(role: "prior" | "current", file?: File) {
		if (!file) return;
		try {
			if (!/\.(txt|md)$/i.test(file.name) || file.size > 50000)
				throw new Error("Choose a .txt or .md file of at most 50,000 bytes.");
			const text = new TextDecoder("utf-8", {
				fatal: true,
				ignoreBOM: true,
			}).decode(await file.arrayBuffer());
			role === "prior" ? setPrior(text) : setCurrent(text);
			setNames((n) => ({ ...n, [role]: file.name }));
			setMessage("");
		} catch (e) {
			setMessage(String(e));
		}
	}

	async function review(decision: string) {
		if (!snapshot?.artifact) return;
		const body = {
			decision,
			file_sha256: snapshot.artifact.file_sha256,
			review_version: snapshot.run.review_version,
			feedback,
		};
		const serialized = JSON.stringify(body);
		if (reviewCommand.current?.body !== serialized)
			reviewCommand.current = { body: serialized, key: key() };
		setBusy(true);
		setMessage("");
		try {
			await command(`${base}/${runId}/review`, {
				...body,
				key: reviewCommand.current.key,
			});
			setMessage("Exact draft review saved. Authority remains not evaluated.");
		} catch (e) {
			setMessage(String(e));
		} finally {
			setBusy(false);
		}
	}

	async function cancel() {
		setBusy(true);
		try {
			await command(`${base}/${runId}/cancel`, { key: cancelKey.current });
			setMessage(
				"Cancellation requested. Wait for the worker acknowledgement.",
			);
		} catch (e) {
			setMessage(String(e));
		} finally {
			setBusy(false);
		}
	}

	const canReview =
		snapshot?.run.execution === "draft_ready" &&
		snapshot.run.review === "pending" &&
		!incomplete &&
		connection === "Connected" &&
		!!snapshot.artifact &&
		(snapshot.run.review_expires || 0) * 1000 > Date.now();
	const active =
		snapshot && ["queued", "running"].includes(snapshot.run.execution);

	return (
		<main>
			<header>
				<div className="eyebrow">ACGS / Local document experiment</div>
				<h1>Procedure comparison</h1>
				<p>
					Two source versions. One saved draft. Review each change against its
					evidence.
				</p>
				<div className="notice">
					SYNTHETIC fixture model · No AI inference · Human assessment of
					meaning required
				</div>
			</header>
			<p className="message" role="status">
				{message || "All documents stay in the local application database."}
			</p>
			{!session ? (
				<section>
					<h2>Open local session</h2>
					<p>
						Paste the temporary token printed by the server. Restarting the
						server requires a new token; saved work remains.
					</p>
					<form onSubmit={login} noValidate>
						<label htmlFor="token">Session token</label>
						<input
							id="token"
							type="password"
							autoComplete="off"
							value={token}
							onChange={(e) => setToken(e.target.value)}
						/>
						<button type="submit" disabled={busy || !token}>
							Open session
						</button>
					</form>
				</section>
			) : (
				<>
					<section>
						<h2>Source versions</h2>
						<p>
							UTF-8 text or Markdown · 50,000 bytes per version · source
							instructions are treated as text.
						</p>
						<form onSubmit={launch} noValidate>
							<div className="pair">
								{(["prior", "current"] as const).map((role) => (
									<div key={role}>
										<label htmlFor={role}>
											{role === "prior"
												? "Prior procedure"
												: "Current procedure"}
										</label>
										<input
											aria-label={`Load ${role} file`}
											type="file"
											accept=".txt,.md"
											disabled={busy || recoveringLaunch || !!runId}
											onChange={(e) =>
												void chooseFile(role, e.target.files?.[0])
											}
										/>
										<textarea
											className="resize-none"
											id={role}
											value={
												recoveringLaunch || (runId && !snapshot)
													? ""
													: role === "prior"
														? prior
														: current
											}
											readOnly={recoveringLaunch || !!runId}
											onChange={(e) =>
												role === "prior"
													? setPrior(e.target.value)
													: setCurrent(e.target.value)
											}
										/>
										<small>
											{new TextEncoder()
												.encode(role === "prior" ? prior : current)
												.length.toLocaleString()}{" "}
											bytes · {names[role]}
										</small>
									</div>
								))}
							</div>
							{!runId && (
								<button
									type="submit"
									disabled={
										busy || recoveringLaunch || !prior.trim() || !current.trim()
									}
								>
									Save and compare
								</button>
							)}
							{runId && !active && snapshot && (
								<button
									type="button"
									className="secondary"
									disabled={busy}
									onClick={() => {
										launchKey.current = key();
										sessionStorage.removeItem(launchStorageKey);
										setPendingLaunch(null);
										setRunId("");
										setFeedback("");
										history.replaceState(null, "", location.pathname);
										setMessage(
											"New comparison: review applies only to its own saved draft.",
										);
									}}
								>
									Create a new comparison
								</button>
							)}
						</form>
					</section>
					{runId && (
						<section aria-label="Saved task">
							<div className="row">
								<h2>Saved task</h2>
								<span>{connection}</span>
							</div>
							<p>
								<a href={`?run=${encodeURIComponent(runId)}`}>
									Reopen this task
								</a>
							</p>
							<code>{runId}</code>
							{incomplete && (
								<p className="notice" role="alert">
									Incomplete evidence · a replay gap or missing saved bytes was
									detected. Review is unavailable.
								</p>
							)}
							{!snapshot ? (
								<p>
									Reading the saved state. Connection status does not establish
									completion.
								</p>
							) : (
								<>
									<dl className="facts">
										{(
											[
												"execution",
												"quality",
												"review",
												"cancellation",
												"policy",
												"peers",
												"authority",
												"delivery",
											] as const
										).map((f) => (
											<div key={f}>
												<dt>{f}</dt>
												<dd>{words(snapshot.run[f])}</dd>
											</div>
										))}
									</dl>
									{active && (
										<button
											type="button"
											className="secondary"
											disabled={
												busy || snapshot.run.cancellation === "requested"
											}
											onClick={() => void cancel()}
										>
											Request cancellation
										</button>
									)}
									{snapshot.artifact && (
										<>
											<h3>Saved draft</h3>
											<p className="hash">
												File SHA-256{" "}
												<code>{snapshot.artifact.file_sha256}</code>
											</p>
											<a href={`${base}/${runId}/draft`}>
												Download saved Markdown
											</a>
											<pre className="draft">{snapshot.artifact.text}</pre>
											{snapshot.artifact.quality_errors.length > 0 && (
												<p role="alert">
													Quality failed:{" "}
													{snapshot.artifact.quality_errors.join(", ")}
												</p>
											)}
											<h3>Claim evidence</h3>
											<p>
												Byte spans resolve to immutable source versions. A
												zero-length anchor identifies where text is absent; the
												whole source hash binds that comparison.
											</p>
											{snapshot.artifact.claims.map((claim) => (
												<article className="claim" key={claim.id}>
													<h4>
														{claim.id} · {claim.statement}
													</h4>
													<div className="pair">
														{claim.evidence.map((ref) => {
															const source = snapshot.sources.find(
																(s) => s.id === ref.source_id,
															);
															return (
																<details key={ref.source_id} open>
																	<summary>
																		{source?.role || "Missing source"} · UTF-8
																		bytes {ref.start}–{ref.end}
																	</summary>
																	<p className="hash">
																		<code>{ref.source_id}</code>
																		<br />
																		<code>{ref.source_sha256}</code>
																	</p>
																	<a
																		href={ref.locator}
																		target="_blank"
																		rel="noopener"
																	>
																		Open exact source span
																	</a>
																	<pre>
																		{ref.comparison_anchor
																			? "(No text at this comparison anchor)"
																			: ref.quote}
																	</pre>
																</details>
															);
														})}
													</div>
												</article>
											))}
											<h3>Review this exact draft</h3>
											<p>
												Approval records a draft review. Policy, peers,
												authority and delivery remain separate. Request changes
												saves feedback; a replacement needs an explicit new
												comparison.
											</p>
											<label htmlFor="feedback">Review feedback</label>
											<textarea
												className="resize-none"
												id="feedback"
												value={feedback}
												readOnly={!canReview}
												onChange={(e) => setFeedback(e.target.value)}
												maxLength={4000}
											/>
											<div className="actions">
												<button
													type="button"
													disabled={busy || !canReview}
													onClick={() => void review("approve")}
												>
													Approve draft
												</button>
												<button
													type="button"
													className="secondary"
													disabled={busy || !canReview || !feedback.trim()}
													onClick={() => void review("request_changes")}
												>
													Request changes
												</button>
												<button
													type="button"
													className="secondary"
													disabled={busy || !canReview}
													onClick={() => void review("reject")}
												>
													Reject draft
												</button>
											</div>
											{snapshot.run.review_expires && (
												<small>
													Review expires{" "}
													{new Date(
														snapshot.run.review_expires * 1000,
													).toLocaleString()}{" "}
													· version {snapshot.run.review_version}
												</small>
											)}
											{snapshot.review_record && (
												<p>
													Saved review: {words(snapshot.review_record.decision)}{" "}
													by {snapshot.review_record.reviewer}.{" "}
													{snapshot.review_record.feedback}
												</p>
											)}
										</>
									)}
									<details>
										<summary>
											Durable history · {snapshot.events.length} events ·{" "}
											{snapshot.attempts.length} worker attempts
										</summary>
										<ol>
											{snapshot.events.map((e) => (
												<li key={e.seq}>
													{e.seq}: {words(e.kind)}
												</li>
											))}
										</ol>
										{snapshot.attempts.map((a) => (
											<p key={a.id}>
												Attempt generation {a.generation}: {words(a.status)}
											</p>
										))}
									</details>
								</>
							)}
						</section>
					)}
				</>
			)}
		</main>
	);
}
const root = document.getElementById("root");
if (!root) throw new Error("Workspace root is missing");
createRoot(root).render(
	<StrictMode>
		<App />
	</StrictMode>,
);
