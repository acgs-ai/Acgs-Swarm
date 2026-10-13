# Procedure comparison workspace

Audience: an internal procedure reviewer checking two immutable source versions.
Single job: inspect saved change claims and review the exact draft.
Palette: paper #f5f7fa, ink #17304a, navy #193f64, cyan #d9edf2,
border #b8c6d3, warning #775215. System body font, restrained Georgia display,
monospace hashes. Signature: a side-by-side evidence pair for every change.
CSS variables in ui/src/style.css own tokens. No remote fonts, scripts or assets.
Natural document scrolling; forms stack below 760px. All actions are native buttons.
Live status is separate from execution facts; no success inferred from connection.
Session and source content stay out of browser persistent storage; run ID in URL.
Only the scoped pending launch idempotency key is retained in sessionStorage,
so authenticated resolution after a lost acknowledgement recovers the admitted
run and server-held source versions without storing documents or relaunching.
An event hole blocks review until a verified full, non-regressing server
snapshot proves the repaired history complete.
Request changes saves feedback, and a separate explicit launch creates any new draft.
One screen; no pre-existing UI primitives in Acgs-Swarm to reuse.
