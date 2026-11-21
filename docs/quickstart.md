# Quickstart (5 minutes)

This quickstart gets you to governed execution + peer-validated settlement quickly.

## 1) Install
```bash
pip install constitutional-swarm
```

## 2) Create a runnable script
Create `quickstart.py`:

```python
from acgs_lite import Constitution
from constitutional_swarm import AgentDNA, ConstitutionalMesh

dna = AgentDNA.default(agent_id="worker-1")
validation = dna.validate("summarize a safe project update")
assert validation.valid

# Start with the default constitution profile, then customize for your domain.
constitution = Constitution.default()
# quorum is the accept threshold (2 of 3 peers). quorum_met also needs every
# assigned peer to have voted, so the loop below votes with all of them.
quorum = 2
# This demo holds every signing key in one process, so it must opt in to the
# single-operator dev evidence mode. Evidence produced in this mode is labelled
# "single_operator_dev" and is rejected by the default verifiers. Production
# meshes keep the default ("independent") and register remote voters with
# register_remote_agent.
mesh = ConstitutionalMesh(
    constitution,
    peers_per_validation=3,
    quorum=quorum,
    evidence_mode="single_operator_dev",
)
mesh.register_local_signer("producer", domain="ops")
mesh.register_local_signer("peer-1", domain="ops")
mesh.register_local_signer("peer-2", domain="ops")
mesh.register_local_signer("peer-3", domain="ops")

assignment = mesh.request_validation("producer", "safe content", "artifact-quickstart")
for voter_id in assignment.peers:
    mesh.submit_vote(
        assignment.assignment_id,
        voter_id,
        approved=True,
        reason="passes constitutional checks",
        signature=mesh.sign_vote(
            assignment.assignment_id,
            voter_id,
            approved=True,
            reason="passes constitutional checks",
        ),
    )

result = mesh.get_result(assignment.assignment_id)
print({"accepted": result.accepted, "quorum_met": result.quorum_met, "settled": result.settled})
```

## 3) Run
```bash
python quickstart.py
```

Expected output shape:
```text
{'accepted': True, 'quorum_met': True, 'settled': True}
```

## Next steps
- Concepts: [`docs/concepts.md`](concepts.md)
- Architecture: [`docs/architecture.md`](architecture.md)
- Examples: [`docs/examples.md`](examples.md)
- Security boundaries: [`docs/security-model.md`](security-model.md)
