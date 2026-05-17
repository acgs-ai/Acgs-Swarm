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
required_votes = 2
mesh = ConstitutionalMesh(constitution, peers_per_validation=3, quorum=required_votes)
mesh.register_local_signer("producer", domain="ops")
mesh.register_local_signer("peer-1", domain="ops")
mesh.register_local_signer("peer-2", domain="ops")
mesh.register_local_signer("peer-3", domain="ops")

assignment = mesh.request_validation("producer", "safe content", "artifact-quickstart")
for voter_id in assignment.peers[:required_votes]:
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
