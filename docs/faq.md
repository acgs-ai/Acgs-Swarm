# FAQ

## Is this a generic multi-agent framework?
No. It is a governance runtime for multi-agent systems, focused on governed execution, peer validation, and durable governance evidence.

## Can I use it without changing my existing agent framework?
Usually yes. The package can be embedded in existing stacks and used for validation, settlement, and verification pathways.

## Which APIs are safest to start with?
Start with the stable core in [`README.md`](../README.md): `AgentDNA`, `ConstitutionalMesh`, `SwarmExecutor`, and `TaskDAG`.

## Are all modules production-ready?
No. Advanced and research modules are explicitly separated by maturity tier.

## Does this package provide compliance certification?
No. It provides governance runtime primitives and evidence tooling, not regulatory certification.

## How do I verify governance receipts?
Use the verifier CLI:
```bash
acgs-verify-receipts --help
python scripts/verify_governance_receipts.py --help
```

## How do I run tests?
```bash
python -m pytest tests/ --import-mode=importlib -q
python -m pytest -m "not slow and not e2e and not research" tests/ --import-mode=importlib -q
```

## Where are advanced/research docs?
- LangGraph runtime: [`docs/langgraph_runtime.md`](langgraph_runtime.md)
- MCFS privacy draft: [`docs/maci_dp_protocol.md`](maci_dp_protocol.md)
- Internal technical notes: `docs/internal/`
- Manuscripts: [`paper/README.md`](../paper/README.md)
