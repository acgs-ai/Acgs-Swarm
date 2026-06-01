# Runbook: testnet-deploy

Register and run constitutional governance nodes on a Bittensor testnet subnet.

> ⚠️ This tool mutates on-chain state and is **not idempotent**. Confirm
> wallet, hotkey, and `--netuid` before every run.

## Prerequisite
```bash
uv run --no-sync python -c "from constitutional_swarm.bittensor.protocol import MinerConfig"
# If this ImportErrors, install the extra:
uv sync --no-sources --extra bittensor
```

## Commands
```bash
# Register a hotkey on the subnet
uv run --no-sync python scripts/testnet_deploy.py register \
  --wallet-name <w> --wallet-hotkey <h>

# Run a miner
uv run --no-sync python scripts/testnet_deploy.py miner \
  --wallet-name <w> --wallet-hotkey <h> \
  --constitution examples/constitution.yaml \
  --netuid <n> --port 8091 \
  --capabilities governance-judgment --domains general

# Run a validator
uv run --no-sync python scripts/testnet_deploy.py validator \
  --wallet-name <w> --wallet-hotkey <h> --netuid <n>
```

## Validate
The subnet metagraph should list the registered hotkey after `register`.

## Common failures
| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: bittensor` | extra not installed | `uv sync --no-sources --extra bittensor` |
| chain rejection on register | wrong netuid / low balance | verify netuid, fund wallet |
