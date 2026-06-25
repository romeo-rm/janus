# Janus Operations

## Runtime

Janus runs on the Wazuh VM at `192.168.10.133` and targets the Windows host at
`192.168.10.134`. The dashboard and REST API are served on port `5000`.

```bash
sudo systemctl status janus
sudo systemctl restart janus
sudo journalctl -u janus -f
```

Open `http://192.168.10.133:5000` from the Windows host.

## Configuration

Copy `.env.example` to `.env` and provide the Wazuh API, indexer, SSH, target,
and optional Gemini credentials. `.env` is ignored by Git and should remain
readable only by the service account.

The `/health` endpoint checks the Wazuh API, OpenSearch indexer, and target SSH
port. A degraded response identifies which dependency is unavailable.

## Detection Semantics

Before each technique, Janus records the current Wazuh alert IDs for the target.
Only alerts created after that baseline can satisfy the technique. A failed
attack command or failed Wazuh query is reported as an error and never counted
as a detection.

Sigma deployment is successful only after the manager reloads the ruleset and
the Wazuh API confirms every mapped rule ID. Reset clears run results but keeps
verified deployment state, matching the rules that remain active in Wazuh.

## Verification

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile orchestrator.py navigator.py
```
