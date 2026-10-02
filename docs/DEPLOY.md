# Deploying across machines

Everything below has been exercised on one machine by `jurisledger cluster` and `tests/test_deploy_governance.py`; across machines it is the same commands with real hostnames. Not yet measured across real network distances.

## 1. Prepare, on the machine that will keep the secrets

```bash
jurisledger init --out net --chain-id my-republic \
  --validators desk.local:7701,laptop.local:7702,vm1.example:7703,vm2.example:7704 \
  --issuers company-registry,tax-authority --min-attestations 2
```

Add `--encrypt` to seal every key file with a passphrase (scrypt + AES-256-GCM). Validators then start with `JURISLEDGER_PASSPHRASE` set in their environment or type it at the prompt; a stolen key file alone is useless.

You get:

| File or folder | Who gets it | Contains |
|---|---|---|
| `net/genesis.json`, `net/peers.json` | every validator, every auditor | the founding record and the validators' addresses; nothing secret |
| `net/validator-i/` | machine *i* only | that validator's key and a `start.sh` |
| `net/issuer-*.key.json` | each identity issuer | its signing key |
| `net/treasury.key.json` | the government account | the only funded account at genesis |

## 2. Start, on each machine

```bash
mkdir -p ~/ledger && cd ~/ledger
# copy in genesis.json, peers.json and your validator-i/ folder (scp, USB, whatever the security policy allows)
chmod 600 validator-i/validator-i.key.json
./validator-i/start.sh
```

Open TCP port 770*i* inbound on that machine's firewall. All traffic is Transport Layer Security (TLS) 1.3 with the certificate pinned to the validator key, so a hostname change is harmless but a key change is a governance vote.

The chain makes progress once more than two thirds of the validators are up. With four validators that is three: you can start them one at a time and the first blocks appear when the third comes online.

## 3. Check it from anywhere

```bash
jurisledger status desk.local:7701
jurisledger export desk.local:7701 -o chain.json && jurisledger audit chain.json
jurisledger wallet new -o me.json
jurisledger wallet register desk.local:7701 --key me.json --name "Ana" --role household
```

Pin the validator you talk to with `--pin <its address from genesis.json>` when you are not on a network you trust.

## 4. Operate

| Task | How |
|---|---|
| A validator crashed | run `start.sh` again; it resumes from `store/` and asks peers for the blocks it missed |
| A validator's disk is lost | start it with an empty `store/`: it asks peers for blocks, and if they have pruned them it receives a certified snapshot instead, checks its validator signatures and state digest, and continues from there |
| The disk is filling up | start validators with `./start.sh --prune-every 1000` (keeps 1,000 to 2,000 recent blocks; older ones move, gzip-compressed, to `store/archive/`), or stop one and run `jurisledger prune --store store --keep 1000`. Keep at least one archive node that never runs with `--no-archive`: it is the ledger's full legal history |
| Someone starts a second validator on the same store by mistake | it is refused: a running validator holds an exclusive lock on the store |
| Limit spam | vote `SET_POLICY` `max_tx_per_block` (for example 50): no account can place more than that many transactions in one block |
| Track the data | `jurisledger index HOST:PORT -o ledger.db` on a schedule, then `query` and `metrics`; see [`DATA.md`](DATA.md) |
| Change the identity threshold or payment cap | each validator sends a `VALIDATOR_VOTE` with `SET_POLICY`; effective when more than two thirds agree |
| Add or remove a validator or issuer | the same vote with `ADD` / `REMOVE` / `ADD_ISSUER` / `REMOVE_ISSUER` |
| Publish the register | `jurisledger register chain.json -o register.html` and host the file anywhere; it is self-contained |

## 5. Two-machine exercise on a desktop and a laptop

Run two validators on each machine (four total, so either machine alone cannot finalise anything — which is the point):

```bash
jurisledger init --out net --validators DESK_IP:7701,DESK_IP:7702,LAPTOP_IP:7703,LAPTOP_IP:7704
```

Copy `net/genesis.json`, `net/peers.json`, `net/validator-2/` and `net/validator-3/` to the laptop, start all four, then stop both laptop validators: the desktop pair keeps running but finalises nothing until the laptop returns and catches up. That is safety over liveness, observed rather than asserted.

On Windows Subsystem for Linux (WSL) 2, inbound ports must be forwarded from Windows to the WSL address, for example with `netsh interface portproxy add v4tov4 listenport=7703 connectaddress=$(wsl hostname -I)`, and allowed through the Windows firewall.
