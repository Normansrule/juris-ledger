"""JurisLedger command line.

  jurisledger demo [--out DIR]            build a sample ledger, evidence file and browsable register
  jurisledger audit CHAIN.json            re-verify a whole ledger from its founding record
  jurisledger verify EVIDENCE.json VALIDATORS.json
                                          check one contract's evidence file offline
  jurisledger register CHAIN.json [-o FILE.html]
                                          render the browsable public register
  jurisledger bench                       performance of this prototype on this machine
  jurisledger cluster [--out DIR] [--n 4] run N validator processes over TCP, kill and rejoin one
  jurisledger node --genesis G --key K --peers P --store DIR --index I [--listen HOST:PORT]
                                          run one validator (a process per machine in a deployment)
  jurisledger init --out DIR --validators host:port,... [--issuers a,b] [--min-attestations 2]
                                          prepare a multi-machine deployment (genesis, peers, per-machine key folders)
  jurisledger keygen [-o FILE]            make a validator or wallet key file
  jurisledger wallet new|register|balance|pay ...   (see jurisledger wallet -h)
  jurisledger snapshot CHAIN.json [-o SNAP.json]  certified state snapshot: join or audit without replaying history
  jurisledger status HOST:PORT            height, state digest and mempool of a running validator
  jurisledger export HOST:PORT [-o FILE]  download and re-audit a running validator's ledger
  jurisledger all | NAME                  run every experiment, or one of:
      contracts legal disputes identity attacks asynchrony integration gdp fraud privacy confidential
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .chain import Chain, InvalidBlock
from .experiments import EXPERIMENTS

TITLES = {
    "contracts": "Signed digital contracts with references and an access trail",
    "legal": "Obligations, compliance and court-ready evidence files",
    "disputes": "Disputes and arbitration with deliberately narrow powers",
    "identity": "Identity without a gatekeeper, key rotation and lost-key recovery",
    "attacks": "Adversarial experiments",
    "asynchrony": "Consensus on a hostile network: single-phase versus two-phase voting",
    "integration": "The real ledger on signed two-phase consensus",
    "gdp": "Gross Domestic Product (GDP) measured from the ledger",
    "fraud": "Fraud detection on a shared ledger",
    "privacy": "Commitments and differentially private statistics (experimental)",
    "confidential": "Confidential payments with range proofs on the real ledger",
}


def run_experiments(names: list[str]) -> int:
    failed = 0
    for n in names:
        print(f"\n=== {TITLES[n]} ===")
        for claim, ok in EXPERIMENTS[n](verbose=True)["checks"]:
            print(f"  [{'PASS' if ok else 'FAIL'}] {claim}")
            failed += not ok
    print(f"\n{'ALL CHECKS PASSED' if not failed else str(failed) + ' CHECK(S) FAILED'}")
    return 1 if failed else 0


def cmd_audit(path: str) -> int:
    try:
        chain = Chain.load(Path(path).read_text())
    except InvalidBlock as err:
        print(f"REJECTED. The ledger in {path} does not verify: {err}")
        return 1
    except (OSError, ValueError, KeyError) as err:
        print(f"Could not read {path} as a ledger export: {err}")
        return 2
    n_tx = sum(len(b.txs) for b in chain.blocks)
    if chain.base_height:
        print(f"VERIFIED. Snapshot after block {chain.base_height} carries a valid certificate from the genesis "
              f"validators and matches its certified state digest; {len(chain.blocks)} later blocks and {n_tx:,} "
              f"transactions replayed on top.\nHistory before block {chain.base_height} is not in this file.")
    else:
        print(f"VERIFIED. {chain.height} blocks and {n_tx:,} transactions replayed from the founding record of "
              f"'{chain.chain_id}'.\nEvery signature, Merkle root, state digest and commit certificate checked.")
    print(f"State digest: {chain.state.root()}")
    return 0


def cmd_verify(evidence_path: str, validators_path: str) -> int:
    from .legal import verify_evidence_bundle
    try:
        bundle = json.loads(Path(evidence_path).read_text())
        trusted = json.loads(Path(validators_path).read_text())
        validators = trusted["validators"] if isinstance(trusted, dict) else trusted
    except (OSError, ValueError, KeyError) as err:
        print(f"Could not read the files: {err}")
        return 2
    report = verify_evidence_bundle(bundle, validators)
    if not report["valid"]:
        print("REJECTED. Do not rely on this file.")
        for p in report["problems"]:
            print(f"  - {p}")
        return 1
    print(f"VERIFIED against {len(validators)} validator keys you supplied.\n")
    print(f"  Contract      {report['title']}")
    print(f"  Parties       {len(report['parties'])}; all signed the same text: {'yes' if report['fully_signed'] else 'NO'}")
    if "prose_matches" in report:
        print(f"  Enclosed text {'is exactly the text that was signed' if report['prose_matches'] else 'DOES NOT MATCH'}")
    if report.get("key_changes"):
        print(f"  Key changes   {len(report['key_changes'])} party key(s) were replaced; signatures follow the new keys")
    labels = bundle.get("labels", {})
    print("\n  What happened, in order (names are labels from the file, keys are what is proven):")
    for ev in report["timeline"]:
        detail = ", ".join(f"{k}={v}" for k, v in ev["detail"].items() if k != "adjustments")
        print(f"    block {ev['height']:>3}  {ev['kind'].replace('_', ' ').lower():<18} by {labels.get(ev['by'], '?')[:22]:<22} {ev['by'][:8]}…  {detail}")
    print("\n  This proves what is in the file. It cannot prove that nothing was left out; "
          "for that, ask a full node.")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="jurisledger", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", default="all")
    ap.add_argument("paths", nargs="*")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--n", type=int, default=4)
    ap.add_argument("--genesis"); ap.add_argument("--key"); ap.add_argument("--peers")
    ap.add_argument("--store"); ap.add_argument("--index", type=int); ap.add_argument("--listen")
    ap.add_argument("--until", type=int, default=None)
    ap.add_argument("--to"); ap.add_argument("--amount"); ap.add_argument("--purpose")
    ap.add_argument("--name"); ap.add_argument("--role", default="household"); ap.add_argument("--sector", default="")
    ap.add_argument("--pin", help="validator address to pin the TLS certificate to")
    ap.add_argument("--validators"); ap.add_argument("--issuers", default="")
    ap.add_argument("--chain-id", default="jurisledger-net"); ap.add_argument("--min-attestations", type=int, default=2)
    ap.add_argument("--unverified-limit", default="100.00"); ap.add_argument("--recovery-delay", type=int, default=100)
    ap.add_argument("--treasury", default="1000000.00")
    args = ap.parse_args(argv[1:])
    cmd = args.command

    if cmd == "all" or cmd in EXPERIMENTS:
        return run_experiments(list(EXPERIMENTS) if cmd == "all" else [cmd])
    if cmd == "demo":
        from .demo import build
        out = args.out or "demo"
        made = build(out)
        print(f"Built a {made['blocks']}-block sample ledger in {out}/\n"
              f"  open      {made['register']}   (in a browser)\n"
              f"  then try  jurisledger audit {made['chain']}\n"
              f"            jurisledger verify {made['evidence']} {made['validators']}")
        return 0
    if cmd == "audit" and len(args.paths) == 1:
        return cmd_audit(args.paths[0])
    if cmd == "verify" and len(args.paths) == 2:
        return cmd_verify(*args.paths)
    if cmd == "register" and len(args.paths) == 1:
        from .dashboard import render
        try:
            chain = Chain.load(Path(args.paths[0]).read_text())
        except InvalidBlock as err:
            print(f"REJECTED. Refusing to render a ledger that does not verify: {err}")
            return 1
        out = args.out or "register.html"
        Path(out).write_text(render(chain))
        print(f"Wrote {out}")
        return 0
    if cmd == "cluster":
        from .cluster import run
        r = run(args.out or "cluster", args.n)
        print("\nCLUSTER OK" if r.get("ok") else "\nCLUSTER FAILED: " + json.dumps(r))
        return 0 if r.get("ok") else 1
    if cmd == "node":
        from .crypto import KeyPair
        from .net import serve
        if not all([args.genesis, args.key, args.peers, args.store, args.index is not None]):
            print("node needs --genesis --key --peers --store --index"); return 2
        genesis = json.loads(Path(args.genesis).read_text())
        key = KeyPair.from_secret_hex(json.loads(Path(args.key).read_text())["secret"])
        peers = [(h, int(p)) for h, p in (x.rsplit(":", 1) for x in json.loads(Path(args.peers).read_text()))]
        listen = tuple(args.listen.rsplit(":", 1)) if args.listen else ("0.0.0.0", peers[args.index][1])
        listen = (listen[0], int(listen[1]))
        if key.address != genesis["validators"][args.index]:
            print("the key does not match validator", args.index, "in the genesis"); return 2
        print(f"validator {args.index} listening on {listen[0]}:{listen[1]}", flush=True)
        serve(key, genesis, peers, args.store, listen, until_height=args.until,
              log=lambda m: print(m, flush=True))
        return 0
    if cmd == "wallet":
        from . import wallet as W
        sub = args.paths[0] if args.paths else ""
        if sub == "new":
            return W.cmd_new(args.out or "wallet.json")
        if sub in ("register", "balance", "pay") and len(args.paths) == 2 and args.key:
            client, key = W.connect(args.paths[1], args.pin), W.load_key(args.key)
            try:
                if sub == "register":
                    return W.cmd_register(client, key, args.name or "unnamed", args.role, args.sector)
                if sub == "balance":
                    return W.cmd_balance(client, key)
                return W.cmd_pay(client, key, args.to or "", args.amount or "0", args.purpose or "")
            except OSError as err:
                print(f"could not reach {args.paths[1]}: {err}"); return 1
        print(__doc__); return 2
    if cmd == "snapshot" and len(args.paths) == 1:
        try:
            chain = Chain.load(Path(args.paths[0]).read_text())
        except InvalidBlock as err:
            print(f"REJECTED. Refusing to snapshot a ledger that does not verify: {err}"); return 1
        out = args.out or "snapshot.json"
        snap = chain.make_snapshot()
        Path(out).write_text(json.dumps({"genesis": chain.genesis, "snapshot": snap, "blocks": []}))
        print(f"wrote {out}: state after block {chain.height}, certified by {len(snap['votes'])} validator signatures.\n"
              f"Verify it with: jurisledger audit {out}   (checks the certificate and the state digest)")
        return 0
    if cmd in ("status", "export") and len(args.paths) == 1:
        from .net import Client
        host, port = args.paths[0].rsplit(":", 1)
        client = Client(host, int(port))
        try:
            if cmd == "status":
                st = client.status()
                print(f"validator {st.get('index')}  height {st.get('height')}  mempool {st.get('mempool')}\n"
                      f"state digest {st.get('root')}\nvalidators: {len(st.get('validators', []))}")
            else:
                chain = client.export()
                out = args.out or "chain.json"
                Path(out).write_text(chain.export())
                print(f"downloaded and re-audited {chain.height} blocks from {args.paths[0]}; wrote {out}")
        except OSError as err:
            print(f"could not reach {args.paths[0]}: {err}"); return 1
        return 0
    if cmd == "init":
        from .deploy import init
        from .wallet import parse_amount
        if not args.validators:
            print("init needs --validators host:port,host:port,..."); return 2
        hosts = [h.strip() for h in args.validators.split(",") if h.strip()]
        issuers = [i.strip() for i in args.issuers.split(",") if i.strip()]
        made = init(args.out or "net", hosts, issuers, args.chain_id, args.min_attestations,
                    parse_amount(args.unverified_limit), args.recovery_delay, parse_amount(args.treasury))
        print(f"prepared a {len(hosts)}-validator network '{args.chain_id}' in {args.out or 'net'}/\n"
              f"  shared with everyone : genesis.json, peers.json\n"
              f"  one folder per machine: {made['validators']}  (each holds only its own key + start.sh)\n"
              f"  keep private          : issuer-*.key.json, treasury.key.json\n"
              f"On each machine: copy genesis.json, peers.json and its validator-i/ folder, then run validator-i/start.sh")
        return 0
    if cmd == "keygen":
        from .crypto import KeyPair
        k = KeyPair.generate()
        Path(args.out or "key.json").write_text(json.dumps({"secret": k.secret_hex(), "address": k.address}))
        print(f"wrote {args.out or 'key.json'}; public key {k.address}")
        return 0
    if cmd == "bench":
        from .bench import run
        run()
        return 0
    ap.print_help()
    return 2


def main_cli() -> None:          # console-script entry point
    sys.exit(main(sys.argv))


if __name__ == "__main__":
    main_cli()
