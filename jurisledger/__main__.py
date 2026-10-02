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
  jurisledger keygen [-o FILE] [--encrypt] make a validator or wallet key file (--encrypt: passphrase-sealed)
  jurisledger wallet new|register|balance|pay ...   (see jurisledger wallet -h)
  jurisledger snapshot CHAIN.json [-o SNAP.json]  certified state snapshot: join or audit without replaying history
  jurisledger index CHAIN.json|HOST:PORT [-o ledger.db]   audit, then add new blocks to a SQLite index
  jurisledger query ledger.db gdp [FROM TO] | account NAME | top | contract ID
  jurisledger metrics ledger.db [-o metrics.csv]         per-block time series for dashboards
  jurisledger api ledger.db [--port 8080] [--follow HOST:PORT --every 10]
                                          read-only JSON API over the index (feeds site/dashboard.html)
  jurisledger fuzz [--runs N --steps M --seed S]   random attacks on the state machine, eight invariants checked
  jurisledger prune --store DIR [--keep N] [--no-archive]   shrink a stopped validator's store to a certified
                                          snapshot plus the last N blocks; older blocks go to DIR/archive/
  jurisledger doctor                      check this machine's Python, packages, Node and network setup
  jurisledger submit SIGNED_TX.json HOST:PORT [--pin ADDR]  send a transaction signed elsewhere (e.g. the web wallet)
  jurisledger status HOST:PORT            height, state digest and mempool of a running validator
  jurisledger export HOST:PORT [-o FILE]  download and re-audit a running validator's ledger
  jurisledger all | NAME                  run every experiment, or one of:
      contracts legal disputes identity attacks asynchrony integration gdp fraud privacy confidential
"""
from __future__ import annotations

import argparse
import json
import sys
import time
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
    ap.add_argument("--prune-every", type=int, default=0); ap.add_argument("--keep", type=int, default=1000)
    ap.add_argument("--no-archive", action="store_true")
    ap.add_argument("--to"); ap.add_argument("--amount"); ap.add_argument("--purpose")
    ap.add_argument("--name"); ap.add_argument("--role", default="household"); ap.add_argument("--sector", default="")
    ap.add_argument("--pin", help="validator address to pin the TLS certificate to")
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--runs", type=int, default=20); ap.add_argument("--steps", type=int, default=400)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--follow"); ap.add_argument("--every", type=float, default=10.0)
    ap.add_argument("--encrypt", action="store_true", help="seal new key files with a passphrase (scrypt + AES-256-GCM)")
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
        from .keystore import KeystoreError, load as load_key
        try:
            key = load_key(args.key)
        except KeystoreError as err:
            print(err); return 2
        peers = [(h, int(p)) for h, p in (x.rsplit(":", 1) for x in json.loads(Path(args.peers).read_text()))]
        listen = tuple(args.listen.rsplit(":", 1)) if args.listen else ("0.0.0.0", peers[args.index][1])
        listen = (listen[0], int(listen[1]))
        if key.address != genesis["validators"][args.index]:
            print("the key does not match validator", args.index, "in the genesis"); return 2
        print(f"validator {args.index} listening on {listen[0]}:{listen[1]}", flush=True)
        from .storage import StoreBusy
        try:
            serve(key, genesis, peers, args.store, listen, until_height=args.until,
                  log=lambda m: print(m, flush=True), prune_every=args.prune_every, keep_archive=not args.no_archive)
        except StoreBusy as err:
            print(f"REFUSED. {err}"); return 1
        return 0
    if cmd == "wallet":
        from . import wallet as W
        sub = args.paths[0] if args.paths else ""
        if sub == "new":
            return W.cmd_new(args.out or "wallet.json", args.encrypt)
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
    if cmd == "index" and len(args.paths) == 1:
        from .index import Index, IndexError_
        src = args.paths[0]
        try:
            if not Path(src).exists() and ":" in src:
                from .net import Client
                host, port = src.rsplit(":", 1)
                chain = Client(host, int(port), expect_address=args.pin).export()       # re-audited locally
            else:
                chain = Chain.load(Path(src).read_text())
        except InvalidBlock as err:
            print(f"REJECTED. Refusing to index a ledger that does not verify: {err}"); return 1
        except OSError as err:
            print(f"could not read {src}: {err}"); return 1
        idx = Index(args.out or "ledger.db")
        try:
            r = idx.sync(chain)
        except IndexError_ as err:
            print(f"REFUSED. {err}"); return 1
        print(f"indexed {r['blocks_added']} new blocks ({r['transactions_added']:,} transactions) into {idx.path} "
              f"in {r['seconds']:.2f} s; index now at block {r['height']}")
        return 0
    if cmd == "query" and len(args.paths) >= 2:
        from .index import Index
        idx, what, rest = Index(args.paths[0]), args.paths[1], args.paths[2:]
        money = lambda c: f"{c / 100:,.2f}"
        if what == "gdp":
            g = idx.gdp(*(int(x) for x in rest[:2])) if rest else idx.gdp()
            print(f"blocks {g['from']}-{g['to']}:  GDP {money(g['gdp'])}  =  C {money(g['C'])} + I {money(g['I'])} + "
                  f"G {money(g['G'])} + X {money(g['X'])} - M {money(g['M'])}")
        elif what == "account" and rest:
            a = idx.resolve(rest[0])
            if not a:
                print(f"no account named or addressed {rest[0]!r}"); return 1
            for r in idx.account_history(a, 25):
                print(f"  block {r['height']:>5}  {'paid    ' if r['direction'] == 'out' else 'received'} {money(r['amount']):>14}  "
                      f"{'to' if r['direction'] == 'out' else 'from'} {r['counterparty'] or '?':<24} {r['purpose'].lower()}")
        elif what == "top":
            for r in idx.top_accounts(int(rest[0]) if rest else 10):
                print(f"  {r['name']:<26} {r['role']:<10} paid {money(r['paid']):>16}   received {money(r['received']):>16}")
        elif what == "contract" and rest:
            for e in idx.contract_timeline(rest[0]):
                print(f"  block {e['height']:>5}  {e['kind'].replace('_', ' ').lower():<18} {e['actor'] or '?':<24} {e['detail']}")
        else:
            print("query what? gdp [FROM TO] | account NAME | top [N] | contract ID"); return 2
        return 0
    if cmd == "fuzz":
        from .fuzz import InvariantBroken, run as fuzz
        try:
            fuzz(runs=args.runs, steps=args.steps, seed=args.seed)
        except InvariantBroken as err:
            print(f"INVARIANT BROKEN. {err}"); return 1
        return 0
    if cmd == "prune":
        from .storage import BlockStore, StoreBusy
        if not args.store or not BlockStore(args.store).genesis_path.exists():
            print("prune what? give --store DIR (a validator's store directory)"); return 2
        st = BlockStore(args.store)
        try:
            st.lock()
            r = st.compact(args.keep, keep_archive=not args.no_archive)
        except StoreBusy as err:
            print(f"REFUSED. {err}. Stop it first, or start it with --prune-every to prune while running."); return 1
        except InvalidBlock as err:
            print(f"REFUSED. The store does not verify, so it will not be pruned: {err}"); return 1
        finally:
            st.unlock()
        if not r["pruned"]:
            print(f"nothing to prune: block {r['height']}, already starting from block {r['base']}"); return 0
        print(f"pruned blocks up to {r['base']} into a certified snapshot; blocks {r['base'] + 1}-{r['height']} kept. "
              f"blocks.jsonl {r['bytes_before']:,} -> {r['bytes_after']:,} bytes; "
              + ("retired blocks are in " + str(st.archive_dir) if not args.no_archive else "retired blocks DROPPED"))
        return 0
    if cmd == "doctor":
        from .doctor import run as doctor
        return doctor()
    if cmd == "submit" and len(args.paths) == 2:
        from . import tx as T
        from .net import Client
        try:
            tx = T.Transaction.from_dict(json.loads(Path(args.paths[0]).read_text()))
        except (OSError, ValueError, KeyError, TypeError) as err:
            print(f"not a signed transaction file: {err}"); return 2
        if not tx.signature_valid():
            print("REFUSED. The signature does not match the transaction: it was altered or signed with another key."); return 1
        host, port = args.paths[1].rsplit(":", 1)
        client = Client(host, int(port), expect_address=args.pin)
        try:
            before = client.account(tx.sender)
            if not before.get("found"):
                print("REFUSED. The sender is not registered on this ledger."); return 1
            if before["nonce"] != tx.nonce:
                print(f"REFUSED. The account's next transaction number is {before['nonce']}, this one is numbered {tx.nonce}. "
                      "Sign it again with the right number."); return 1
            client.submit(tx)
            print(f"sent {tx.kind.lower()} {tx.txid[:16]}…; waiting for finality")
            for _ in range(60):
                time.sleep(0.5)
                if client.account(tx.sender).get("nonce", 0) > tx.nonce:
                    print(f"FINAL. Transaction {tx.txid} is in a block."); return 0
        except OSError as err:
            print(f"could not reach {args.paths[1]}: {err}"); return 1
        print("not finalised within 30 s: the validators may have rejected it (check balance, purpose and policy)"); return 1
    if cmd == "api" and len(args.paths) == 1:
        from .api import serve
        try:
            server, stop = serve(args.paths[0], args.host, args.port, follow_source=args.follow, every=args.every,
                                 pin=args.pin, log=lambda m: print(m, flush=True))
        except (FileNotFoundError, OSError) as err:
            print(err); return 1
        print(f"read-only API on http://{args.host}:{args.port}/api/status"
              + (f", following {args.follow} every {args.every:g} s" if args.follow else "")
              + "\nopen site/dashboard.html and point it here. Ctrl+C to stop.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stop.set(); server.server_close()
        return 0
    if cmd == "metrics" and len(args.paths) == 1:
        from .index import Index
        out = args.out or "metrics.csv"
        n = Index(args.paths[0]).write_metrics_csv(out)
        print(f"wrote {n} rows (one per block) to {out}")
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
        from .keystore import KeystoreError, passphrase_from_env_or_prompt
        try:
            pw = passphrase_from_env_or_prompt("passphrase for all new key files: ", confirm=True) if args.encrypt else None
        except KeystoreError as err:
            print(err); return 2
        made = init(args.out or "net", hosts, issuers, args.chain_id, args.min_attestations,
                    parse_amount(args.unverified_limit), args.recovery_delay, parse_amount(args.treasury), pw)
        print(f"prepared a {len(hosts)}-validator network '{args.chain_id}' in {args.out or 'net'}/\n"
              f"  shared with everyone : genesis.json, peers.json\n"
              f"  one folder per machine: {made['validators']}  (each holds only its own key + start.sh)\n"
              f"  keep private          : issuer-*.key.json, treasury.key.json\n"
              f"On each machine: copy genesis.json, peers.json and its validator-i/ folder, then run validator-i/start.sh")
        return 0
    if cmd == "keygen":
        from .crypto import KeyPair
        from .keystore import KeystoreError, passphrase_from_env_or_prompt, save
        k = KeyPair.generate()
        try:
            pw = passphrase_from_env_or_prompt("new passphrase: ", confirm=True) if args.encrypt else None
            save(k, args.out or "key.json", pw)
        except KeystoreError as err:
            print(err); return 2
        print(f"wrote {args.out or 'key.json'} ({'encrypted with scrypt + AES-256-GCM' if pw else 'UNENCRYPTED: protect this file'}); "
              f"public key {k.address}")
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
