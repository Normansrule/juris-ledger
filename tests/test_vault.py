import json
import random
from itertools import combinations

import pytest

from jurisledger import vault as Vt
from jurisledger.contracts import Wallet
from jurisledger.crypto import KeyPair
from jurisledger.experiments import EXPERIMENTS, FRAMEWORK_PROSE, MiniWorld
from jurisledger.privacy import decrypt_note

TEXT = FRAMEWORK_PROSE


def test_shamir_any_k_shares_recover_and_fewer_do_not():
    secret = random.getrandbits(256)
    shares = Vt.split(secret, 5, 3)
    for combo in combinations(shares, 3):
        assert Vt.combine(list(combo)) == secret
    assert all(Vt.combine(list(c)) != secret for c in combinations(shares, 2))
    with pytest.raises(ValueError):
        Vt.combine([shares[0], shares[0]])


@pytest.fixture
def setup():
    m = MiniWorld()
    mill, bakery = m.w["mill"], m.w["bakery"]
    t = mill.create_contract("Lease", TEXT, {}, [mill.address, bakery.address], visibility="restricted")
    m.send(t, bakery.sign_contract(t.txid, TEXT))
    keys = [KeyPair.from_seed(f"c{i}") for i in range(4)]
    return m, t.txid, keys


def test_seal_refuses_the_wrong_text_and_detects_a_tampered_ciphertext(setup):
    m, cid, keys = setup
    with pytest.raises(Vt.VaultError, match="does not match"):
        Vt.seal(cid, TEXT + " (and a hidden clause)", m.chain, [k.address for k in keys], 2)
    sealed = Vt.seal(cid, TEXT, m.chain, [k.address for k in keys], 2)
    m.send(m.w["bakery"].access(cid, "VIEW", "read"))
    bad = dict(sealed, ciphertext=("00" if sealed["ciphertext"][:2] != "00" else "11") + sealed["ciphertext"][2:])
    with pytest.raises(Vt.VaultError, match="altered"):
        Vt.collect(bad, m.w["bakery"].key, [Vt.Custodian(k) for k in keys], m.chain)


def test_the_collusion_check_is_not_vacuous(setup):
    """The same method that fails with k-1 shares succeeds with k: the experiment's claim means something."""
    m, cid, keys = setup
    sealed = Vt.seal(cid, TEXT, m.chain, [k.address for k in keys], 2)
    notes = [decrypt_note(k.secret_hex(), k.address, sealed["shares"][k.address]) for k in keys[:2]]
    key = Vt.key_from_secret(Vt.combine([(int(n["x"]), int(n["y"], 16)) for n in notes], Vt.L))
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    plain = AESGCM(key).decrypt(bytes.fromhex(sealed["nonce"]), bytes.fromhex(sealed["ciphertext"]), cid.encode())
    assert plain.decode() == TEXT


def test_journal_survives_a_restart(setup, tmp_path):
    m, cid, keys = setup
    sealed = Vt.seal(cid, TEXT, m.chain, [k.address for k in keys], 2)
    m.send(m.w["bakery"].access(cid, "VIEW", "once"))
    j = str(tmp_path / "c0.jsonl")
    Vt.Custodian(keys[0], journal=j).release(sealed, m.w["bakery"].address, m.chain)
    restarted = Vt.Custodian(keys[0], journal=j)                    # same custodian after a restart
    with pytest.raises(Vt.VaultError, match="unspent"):
        restarted.release(sealed, m.w["bakery"].address, m.chain)
    assert json.loads(open(j).readline())["receipt"] == 1


def test_vault_experiment_passes():
    assert all(ok for _, ok in EXPERIMENTS["vault"](verbose=False)["checks"])



def test_reshare_needs_the_old_threshold_and_leaves_the_file_untouched_on_failure(setup):
    m, cid, keys = setup
    sealed = Vt.seal(cid, TEXT, m.chain, [k.address for k in keys], 3)
    before = json.dumps(sealed, sort_keys=True)
    with pytest.raises(Vt.VaultError, match="valid contributions"):
        Vt.reshare(sealed, [Vt.Custodian(k) for k in keys[:2]], [Vt.Custodian(KeyPair.from_seed(f"n{i}")) for i in range(3)], 2)
    assert json.dumps(sealed, sort_keys=True) == before


def test_a_contribution_that_does_not_start_from_the_senders_share_is_rejected_publicly(setup):
    m, cid, keys = setup
    sealed = Vt.seal(cid, TEXT, m.chain, [k.address for k in keys], 2)
    new = [k.address for k in keys]
    c = Vt.Custodian(keys[0]).contribute(sealed, new, 2)
    assert Vt.contribution_valid(sealed, c, 2)
    forged = dict(c, commitments=Vt.commit_poly([12345, 678]))         # a polynomial through someone else's value
    assert not Vt.contribution_valid(sealed, forged, 2)
    assert not Vt.contribution_valid(sealed, dict(c, x=2), 2)           # claiming another custodian's slot


def test_custodian_refuses_a_share_from_an_earlier_epoch(setup):
    m, cid, keys = setup
    sealed = Vt.seal(cid, TEXT, m.chain, [k.address for k in keys], 2)
    rotated, _ = Vt.reshare(sealed, [Vt.Custodian(k) for k in keys[:2]], [Vt.Custodian(k) for k in keys], 2)
    m.send(m.w["bakery"].access(cid, "VIEW", "read"))
    spliced = dict(rotated, shares=sealed["shares"])                 # new header, old shares
    with pytest.raises(Vt.VaultError, match="earlier set of custodians"):
        Vt.Custodian(keys[0]).release(spliced, m.w["bakery"].address, m.chain)


def test_version_1_files_still_open(setup):
    from jurisledger.privacy import encrypt_note
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import secrets as _s
    m, cid, keys = setup
    key, nonce = _s.token_bytes(32), _s.token_bytes(12)
    shares = Vt.split(int.from_bytes(key, "big"), len(keys), 2)
    v1 = {"version": 1, "contract_id": cid, "prose_hash": m.chain.state.contracts[cid]["prose_hash"], "threshold": 2,
          "nonce": nonce.hex(), "ciphertext": AESGCM(key).encrypt(nonce, TEXT.encode(), cid.encode()).hex(),
          "custodians": [k.address for k in keys],
          "shares": {k.address: encrypt_note(k.address, {"contract_id": cid, "x": x, "y": format(y, "x")}) for k, (x, y) in zip(keys, shares)},
          "share_digests": {str(x): Vt._share_digest(cid, x, y) for x, y in shares}}
    m.send(m.w["bakery"].access(cid, "VIEW", "read"))
    text, _ = Vt.collect(v1, m.w["bakery"].key, [Vt.Custodian(k) for k in keys], m.chain)
    assert text == TEXT
    with pytest.raises(Vt.VaultError, match="version-2"):
        Vt.reshare(v1, [Vt.Custodian(k) for k in keys], [Vt.Custodian(k) for k in keys], 2)
