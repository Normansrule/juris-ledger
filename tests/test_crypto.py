import pytest

from jurisledger.crypto import (EMPTY_ROOT, KeyPair, canonical, merkle_proof, merkle_root, sha256_hex,
                          verify, verify_merkle_proof)


def test_canonical_is_order_independent_and_rejects_floats():
    assert canonical({"b": 1, "a": [1, 2]}) == canonical({"a": [1, 2], "b": 1})
    with pytest.raises(TypeError):
        canonical({"amount": 1.5})


def test_signatures():
    k, other = KeyPair.from_seed("k"), KeyPair.from_seed("other")
    sig = k.sign(b"hello")
    assert verify(k.address, b"hello", sig)
    assert not verify(k.address, b"hello!", sig)
    assert not verify(other.address, b"hello", sig)
    assert not verify("zz", b"hello", sig)


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 13, 64, 100])
def test_merkle_proofs_for_every_leaf(n):
    leaves = [sha256_hex(str(i).encode()) for i in range(n)]
    root = merkle_root(leaves)
    for i, leaf in enumerate(leaves):
        proof = merkle_proof(leaves, i)
        assert verify_merkle_proof(leaf, proof, root)
        assert not verify_merkle_proof(sha256_hex(b"absent"), proof, root)


def test_merkle_root_changes_with_content_and_order():
    a, b = sha256_hex(b"a"), sha256_hex(b"b")
    assert merkle_root([a, b]) != merkle_root([b, a])
    assert merkle_root([a, b]) != merkle_root([a, b, b])      # no duplicate-leaf ambiguity
    assert merkle_root([]) == EMPTY_ROOT
