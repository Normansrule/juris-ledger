import pytest

from jurisledger import fuzz
from jurisledger import state as S


def test_invariants_hold_under_random_attack():
    r = fuzz.run(runs=4, steps=300, log=lambda m: None)
    assert r.steps == 1200 and r.accepted > 300 and r.attacks_refused > 100
    assert r.by_kind.get("DISPUTE_AWARD", [0, 0])[0] > 0            # the deep paths are actually reached


def test_the_oracle_catches_a_planted_money_bug(monkeypatch):
    original = S.State._payment

    def leaky(self, tx, height):                                   # pays the recipient twice
        original(self, tx, height)
        self.accounts[tx.payload["to"]]["balance"] += 1
    monkeypatch.setattr(S.State, "_payment", leaky)
    with pytest.raises(fuzz.InvariantBroken, match="I1 money not conserved"):
        fuzz.run(runs=1, steps=200, log=lambda m: None)


def test_the_oracle_catches_a_non_atomic_rejection(monkeypatch):
    original = S.State.apply

    def half_applied(self, tx, height):                            # bumps the sender's number, then fails
        acct = self.accounts.get(tx.sender)
        try:
            original(self, tx, height)
        except S.InvalidTx:
            if acct is not None:
                acct["nonce"] += 1
            raise
    monkeypatch.setattr(S.State, "apply", half_applied)
    with pytest.raises(fuzz.InvariantBroken, match="I3"):
        fuzz.run(runs=1, steps=200, log=lambda m: None)


def test_cli_fuzz(capsys):
    from jurisledger.__main__ import main
    assert main(["jurisledger", "fuzz", "--runs", "1", "--steps", "100"]) == 0
    assert "All eight invariants held" in capsys.readouterr().out
