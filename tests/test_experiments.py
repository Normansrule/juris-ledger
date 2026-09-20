"""Every claim printed by `python -m jurisledger all` is asserted here."""
import pytest

from jurisledger.experiments import EXPERIMENTS


@pytest.mark.parametrize("name", sorted(EXPERIMENTS))
def test_experiment_claims_hold(name):
    result = EXPERIMENTS[name](verbose=False)
    failed = [claim for claim, ok in result["checks"] if not ok]
    assert not failed, failed
