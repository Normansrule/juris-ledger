import pytest

from jurisledger import bft


def test_single_phase_forks_and_two_phase_does_not_under_the_same_adversary():
    assert bft.run_partition(two_phase=False).forked()
    sim = bft.run_partition(two_phase=True)
    assert not sim.forked() and None not in sim.decisions().values()


def test_adversary_only_delays_never_drops():
    sim = bft.run_partition(two_phase=True)
    assert all(due > sim.time for due, _, _ in sim.queue)      # after healing, nothing is still being held back


@pytest.mark.parametrize("seed", range(40))
def test_two_phase_is_safe_and_live_with_one_liar(seed):
    sim = bft.run_fuzz(True, seed, byzantine=1)
    assert not sim.forked(sim.honest)
    assert None not in sim.decisions(sim.honest).values()


@pytest.mark.parametrize("n", [4, 7])
def test_two_phase_without_faults_agrees(n):
    sim = bft.run_fuzz(True, seed=n, byzantine=0, n=n)
    assert len(set(sim.decisions().values())) == 1


def test_a_locked_validator_refuses_a_rival_block():
    sim = bft.Sim([bft.TwoPhaseNode(i, 4) for i in range(4)])
    node = sim.nodes[2]
    node.locked_value, node.locked_round = "A", 0
    node.round = 1
    assert node._acceptable(bft.Msg(bft.PROPOSAL, 1, "B", 1)) is False
    assert node._acceptable(bft.Msg(bft.PROPOSAL, 1, "A", 1)) is True
    assert node._acceptable(bft.Msg(bft.PROPOSAL, 1, "B", 1, valid_round=0)) is None   # no proof of a polka for B
