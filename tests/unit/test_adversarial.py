"""Tests for adversarial test generators."""

from sentinel.evaluation.adversarial import (
    _generate_evasion_attacks,
    _generate_label_flip_attacks,
    _generate_prompt_injection_payloads,
)


class TestAdversarialGenerators:
    def test_evasion_attacks_generated(self):
        base = ["Multiple failed login attempts from 10.0.0.1"]
        attacks = _generate_evasion_attacks(base)
        assert len(attacks) >= 5
        for name, original, poisoned in attacks:
            assert isinstance(name, str)
            assert isinstance(original, str)
            assert isinstance(poisoned, str)
            # Poisoned should differ from original
            assert poisoned != original or name == "case_randomisation"

    def test_prompt_injection_payloads(self):
        payloads = _generate_prompt_injection_payloads()
        assert len(payloads) >= 5
        for name, payload in payloads:
            assert isinstance(name, str)
            assert isinstance(payload, str)
            assert len(payload) > 0

    def test_label_flip_attacks(self):
        attacks = _generate_label_flip_attacks()
        assert len(attacks) >= 3
        for name, desc, log_msg in attacks:
            assert isinstance(name, str)
            assert isinstance(log_msg, str)
