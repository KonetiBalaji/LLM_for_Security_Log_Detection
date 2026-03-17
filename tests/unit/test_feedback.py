"""Tests for the SOC analyst feedback store."""

import tempfile
from pathlib import Path

from sentinel.feedback.feedback_store import FeedbackEntry, FeedbackStore


class TestFeedbackStore:
    def setup_method(self):
        self._tmpfile = tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False)
        self._tmpfile.close()
        self.store = FeedbackStore(store_path=Path(self._tmpfile.name))

    def teardown_method(self):
        Path(self._tmpfile.name).unlink(missing_ok=True)

    def test_submit_and_retrieve(self):
        entry = FeedbackEntry(
            log_message="test log",
            predicted_label="Error",
            is_correct=True,
            analyst_id="analyst1",
        )
        entry_id = self.store.submit(entry)
        assert entry_id == entry.id

        all_entries = self.store.get_all()
        assert len(all_entries) == 1
        assert all_entries[0].log_message == "test log"

    def test_corrections(self):
        self.store.submit(FeedbackEntry(
            log_message="log1", predicted_label="Error",
            is_correct=False, correct_label="Security Alert",
        ))
        self.store.submit(FeedbackEntry(
            log_message="log2", predicted_label="Error",
            is_correct=True,
        ))

        corrections = self.store.get_corrections()
        assert len(corrections) == 1
        assert corrections[0].correct_label == "Security Alert"

    def test_stats(self):
        self.store.submit(FeedbackEntry(
            log_message="l1", predicted_label="A",
            predicted_method="regex", is_correct=True,
        ))
        self.store.submit(FeedbackEntry(
            log_message="l2", predicted_label="B",
            predicted_method="bert", is_correct=False,
            correct_label="C",
        ))

        stats = self.store.get_stats()
        assert stats["total"] == 2
        assert stats["correct"] == 1
        assert stats["accuracy"] == 0.5
        assert "regex" in stats["by_method"]
        assert "bert" in stats["by_method"]

    def test_export_training_data(self):
        self.store.submit(FeedbackEntry(
            log_message="bad log", predicted_label="Error",
            is_correct=False, correct_label="Security Alert",
        ))
        data = self.store.export_training_data()
        assert len(data) == 1
        assert data[0] == ("bad log", "Security Alert")

    def test_empty_store_stats(self):
        stats = self.store.get_stats()
        assert stats["total"] == 0
        assert stats["accuracy"] == 0.0

    def test_clear(self):
        self.store.submit(FeedbackEntry(log_message="x", predicted_label="Y", is_correct=True))
        self.store.clear()
        assert len(self.store.get_all()) == 0
