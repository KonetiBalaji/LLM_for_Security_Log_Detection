"""Kafka consumer for real-time log ingestion and classification."""

from __future__ import annotations

import json
import logging
import signal
import sys
from typing import Any

from sentinel.analyzers.orchestrator import SecurityAnalyzer
from sentinel.classifiers.pipeline import ClassificationPipeline
from sentinel.core.config import SentinelSettings, get_settings

logger = logging.getLogger(__name__)


class SentinelKafkaConsumer:
    """Consume log messages from a Kafka topic, classify, and produce results.

    Parameters
    ----------
    input_topic:
        Kafka topic to consume raw log messages from.
    output_topic:
        Kafka topic to produce classification/analysis results to.
    bootstrap_servers:
        Kafka broker addresses.
    group_id:
        Consumer group ID.
    batch_size:
        Number of messages to accumulate before batch classification.
    settings:
        Application configuration.
    """

    def __init__(
        self,
        input_topic: str = "sentinel-logs",
        output_topic: str = "sentinel-results",
        bootstrap_servers: str = "localhost:9092",
        group_id: str = "sentinel-consumers",
        batch_size: int = 50,
        settings: SentinelSettings | None = None,
    ) -> None:
        self._input_topic = input_topic
        self._output_topic = output_topic
        self._bootstrap_servers = bootstrap_servers
        self._group_id = group_id
        self._batch_size = batch_size
        self._settings = settings or get_settings()
        self._running = False

        self._pipeline = ClassificationPipeline(settings=self._settings)
        self._analyzer = SecurityAnalyzer()

        self._consumer: Any = None
        self._producer: Any = None

    def _init_kafka(self) -> None:
        """Lazily initialise Kafka consumer and producer."""
        try:
            from kafka import KafkaConsumer, KafkaProducer
        except ImportError:
            raise ImportError(
                "kafka-python is required for streaming. "
                "Install with: pip install kafka-python"
            )

        self._consumer = KafkaConsumer(
            self._input_topic,
            bootstrap_servers=self._bootstrap_servers,
            group_id=self._group_id,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            auto_offset_reset="latest",
            enable_auto_commit=True,
            max_poll_records=self._batch_size,
        )

        self._producer = KafkaProducer(
            bootstrap_servers=self._bootstrap_servers,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        )

        logger.info(
            "Kafka connected: consuming '%s', producing to '%s'",
            self._input_topic,
            self._output_topic,
        )

    def start(self) -> None:
        """Start consuming and processing log messages."""
        self._init_kafka()
        self._running = True

        # Graceful shutdown on SIGINT/SIGTERM
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

        logger.info("SENTINEL streaming consumer started")

        batch: list[tuple[str, str]] = []

        while self._running:
            messages = self._consumer.poll(timeout_ms=1000)

            for topic_partition, records in messages.items():
                for record in records:
                    msg = record.value
                    source = msg.get("source", "kafka")
                    log_message = msg.get("log_message", msg.get("message", ""))

                    if not log_message:
                        continue

                    batch.append((source, log_message))

                    if len(batch) >= self._batch_size:
                        self._process_batch(batch)
                        batch = []

            # Process remaining messages in partial batch
            if batch:
                self._process_batch(batch)
                batch = []

    def _process_batch(self, batch: list[tuple[str, str]]) -> None:
        """Classify and analyse a batch of log messages."""
        classified = self._pipeline.classify(batch)
        analysis = self._analyzer.analyze(classified)

        # Produce individual classification results
        for result in classified:
            self._producer.send(
                self._output_topic,
                value={
                    "type": "classification",
                    "source": result.source,
                    "log_message": result.log_message,
                    "label": result.label,
                    "method": result.method.value,
                    "confidence": result.confidence,
                },
            )

        # Produce analysis summary if events detected
        if analysis.events:
            self._producer.send(
                self._output_topic,
                value={
                    "type": "analysis",
                    "event_count": len(analysis.events),
                    "highest_severity": (
                        analysis.highest_severity.value
                        if analysis.highest_severity
                        else None
                    ),
                    "requires_attention": analysis.requires_immediate_attention,
                    "summary": analysis.summary,
                },
            )

        self._producer.flush()
        logger.info("Processed batch of %d messages", len(batch))

    def _shutdown(self, signum: int, frame: Any) -> None:
        """Graceful shutdown handler."""
        logger.info("Shutting down streaming consumer...")
        self._running = False
        if self._consumer:
            self._consumer.close()
        if self._producer:
            self._producer.close()

    def stop(self) -> None:
        """Stop the consumer programmatically."""
        self._shutdown(0, None)
