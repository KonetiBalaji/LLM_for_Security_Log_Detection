"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.core.config import SentinelSettings, reset_settings
from sentinel.core.enums import AttackType, ClassificationMethod, SeverityLevel
from sentinel.core.models import ClassificationResult, SecurityEvent


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    """Ensure each test gets fresh settings."""
    reset_settings()
    yield
    reset_settings()


@pytest.fixture
def project_root() -> Path:
    """Return the project root directory."""
    return Path(__file__).resolve().parent.parent


@pytest.fixture
def sample_web_log() -> str:
    return '192.168.1.100 - - [21/Apr/2019:03:39:58 +0330] "GET /index.html HTTP/1.1" 200 1234'


@pytest.fixture
def sample_syslog() -> str:
    return "Jun 14 15:16:01 server sshd[1234]: authentication failure; logname= uid=0"


@pytest.fixture
def sample_security_log() -> str:
    return "Jun 14 15:16:01 server sshd[1234]: Failed password for root from 192.168.1.200"


@pytest.fixture
def sample_openstack_log() -> str:
    return "nova.osapi_compute.wsgi.server 1234 INFO nova.api: GET /v2/servers/detail HTTP/1.1 status: 200"


@pytest.fixture
def sample_hdfs_log() -> str:
    return "081109 203518 148 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999687919862906"


@pytest.fixture
def sample_classified_logs() -> list[ClassificationResult]:
    return [
        ClassificationResult(
            source="TestSystem",
            log_message="IP 192.168.1.100 blocked due to potential attack",
            label="Security Alert",
            method=ClassificationMethod.REGEX,
            confidence=1.0,
            entities={"ip_addresses": ["192.168.1.100"]},
        ),
        ClassificationResult(
            source="TestSystem",
            log_message="Backup completed successfully.",
            label="System Notification",
            method=ClassificationMethod.REGEX,
            confidence=1.0,
        ),
        ClassificationResult(
            source="TestSystem",
            log_message="GET /v2/servers/detail HTTP/1.1 status: 404",
            label="HTTP Status",
            method=ClassificationMethod.BERT,
            confidence=0.85,
            entities={"http_method": "GET", "status_code": "404"},
        ),
        ClassificationResult(
            source="TestSystem",
            log_message="Multiple failed login attempts for user admin from 10.0.0.1",
            label="Security Alert",
            method=ClassificationMethod.BERT,
            confidence=0.92,
            entities={"username": "admin", "ip_addresses": ["10.0.0.1"]},
        ),
    ]


@pytest.fixture
def sample_security_events() -> list[SecurityEvent]:
    return [
        SecurityEvent(
            event_type="Security Alert",
            log_message="Brute force attack detected from 10.0.0.1",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            source_ips=["10.0.0.1"],
            attack_type=AttackType.BRUTE_FORCE,
            requires_attention=True,
        ),
        SecurityEvent(
            event_type="Suspicious HTTP Activity",
            log_message="GET /admin?id=1' OR 1=1-- HTTP/1.1",
            severity=SeverityLevel.LOW,
            confidence=0.7,
            source_ips=["192.168.1.50"],
            attack_type=AttackType.SQL_INJECTION,
            url_pattern="/admin?id=1' OR 1=1--",
        ),
    ]
