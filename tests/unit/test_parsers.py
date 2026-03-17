"""Unit tests for all log parsers."""

from __future__ import annotations

import pytest

from sentinel.core.enums import LogType
from sentinel.parsers.generic import GenericParser
from sentinel.parsers.hdfs import HDFSParser
from sentinel.parsers.openstack import OpenStackParser
from sentinel.parsers.registry import ParserRegistry, detect_log_type, preprocess_logs
from sentinel.parsers.syslog import SecurityLogParser, SyslogParser
from sentinel.parsers.web_server import WebServerParser


# =====================================================================
# WebServerParser
# =====================================================================
class TestWebServerParser:
    def setup_method(self):
        self.parser = WebServerParser()

    def test_log_type(self):
        assert self.parser.log_type == LogType.WEB_SERVER

    def test_detect_valid(self, sample_web_log):
        assert self.parser.detect(sample_web_log) is True

    def test_detect_invalid(self):
        assert self.parser.detect("just some random text") is False

    def test_parse_extracts_fields(self, sample_web_log):
        result = self.parser.parse(sample_web_log)
        assert result["ip_address"] == "192.168.1.100"
        assert result["status_code"] == "200"
        assert result["http_method"] == "GET"
        assert result["url"] == "/index.html"
        assert result["raw"] == sample_web_log

    def test_parse_fallback_on_bad_line(self):
        result = self.parser.parse("not a web log")
        assert "raw" in result
        assert result["raw"] == "not a web log"

    def test_parse_post_request(self):
        line = '10.0.0.1 - user [01/Jan/2025:00:00:00 +0000] "POST /api/login HTTP/1.1" 302 0'
        result = self.parser.parse(line)
        assert result["http_method"] == "POST"
        assert result["url"] == "/api/login"
        assert result["status_code"] == "302"


# =====================================================================
# SyslogParser
# =====================================================================
class TestSyslogParser:
    def setup_method(self):
        self.parser = SyslogParser()

    def test_log_type(self):
        assert self.parser.log_type == LogType.SYSLOG

    def test_detect_valid(self):
        line = "Jun 14 15:16:01 server kernel: some message"
        assert self.parser.detect(line) is True

    def test_detect_rejects_security_log(self, sample_security_log):
        # Security logs should be handled by SecurityLogParser
        assert self.parser.detect(sample_security_log) is False

    def test_parse(self):
        line = "Jun 14 15:16:01 myhost cron[123]: job completed"
        result = self.parser.parse(line)
        assert result["hostname"] == "myhost"
        assert "job completed" in result["message"]


# =====================================================================
# SecurityLogParser
# =====================================================================
class TestSecurityLogParser:
    def setup_method(self):
        self.parser = SecurityLogParser()

    def test_log_type(self):
        assert self.parser.log_type == LogType.SECURITY

    def test_detect_sshd(self, sample_security_log):
        assert self.parser.detect(sample_security_log) is True

    def test_detect_sudo(self):
        line = "Jun 14 15:16:01 server sudo: user1 : TTY=pts/0"
        assert self.parser.detect(line) is True

    def test_parse_sshd(self, sample_security_log):
        result = self.parser.parse(sample_security_log)
        assert result["service"] == "sshd"
        assert "Failed password" in result["message"]


# =====================================================================
# OpenStackParser
# =====================================================================
class TestOpenStackParser:
    def setup_method(self):
        self.parser = OpenStackParser()

    def test_log_type(self):
        assert self.parser.log_type == LogType.OPENSTACK

    def test_detect_valid(self, sample_openstack_log):
        assert self.parser.detect(sample_openstack_log) is True

    def test_parse(self, sample_openstack_log):
        result = self.parser.parse(sample_openstack_log)
        assert result["level"] == "INFO"
        assert "component" in result


# =====================================================================
# HDFSParser
# =====================================================================
class TestHDFSParser:
    def setup_method(self):
        self.parser = HDFSParser()

    def test_log_type(self):
        assert self.parser.log_type == LogType.HDFS

    def test_detect_valid(self, sample_hdfs_log):
        assert self.parser.detect(sample_hdfs_log) is True

    def test_parse_extracts_block_id(self, sample_hdfs_log):
        result = self.parser.parse(sample_hdfs_log)
        assert result["level"] == "INFO"
        assert "blk_-1608999687919862906" in result["block_ids"]
        assert result["raw"] == sample_hdfs_log


# =====================================================================
# GenericParser
# =====================================================================
class TestGenericParser:
    def test_always_detects(self):
        parser = GenericParser()
        assert parser.detect("anything at all") is True

    def test_parse_returns_raw(self):
        parser = GenericParser()
        result = parser.parse("hello world")
        assert result == {"raw": "hello world"}


# =====================================================================
# ParserRegistry
# =====================================================================
class TestParserRegistry:
    def test_auto_detect_web_server(self, sample_web_log):
        assert detect_log_type(sample_web_log) == LogType.WEB_SERVER

    def test_auto_detect_syslog(self):
        line = "Jun 14 15:16:01 server kernel: message"
        assert detect_log_type(line) == LogType.SYSLOG

    def test_auto_detect_security(self, sample_security_log):
        assert detect_log_type(sample_security_log) == LogType.SECURITY

    def test_auto_detect_hdfs(self, sample_hdfs_log):
        assert detect_log_type(sample_hdfs_log) == LogType.HDFS

    def test_auto_detect_generic_fallback(self):
        assert detect_log_type("just some random text 12345") == LogType.GENERIC

    def test_preprocess_returns_dataframe(self, sample_web_log):
        df = preprocess_logs([sample_web_log], LogType.WEB_SERVER)
        assert len(df) == 1
        assert "raw" in df.columns

    def test_preprocess_empty_list(self):
        df = preprocess_logs([])
        assert len(df) == 0

    def test_register_custom_parser(self):
        registry = ParserRegistry()
        initial_count = len(registry.parsers)

        class DummyParser(GenericParser):
            @property
            def log_type(self):
                return LogType.GENERIC

        registry.register(DummyParser())
        assert len(registry.parsers) == initial_count + 1
