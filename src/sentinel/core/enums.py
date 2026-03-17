"""Enumerations for severity levels, attack types, log types, and MITRE tactics."""

from enum import Enum


class SeverityLevel(str, Enum):
    """Security event severity classification."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AttackType(str, Enum):
    """Known attack type categories aligned with common threat taxonomies."""

    BRUTE_FORCE = "BRUTE_FORCE"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    FILE_INCLUSION = "FILE_INCLUSION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    ENUMERATION = "ENUMERATION"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    MALWARE = "MALWARE"
    UNKNOWN = "UNKNOWN"


class LogType(str, Enum):
    """Supported log format types."""

    WEB_SERVER = "web_server"
    SYSLOG = "syslog"
    SECURITY = "security"
    OPENSTACK = "openstack"
    HDFS = "hdfs"
    GENERIC = "generic"


class MitreTactic(str, Enum):
    """MITRE ATT&CK Enterprise tactic categories."""

    RECONNAISSANCE = "Reconnaissance"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class ClassificationMethod(str, Enum):
    """Classification method identifier."""

    REGEX = "regex"
    BERT = "bert"
    LLM = "llm"
    ANOMALY = "anomaly"
