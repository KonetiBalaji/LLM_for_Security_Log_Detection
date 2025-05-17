from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
import re
import pandas as pd
from dataclasses import dataclass, asdict

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AttackType(str, Enum):
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

@dataclass
class SecurityEvent:
    """Represents a security event identified in logs"""
    event_type: str
    log_message: str
    severity: SeverityLevel
    confidence: float
    source_ips: List[str]
    url_pattern: Optional[str] = None
    attack_type: AttackType = AttackType.UNKNOWN
    http_method: Optional[str] = None
    status_code: Optional[str] = None
    user_agent: Optional[str] = None
    username: Optional[str] = None
    timestamp: Optional[str] = None
    requires_attention: bool = False
    root_cause: Optional[str] = None
    recommendation: Optional[str] = None
    related_events: List[int] = None
    
    def __post_init__(self):
        if self.related_events is None:
            self.related_events = []

class SecurityAnalyzer:
    """Analyze classified logs for security events using LLM with rule-based fallback"""
    
    def __init__(self):
        """Initialize the security analyzer"""
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.url_pattern = re.compile(r'(?:GET|POST|PUT|DELETE|HEAD) ([^\s"]+)')
        self.http_method_pattern = re.compile(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\b')
        self.status_code_pattern = re.compile(r'status: (\d{3})|HTTP (\d{3})|code (\d{3})')
        self.username_pattern = re.compile(r'user[:\s]+(\w+)|User(\d+)')
        
        # Lazily initialize LLM processor when needed
        self.llm_processor = None
    
    def analyze(self, classified_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze classified logs for security patterns with enhanced LLM analysis
        
        Args:
            classified_logs: List of classified log dictionaries
            
        Returns:
            Analysis results dictionary with events, patterns, and summary
        """
        # Extract security events with enhanced LLM analysis
        events = self._extract_security_events(classified_logs)
        
        # Group related events
        grouped_events = self._group_related_events(events)
        
        # Analyze IP patterns
        ip_frequency = self._analyze_ip_frequency(classified_logs)
        suspicious_ips = self._identify_suspicious_ips(ip_frequency)
        
        # Analyze URL patterns
        url_patterns = self._analyze_url_patterns(classified_logs)
        
        # Analyze time patterns
        time_patterns = self._analyze_time_patterns(classified_logs)
        
        # Determine highest severity
        highest_severity = self._determine_highest_severity(events)
        
        # Generate recommendations using LLM with fallback
        recommendations, llm_rec_success = self._generate_recommendations_with_llm(
            events, suspicious_ips, highest_severity
        )
        
        # Generate summary
        summary = self._generate_summary(
            events, 
            grouped_events,
            suspicious_ips, 
            url_patterns, 
            time_patterns
        )
        
        # Create analysis results
        analysis_results = {
            "events": [asdict(event) for event in events],
            "grouped_events": grouped_events,
            "ip_analysis": {
                "frequency": ip_frequency,
                "suspicious": suspicious_ips
            },
            "url_analysis": url_patterns,
            "time_analysis": time_patterns,
            "highest_severity": highest_severity.value if highest_severity else None,
            "requires_immediate_attention": highest_severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH],
            "summary": summary,
            "recommendations": recommendations,
            "analysis_method": "llm_with_fallback" if llm_rec_success else "rule_based"
        }
        
        return analysis_results
    
    def _extract_security_events(self, classified_logs: List[Dict[str, Any]]) -> List[SecurityEvent]:
        """Extract security events from classified logs with enhanced LLM analysis
        
        Args:
            classified_logs: List of classified log dictionaries
            
        Returns:
            List of SecurityEvent objects
        """
        events = []
        
        for i, log in enumerate(classified_logs):
            # Initialize variables
            event_type = None
            severity = SeverityLevel.LOW
            attack_type = AttackType.UNKNOWN
            requires_attention = False
            
            classification = log.get("classification", "")
            log_message = log.get("log_message", "")
            
            # Extract entities
            source_ips = self._extract_ips(log_message)
            url_pattern = self._extract_url(log_message)
            http_method = self._extract_http_method(log_message)
            status_code = self._extract_status_code(log_message)
            username = self._extract_username(log_message)
            
            # Determine if this is a security event based on classification
            if classification == "Security Alert":
                event_type = "Security Alert"
                severity = SeverityLevel.HIGH
                requires_attention = True
                
                # Determine attack type
                if any(term in log_message.lower() for term in ["brute force", "multiple fail", "repeated attempt"]):
                    attack_type = AttackType.BRUTE_FORCE
                elif any(term in log_message.lower() for term in ["sql injection", "sqli", "union select"]):
                    attack_type = AttackType.SQL_INJECTION
                    severity = SeverityLevel.CRITICAL
                elif any(term in log_message.lower() for term in ["xss", "cross site", "script"]):
                    attack_type = AttackType.XSS
                    severity = SeverityLevel.HIGH
                elif any(term in log_message.lower() for term in ["file inclusion", "lfi", "rfi", "../"]):
                    attack_type = AttackType.FILE_INCLUSION
                    severity = SeverityLevel.CRITICAL
                elif any(term in log_message.lower() for term in ["command", "exec", "shell", "cmd"]):
                    attack_type = AttackType.COMMAND_INJECTION
                    severity = SeverityLevel.CRITICAL
                elif any(term in log_message.lower() for term in ["path traversal", "directory traversal", "../"]):
                    attack_type = AttackType.PATH_TRAVERSAL
                    severity = SeverityLevel.HIGH
                elif any(term in log_message.lower() for term in ["privilege", "escalat", "admin", "root"]):
                    attack_type = AttackType.PRIVILEGE_ESCALATION
                    severity = SeverityLevel.CRITICAL
                elif any(term in log_message.lower() for term in ["denial", "dos", "ddos", "flood"]):
                    attack_type = AttackType.DENIAL_OF_SERVICE
                    severity = SeverityLevel.HIGH
                
            elif classification == "Critical Error":
                event_type = "Critical Error"
                severity = SeverityLevel.HIGH
                requires_attention = True
            elif "error" in classification.lower() or "fail" in classification.lower():
                event_type = classification
                severity = SeverityLevel.MEDIUM
            elif "HTTP Status" == classification and status_code and status_code.startswith("4"):
                # HTTP 4xx errors might indicate scanning or enumeration
                event_type = "Suspicious HTTP Activity"
                severity = SeverityLevel.LOW
                attack_type = AttackType.ENUMERATION
            elif any(term in log_message.lower() for term in ["unauthorized", "suspicious", "unusual"]):
                event_type = "Suspicious Activity"
                severity = SeverityLevel.MEDIUM
                requires_attention = True
            
            # Only create events for security-related logs
            if event_type:
                # Use LLM for root cause analysis with fallback
                root_cause, llm_rca_success = self._determine_root_cause_with_llm(
                    log_message, classification, event_type
                )
                
                # Use LLM for recommendations with fallback
                recommendation, llm_rec_success = self._generate_event_recommendation_with_llm(
                    log_message, attack_type, severity
                )
                
                events.append(SecurityEvent(
                    event_type=event_type,
                    log_message=log_message,
                    severity=severity,
                    confidence=log.get("confidence", 0.5),
                    source_ips=source_ips,
                    url_pattern=url_pattern,
                    attack_type=attack_type,
                    http_method=http_method,
                    status_code=status_code,
                    username=username,
                    timestamp=log.get("timestamp"),
                    requires_attention=requires_attention,
                    root_cause=root_cause,
                    recommendation=recommendation,
                    related_events=[]
                ))
        
        return events
    
    def _determine_root_cause_with_llm(self, log_message: str, classification: str, 
                                     event_type: str = None) -> Tuple[str, bool]:
        """Determine root cause using LLM with fallback to rule-based analysis
        
        Args:
            log_message: Log message
            classification: Log classification
            event_type: Type of security event (optional)
            
        Returns:
            Tuple of (root_cause_description, success_flag)
        """
        # Initialize LLM processor if needed
        if not self.llm_processor:
            from src.processor_llm import LLMProcessor
            self.llm_processor = LLMProcessor()
        
        # Create prompt for root cause analysis
        prompt = f"""Analyze this log message and provide a detailed technical root cause analysis.

Log Message: {log_message}
Classification: {classification}
Event Type: {event_type if event_type else "Unknown"}

Focus on explaining:
1. What specific problem or issue occurred
2. What components or systems are involved
3. What is the most likely technical cause of this issue
4. What specific vulnerability or misconfiguration might have led to this
5. Are there any potential security implications

Provide your technical root cause analysis inside <root_cause> </root_cause> tags.
Keep your analysis concise but technically precise (3-4 sentences maximum).
"""

        try:
            # Get response from LLM
            response = self.llm_processor.classify_with_llm(log_message, prompt)
            
            # Check if root_cause is in the response
            if "root_cause" in response:
                return response["root_cause"], True
            else:
                # Fallback to rule-based if LLM didn't provide the expected format
                return self._determine_root_cause_rule_based(log_message, classification), False
                
        except Exception as e:
            print(f"Error in LLM-based root cause analysis: {e}")
            # Fallback to rule-based analysis
            return self._determine_root_cause_rule_based(log_message, classification), False
    
    def _determine_root_cause_rule_based(self, log_message: str, classification: str) -> str:
        """Rule-based root cause analysis as fallback
        
        Args:
            log_message: Log message
            classification: Log classification
            
        Returns:
            Root cause description
        """
        log_lower = log_message.lower()
        
        # Authentication/Security issues
        if "brute force" in log_lower or "multiple failed" in log_lower:
            return "Automated attack attempting to guess credentials by repeatedly trying different password combinations. This could indicate targeted account compromise attempts or widespread scanning."
        elif "sql injection" in log_lower:
            return "Malicious attempt to manipulate database queries by injecting SQL code. The application may have inadequate input validation or parameterized queries are not being used properly."
        elif "xss" in log_lower or "cross site" in log_lower:
            return "Attempt to inject malicious scripts into web pages viewed by other users. This indicates insufficient output encoding or input validation in the web application."
        elif "file inclusion" in log_lower or "directory traversal" in log_lower:
            return "Attempt to access unauthorized files or directories by manipulating path parameters. This suggests improper file path validation or incorrect permission controls."
        elif "command injection" in log_lower:
            return "Attempt to execute arbitrary commands on the server by injecting OS commands. This indicates unsafe handling of user input in system command execution."
        elif "privilege" in log_lower and "escalat" in log_lower:
            return "Attempt to gain higher-level permissions than authorized. This could be due to vulnerable software, misconfigured permissions, or exploitation of a known vulnerability."
        elif "unauthorized" in log_lower:
            return "Access attempt without proper authentication or authorization. This may indicate improper access controls, broken authentication mechanisms, or account compromise."
            
        # Error conditions
        elif "null pointer" in log_lower or "nullpointer" in log_lower:
            return "Application attempted to use a null reference, indicating improper initialization, missing error handling, or logic flaws in the code."
        elif "out of memory" in log_lower:
            return "Application exhausted available memory resources. This could be due to memory leaks, resource-intensive operations, or insufficient system resources."
        elif "connection refused" in log_lower or "connection timeout" in log_lower:
            return "Failed network connection, indicating network partition, service unavailability, incorrect address/port, or firewall restrictions."
        elif "disk full" in log_lower or "no space" in log_lower:
            return "System has insufficient disk space for the operation. This may require cleanup of temporary files, log rotation, or increased storage allocation."
        elif "error" in log_lower and "timeout" in log_lower:
            return "Operation exceeded the allocated time limit. This could indicate performance issues, deadlocks, high system load, or network problems."
        elif "deadlock" in log_lower:
            return "Resource conflict where multiple processes are blocking each other. This indicates concurrency issues in the application design."
        elif "500" in log_lower and ("error" in log_lower or "http" in log_lower):
            return "Server-side processing error in the web application. This requires investigation of application logs for the specific error stack trace."
        elif "404" in log_lower and ("error" in log_lower or "http" in log_lower):
            return "Requested resource not found. This could indicate deleted content, misconfigured routes, or attempted access to non-existent resources."
        elif "403" in log_lower and ("error" in log_lower or "http" in log_lower):
            return "Access forbidden to the requested resource. This indicates permission issues or intentional access restrictions."
            
        # Classification-based generic causes
        elif classification == "Critical Error":
            return "Severe system issue that impacts core functionality. This requires immediate investigation of logs and system state."
        elif "error" in classification.lower():
            return "Application or system error that may impact functionality. Review detailed error messages and associated system state for specific cause."
        elif "workflow" in classification.lower() and "error" in classification.lower():
            return "Process execution failure in a defined workflow. This could indicate data validation issues, state inconsistencies, or dependency failures."
        elif "deprecation" in classification.lower():
            return "Use of outdated components or APIs that will be removed in future versions. Update to recommended alternatives as specified."
        
        # Default case
        return "Insufficient information to determine specific root cause. Additional context or log correlation may be required."
    
    def _generate_event_recommendation_with_llm(self, log_message: str, 
                                             attack_type: AttackType, 
                                             severity: SeverityLevel) -> Tuple[str, bool]:
        """Generate recommendations using LLM with fallback to rule-based
        
        Args:
            log_message: Log message
            attack_type: Type of attack
            severity: Severity level
            
        Returns:
            Tuple of (recommendations, success_flag)
        """
        # Initialize LLM processor if needed
        if not self.llm_processor:
            from src.processor_llm import LLMProcessor
            self.llm_processor = LLMProcessor()
        
        # Create prompt for recommendations
        prompt = f"""Based on this security log event, provide specific, actionable recommendations for remediation.

Log Message: {log_message}
Attack Type: {attack_type.value if attack_type != AttackType.UNKNOWN else "Unknown"}
Severity: {severity.value}

Provide 3-5 clear, prioritized, actionable technical recommendations that would address:
1. The immediate security issue
2. The root cause of the problem
3. How to prevent similar issues in the future

Format your recommendations as a numbered list inside <recommendations> </recommendations> tags.
Each recommendation should be concise but specific enough to be actionable.
"""

        try:
            # Get response from LLM
            response = self.llm_processor.classify_with_llm(log_message, prompt)
            
            # Check if recommendations is in the response
            if "recommendations" in response:
                return response["recommendations"], True
            else:
                # Fallback to rule-based if LLM didn't provide the expected format
                return self._generate_event_recommendation_rule_based(attack_type, severity), False
                
        except Exception as e:
            print(f"Error in LLM-based recommendations: {e}")
            # Fallback to rule-based recommendations
            return self._generate_event_recommendation_rule_based(attack_type, severity), False
    
    def _generate_event_recommendation_rule_based(self, attack_type: AttackType, severity: SeverityLevel) -> str:
        """Rule-based recommendation generator as fallback
        
        Args:
            attack_type: Type of attack
            severity: Severity level
            
        Returns:
            Recommendation string
        """
        # Base recommendations by attack type
        if attack_type == AttackType.BRUTE_FORCE:
            return ("1. Implement account lockout policies (e.g., 5 failed attempts = 15 min lockout).\n"
                    "2. Enable multi-factor authentication for all administrative accounts.\n"
                    "3. Set up alerts for multiple failed login attempts.\n"
                    "4. Consider IP-based rate limiting for authentication endpoints.")
                    
        elif attack_type == AttackType.SQL_INJECTION:
            return ("1. Review and fix all SQL queries to use parameterized statements.\n"
                    "2. Implement input validation with strict whitelisting approach.\n"
                    "3. Deploy a Web Application Firewall (WAF) with SQL injection rules.\n"
                    "4. Consider using an ORM framework to handle database interactions.")
                    
        elif attack_type == AttackType.XSS:
            return ("1. Implement proper output encoding for all user-controlled data.\n"
                    "2. Configure Content Security Policy (CSP) headers.\n"
                    "3. Use framework-provided XSS protection functions.\n"
                    "4. Validate and sanitize all user inputs with context-aware filters.")
                    
        elif attack_type == AttackType.FILE_INCLUSION:
            return ("1. Validate and sanitize all file paths with whitelisting.\n"
                    "2. Use absolute paths instead of relative ones.\n"
                    "3. Implement proper access controls for file operations.\n"
                    "4. Consider using a file access abstraction layer.")
                    
        elif attack_type == AttackType.COMMAND_INJECTION:
            return ("1. Avoid using system commands with user input whenever possible.\n"
                    "2. If necessary, implement strict input validation and sanitization.\n"
                    "3. Use language-specific APIs instead of shell commands.\n"
                    "4. Run with least privileges in a contained environment.")
                    
        elif attack_type == AttackType.PATH_TRAVERSAL:
            return ("1. Validate file paths and normalize before use.\n"
                    "2. Use path canonicalization to resolve and verify paths.\n"
                    "3. Implement proper access controls for all file operations.\n"
                    "4. Consider using safe APIs for file operations.")
                    
        elif attack_type == AttackType.PRIVILEGE_ESCALATION:
            return ("1. Implement least privilege principle across all systems.\n"
                    "2. Conduct regular permission audits for all user roles.\n"
                    "3. Apply security patches promptly.\n"
                    "4. Use privileged access management (PAM) solutions.\n"
                    "5. Monitor all privilege changes and escalations.")
                    
        elif attack_type == AttackType.DENIAL_OF_SERVICE:
            return ("1. Implement rate limiting and traffic filtering.\n"
                    "2. Configure resource allocation controls and timeouts.\n"
                    "3. Consider using a CDN or DDoS protection service.\n"
                    "4. Optimize application performance to handle load spikes.")
                    
        elif attack_type == AttackType.ENUMERATION:
            return ("1. Implement consistent error messages that don't leak information.\n"
                    "2. Apply rate limiting for failed or repetitive requests.\n"
                    "3. Consider adding CAPTCHA for repeated failed actions.\n"
                    "4. Use generic error pages for all types of errors.")
                    
        elif attack_type == AttackType.INFORMATION_DISCLOSURE:
            return ("1. Review application to ensure sensitive data is properly protected.\n"
                    "2. Implement proper error handling that doesn't reveal system details.\n"
                    "3. Apply the principle of least privilege for all data access.\n"
                    "4. Use data masking for sensitive information in logs and responses.")
                    
        # Severity-based generic recommendations
        elif severity == SeverityLevel.CRITICAL:
            return ("1. Investigate immediately and isolate affected systems if necessary.\n"
                    "2. Address the underlying vulnerability with highest priority.\n"
                    "3. Conduct a forensic analysis to determine impact and scope.\n"
                    "4. Develop and apply patches or configuration changes.\n"
                    "5. Review similar systems for the same vulnerability.")
                    
        elif severity == SeverityLevel.HIGH:
            return ("1. Prioritize investigation within the next 24 hours.\n"
                    "2. Apply temporary mitigations if immediate fixes aren't available.\n"
                    "3. Develop a remediation plan with clear ownership and timeline.\n"
                    "4. Test and deploy fixes as soon as possible.")
                    
        elif severity == SeverityLevel.MEDIUM:
            return ("1. Schedule investigation and remediation during the next maintenance cycle.\n"
                    "2. Apply standard best practices for the affected component.\n"
                    "3. Monitor for any escalation or increased frequency of the issue.")
                    
        elif severity == SeverityLevel.LOW:
            return ("1. Document the issue for future reference.\n"
                    "2. Address during routine maintenance or updates.\n"
                    "3. Monitor for pattern changes that might indicate increased risk.")
                    
        else:
            return "Monitor for recurring patterns or escalation of this issue."
    
    def _generate_recommendations_with_llm(self, 
                                        events: List[SecurityEvent],
                                        suspicious_ips: List[Dict[str, Any]],
                                        highest_severity: SeverityLevel) -> Tuple[List[str], bool]:
        """Generate overall recommendations using LLM with fallback to rule-based
        
        Args:
            events: List of SecurityEvent objects
            suspicious_ips: List of suspicious IP details
            highest_severity: Highest severity level
            
        Returns:
            Tuple of (list_of_recommendations, success_flag)
        """
        # If no events, use rule-based approach
        if not events:
            return self._generate_recommendations_rule_based(events, suspicious_ips, highest_severity), False
        
        # Initialize LLM processor if needed
        if not self.llm_processor:
            from src.processor_llm import LLMProcessor
            self.llm_processor = LLMProcessor()
        
        # Prepare summary of events for the prompt
        event_summaries = []
        for i, event in enumerate(events[:10]):  # Limit to top 10 events to avoid token limits
            event_summaries.append(f"Event {i+1}: {event.event_type} - {event.severity.value} - {event.attack_type.value if event.attack_type != AttackType.UNKNOWN else 'Unknown'}")
        
        # Prepare suspicious IPs summary
        ip_summaries = []
        for ip in suspicious_ips[:5]:  # Limit to top 5 IPs
            ip_summaries.append(f"IP: {ip.get('ip')} - Requests: {ip.get('request_count')} - Level: {ip.get('suspicion_level')}")
        
        # Cleaned prompt assignment to avoid hidden characters
        prompt = (
            "Based on the security analysis results, provide comprehensive security recommendations.\n\n"
            "Event Summary:\n" + "\n".join(event_summaries) + "\n\n"
            "Suspicious IPs:\n" + ("\n".join(ip_summaries) if ip_summaries else "None detected") + "\n\n"
            f"Highest Severity: {highest_severity.value if highest_severity else 'None'}\n\n"
            "Provide a comprehensive set of prioritized security recommendations that:\n"
            "1. Address the most critical issues first\n"
            "2. Include specific, actionable steps\n"
            "3. Cover both immediate response and long-term prevention\n"
            "4. Are organized in logical categories (e.g., Authentication, Network Security, etc.)\n\n"
            "Format your response as a bulleted list inside <recommendations> </recommendations> tags.\n"
            "Each recommendation should be clear and actionable for IT security personnel."
        )

        try:
            # Get response from LLM
            response = self.llm_processor.classify_with_llm("", prompt)
            
            # Check if recommendations is in the response
            if "recommendations" in response:
                recommendations_text = response["recommendations"].strip()
                # Split into list of recommendations
                recommendations = [line.strip() for line in recommendations_text.split('\n') if line.strip()]
                return recommendations, True
            else:
                # Fallback to rule-based if LLM didn't provide the expected format
                return self._generate_recommendations_rule_based(events, suspicious_ips, highest_severity), False
                
        except Exception as e:
            print(f"Error in LLM-based comprehensive recommendations: {e}")
            # Fallback to rule-based recommendations
            return self._generate_recommendations_rule_based(events, suspicious_ips, highest_severity), False
    
    def _generate_recommendations_rule_based(self, 
                                          events: List[SecurityEvent],
                                          suspicious_ips: List[Dict[str, Any]],
                                          highest_severity: SeverityLevel) -> List[str]:
        """Generate recommendations based on rule-based analysis.
        Args:
            events: List of security events
            suspicious_ips: List of suspicious IPs
            highest_severity: Highest severity level found
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        # Add severity-based recommendations
        if highest_severity == SeverityLevel.CRITICAL:
            recommendations.append("CRITICAL: Immediate action required. Review all critical events and implement recommended fixes.")
        elif highest_severity == SeverityLevel.HIGH:
            recommendations.append("HIGH: Prompt attention needed. Address high severity issues within 24 hours.")
        
        # Add attack type specific recommendations
        attack_types = {event.attack_type for event in events if event.attack_type != AttackType.UNKNOWN}
        
        if AttackType.BRUTE_FORCE in attack_types:
            recommendations.append("Implement rate limiting and account lockout policies to prevent brute force attacks.")
        
        if AttackType.SQL_INJECTION in attack_types:
            recommendations.append("Review and sanitize all database queries. Use parameterized queries to prevent SQL injection.")
        
        if AttackType.XSS in attack_types:
            recommendations.append("Implement proper input validation and output encoding to prevent XSS attacks.")
        
        if AttackType.FILE_INCLUSION in attack_types:
            recommendations.append("Restrict file access and implement proper path validation to prevent file inclusion attacks.")
        
        if AttackType.COMMAND_INJECTION in attack_types:
            recommendations.append("Sanitize all user inputs used in command execution to prevent command injection.")
        
        if AttackType.PATH_TRAVERSAL in attack_types:
            recommendations.append("Implement proper path validation and access controls to prevent path traversal attacks.")
        
        if AttackType.PRIVILEGE_ESCALATION in attack_types:
            recommendations.append("Review user permissions and implement principle of least privilege.")
        
        if AttackType.DENIAL_OF_SERVICE in attack_types:
            recommendations.append("Implement rate limiting and DDoS protection measures.")
        
        # Add IP-based recommendations
        if suspicious_ips:
            recommendations.append(f"Investigate and potentially block {len(suspicious_ips)} suspicious IP addresses.")
        
        # Add general recommendations
        recommendations.extend([
            "Review and update security policies and procedures.",
            "Ensure all systems are patched and up to date.",
            "Implement comprehensive logging and monitoring.",
            "Conduct regular security assessments and penetration testing."
        ])
        
        return recommendations
    
    def _group_related_events(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Group related security events
        
        Args:
            events: List of SecurityEvent objects
            
        Returns:
            List of event groups
        """
        if not events:
            return []
            
        # Initialize groups
        groups = []
        
        # Group by IP
        ip_groups = {}
        for i, event in enumerate(events):
            for ip in event.source_ips:
                if ip not in ip_groups:
                    ip_groups[ip] = []
                ip_groups[ip].append(i)
        
        # Group by attack type
        attack_groups = {}
        for i, event in enumerate(events):
            if event.attack_type != AttackType.UNKNOWN:
                attack_key = event.attack_type.value
                if attack_key not in attack_groups:
                    attack_groups[attack_key] = []
                attack_groups[attack_key].append(i)
        
        # Create group objects
        for ip, indices in ip_groups.items():
            if len(indices) > 1:
                highest_severity = max([events[i].severity for i in indices], key=lambda s: SeverityLevel[s.value])
                groups.append({
                    "type": "IP-based",
                    "key": ip,
                    "event_indices": indices,
                    "severity": highest_severity.value,
                    "count": len(indices),
                    "requires_attention": any(events[i].requires_attention for i in indices)
                })
        
        for attack, indices in attack_groups.items():
            if len(indices) > 1:
                highest_severity = max([events[i].severity for i in indices], key=lambda s: SeverityLevel[s.value])
                groups.append({
                    "type": "Attack-based",
                    "key": attack,
                    "event_indices": indices,
                    "severity": highest_severity.value,
                    "count": len(indices),
                    "requires_attention": any(events[i].requires_attention for i in indices)
                })
        
        # Update related events in each event
        for group in groups:
            for i in group["event_indices"]:
                events[i].related_events = [j for j in group["event_indices"] if j != i]
        
        return groups
    
    def _extract_ips(self, log_message: str) -> List[str]:
        """Extract IP addresses from log message
        
        Args:
            log_message: Log message
            
        Returns:
            List of IP addresses
        """
        return self.ip_pattern.findall(log_message)
    
    def _extract_url(self, log_message: str) -> Optional[str]:
        """Extract URL from log message
        
        Args:
            log_message: Log message
            
        Returns:
            URL or None
        """
        match = self.url_pattern.search(log_message)
        return match.group(1) if match else None
    
    def _extract_http_method(self, log_message: str) -> Optional[str]:
        """Extract HTTP method from log message
        
        Args:
            log_message: Log message
            
        Returns:
            HTTP method or None
        """
        match = self.http_method_pattern.search(log_message)
        return match.group(0) if match else None
    
    def _extract_status_code(self, log_message: str) -> Optional[str]:
        """Extract HTTP status code from log message
        
        Args:
            log_message: Log message
            
        Returns:
            Status code or None
        """
        match = self.status_code_pattern.search(log_message)
        if match:
            for group in match.groups():
                if group:
                    return group
        return None
    
    def _extract_username(self, log_message: str) -> Optional[str]:
        """Extract username from log message
        
        Args:
            log_message: Log message
            
        Returns:
            Username or None
        """
        match = self.username_pattern.search(log_message)
        if match:
            return match.group(1) or match.group(2)
        return None
    
    def _analyze_ip_frequency(self, logs: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze IP address frequency in logs
        
        Args:
            logs: List of log dictionaries
            
        Returns:
            Dictionary mapping IP addresses to frequency counts
        """
        ip_counts = {}
        
        for log in logs:
            ips = self._extract_ips(log.get("log_message", ""))
            for ip in ips:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        return ip_counts
    
    def _identify_suspicious_ips(self, ip_frequency: Dict[str, int], threshold: int = 5) -> List[Dict[str, Any]]:
        """Identify suspicious IPs based on frequency
        
        Args:
            ip_frequency: IP frequency dictionary
            threshold: Frequency threshold for suspicion
            
        Returns:
            List of suspicious IP details
        """
        suspicious = []
        
        for ip, count in ip_frequency.items():
            if count >= threshold:
                suspicious.append({
                    "ip": ip,
                    "request_count": count,
                    "suspicion_level": "High" if count >= 10 else "Medium"
                })
        
        return suspicious
    
    def _analyze_url_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Analyze URL patterns in logs
        
        Args:
            logs: List of log dictionaries
            
        Returns:
            Dictionary mapping URLs to details
        """
        url_data = {}
        
        for log in logs:
            log_message = log.get("log_message", "")
            url = self._extract_url(log_message)
            
            if url:
                if url not in url_data:
                    url_data[url] = {
                        "count": 0,
                        "methods": {},
                        "status_codes": {},
                        "ips": set()
                    }
                
                url_data[url]["count"] += 1
                
                # Count HTTP methods
                method = self._extract_http_method(log_message)
                if method:
                    url_data[url]["methods"][method] = url_data[url]["methods"].get(method, 0) + 1
                
                # Count status codes
                code = self._extract_status_code(log_message)
                if code:
                    url_data[url]["status_codes"][code] = url_data[url]["status_codes"].get(code, 0) + 1
                
                # Track unique IPs
                ips = self._extract_ips(log_message)
                url_data[url]["ips"].update(ips)
        
        # Convert sets to lists for JSON serialization
        for url in url_data:
            url_data[url]["ips"] = list(url_data[url]["ips"])
            url_data[url]["unique_ip_count"] = len(url_data[url]["ips"])
        
        return url_data
    
    def _analyze_time_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze time-based patterns in logs
        
        Args:
            logs: List of log dictionaries
            
        Returns:
            Dictionary with time analysis details
        """
        # This would require timestamp parsing, which might vary by log format
        # For now, return a placeholder
        return {
            "analysis_available": False,
            "reason": "Timestamp parsing requires log format specification"
        }
    
    def _determine_highest_severity(self, events: List[SecurityEvent]) -> Optional[SeverityLevel]:
        """Determine the highest severity level in events
        
        Args:
            events: List of SecurityEvent objects
            
        Returns:
            Highest severity level or None if no events
        """
        if not events:
            return None
        
        severity_order = {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1,
            SeverityLevel.INFO: 0
        }
        
        return max(events, key=lambda e: severity_order[e.severity]).severity
    
    def _generate_summary(self, 
                         events: List[SecurityEvent],
                         grouped_events: List[Dict[str, Any]],
                         suspicious_ips: List[Dict[str, Any]],
                         url_patterns: Dict[str, Dict[str, Any]],
                         time_patterns: Dict[str, Any]) -> str:
        """Generate a summary of the security analysis
        
        Args:
            events: List of SecurityEvent objects
            grouped_events: List of event groups
            suspicious_ips: List of suspicious IP details
            url_patterns: URL pattern analysis
            time_patterns: Time pattern analysis
            
        Returns:
            Summary string
        """
        if not events:
            return "No security events detected in the analyzed logs."
        
        # Count events by severity
        severity_counts = {}
        for event in events:
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
        
        # Generate summary
        summary_parts = []
        
        # Basic event count
        event_count_text = f"Detected {len(events)} security-related events"
        if severity_counts:
            severity_text = []
            if SeverityLevel.CRITICAL in severity_counts:
                severity_text.append(f"{severity_counts[SeverityLevel.CRITICAL]} critical")
            if SeverityLevel.HIGH in severity_counts:
                severity_text.append(f"{severity_counts[SeverityLevel.HIGH]} high")
            if SeverityLevel.MEDIUM in severity_counts:
                severity_text.append(f"{severity_counts[SeverityLevel.MEDIUM]} medium")
            if SeverityLevel.LOW in severity_counts:
                severity_text.append(f"{severity_counts[SeverityLevel.LOW]} low")
            if SeverityLevel.INFO in severity_counts:
                severity_text.append(f"{severity_counts[SeverityLevel.INFO]} info")
            
            event_count_text += f" ({', '.join(severity_text)})"
        
        summary_parts.append(event_count_text + ".")
        
        # Group information
        if grouped_events:
            num_ip_groups = sum(1 for g in grouped_events if g["type"] == "IP-based")
            num_attack_groups = sum(1 for g in grouped_events if g["type"] == "Attack-based")
            
            if num_ip_groups > 0:
                summary_parts.append(f"Identified {num_ip_groups} IP address(es) with multiple security events.")
            
            if num_attack_groups > 0:
                summary_parts.append(f"Detected {num_attack_groups} attack pattern(s) across multiple events.")
        
        # Suspicious IPs
        if suspicious_ips:
            summary_parts.append(f"Found {len(suspicious_ips)} suspicious IP address(es) with high request volume.")
        
        # URL patterns
        abnormal_urls = [url for url, data in url_patterns.items() if len(data["ips"]) > 3]
        if abnormal_urls:
            summary_parts.append(f"Identified {len(abnormal_urls)} URL(s) accessed from multiple IP addresses.")
        
        # Most common attack type
        attack_types = [event.attack_type for event in events if event.attack_type != AttackType.UNKNOWN]
        if attack_types:
            from collections import Counter
            most_common_attack = Counter(attack_types).most_common(1)[0][0]
            summary_parts.append(f"Most common attack type: {most_common_attack.value}.")
        
        return " ".join(summary_parts)