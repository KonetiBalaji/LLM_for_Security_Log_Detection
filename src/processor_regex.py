import re
from typing import Optional, Dict, List, Pattern

class RegexProcessor:
    """Process logs using regex patterns for fast, rule-based classification"""
    
    def __init__(self):
        """Initialize regex patterns for different security events"""
        self.regex_patterns = {
            r"User User\d+ logged (in|out).": "User Action",
            r"Backup (started|ended) at .*": "System Notification",
            r"Backup completed successfully.": "System Notification",
            r"System updated to version .*": "System Notification",
            r"File .* uploaded successfully by user .*": "System Notification",
            r"Disk cleanup completed successfully.": "System Notification",
            r"System reboot initiated by user .*": "System Notification",
            r"Account with ID .* created by .*": "User Action",
            r".*authentication fail.*|.*login fail.*|.*failed login.*": "Security Alert",
            r".*unauthorized.*|.*suspicious.*|.*unusual activity.*": "Security Alert",
            r".*brute force.*|.*multiple failed.*|.*repeated attempt.*": "Security Alert",
            r".*admin.*escalat.*|.*privilege.*escalat.*": "Security Alert",
            r".*GET.*HTTP.*": "HTTP Status",
            r".*POST.*HTTP.*": "HTTP Status",
            r".*PUT.*HTTP.*": "HTTP Status",
            r".*DELETE.*HTTP.*": "HTTP Status",
            r".*memory.*usage.*|.*disk.*usage.*|.*CPU.*usage.*": "Resource Usage",
            r".*error.*|.*exception.*|.*fail.*": "Error",
            r".*deprecated.*|.*will be removed.*|.*is outdated.*": "Deprecation Warning",
            r".*workflow.*failed.*|.*process.*failed.*|.*task.*failed.*": "Workflow Error"
        }
    
    def classify_with_regex(self, log_message: str) -> Optional[str]:
        """Classify log message using regex patterns
        
        Args:
            log_message: Log message to classify
            
        Returns:
            Classification label or None if no match
        """
        for pattern, label in self.regex_patterns.items():
            if re.search(pattern, log_message, re.IGNORECASE):
                return label
        return None
    
    def extract_entities(self, log_message: str) -> Dict[str, str]:
        """Extract relevant entities from log message
        
        Args:
            log_message: Log message to extract from
            
        Returns:
            Dictionary of extracted entities
        """
        entities = {}
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.findall(ip_pattern, log_message)
        if ip_matches:
            entities['ip_addresses'] = ip_matches
        
        # Extract HTTP methods
        http_method_pattern = r'\b(GET|POST|PUT|DELETE|OPTIONS|HEAD|TRACE|CONNECT)\b'
        http_method_match = re.search(http_method_pattern, log_message)
        if http_method_match:
            entities['http_method'] = http_method_match.group(0)
        
        # Extract HTTP status codes
        status_code_pattern = r'status: (\d{3})|HTTP (\d{3})|code (\d{3})'
        status_code_match = re.search(status_code_pattern, log_message)
        if status_code_match:
            for group in status_code_match.groups():
                if group:
                    entities['status_code'] = group
                    break
        
        # Extract usernames
        username_pattern = r'user (\w+)|User(\d+)'
        username_match = re.search(username_pattern, log_message)
        if username_match:
            username = username_match.group(1) or username_match.group(2)
            if username:
                entities['username'] = username
        
        return entities


def classify_with_regex(log_message):
    """Legacy function for backward compatibility"""
    processor = RegexProcessor()
    return processor.classify_with_regex(log_message)


if __name__ == "__main__":
    # Test the processor with some examples
    processor = RegexProcessor()
    test_logs = [
        "Backup completed successfully.",
        "Account with ID 1234 created by User1.",
        "Multiple failed login attempts for user admin from 192.168.1.100",
        "GET /api/users HTTP/1.1 200 OK",
        "System memory usage at 95%, consider cleanup",
        "Hey Bro, chill ya!"
    ]
    
    for log in test_logs:
        label = processor.classify_with_regex(log)
        entities = processor.extract_entities(log)
        print(f"Log: {log}")
        print(f"Classification: {label}")
        print(f"Entities: {entities}")
        print("-" * 50)