import re
import pandas as pd
from typing import List, Dict, Any, Union, Tuple, Optional

class LogParser:
    """Parser for different log formats"""
    
    def __init__(self, log_type: str = "web_server"):
        """Initialize parser with log type
        
        Args:
            log_type: Type of log (web_server, system, security, etc.)
        """
        self.log_type = log_type
        self._setup_parsers()
    
    def _setup_parsers(self):
        """Set up regex patterns for parsing based on log type"""
        if self.log_type == "web_server":
            # Common web server (Apache/Nginx) log format
            self.pattern = r'([\d\.]+) - .* \[(.*?)\] "(.*?)" (\d+) (\d+)'
        elif self.log_type == "system":
            # Common system log format (e.g., Linux syslog)
            self.pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+) (\w+) (.*?): (.*)'
        elif self.log_type == "security":
            # Security log format (e.g., auth.log)
            self.pattern = r'(.*?)\s+(\w+)\s+(\w+)\s+(.*)'
        elif self.log_type == "openstack":
            # OpenStack log format
            self.pattern = r'(.*?) (\d+) (INFO|WARNING|ERROR|CRITICAL) (.*?): (.*)'
        else:
            # Generic fallback pattern
            self.pattern = r'(.*)'
        
        self.compiled_pattern = re.compile(self.pattern)
    
    def parse(self, log_line: str) -> Dict[str, Any]:
        """Parse a log line into structured format
        
        Args:
            log_line: Raw log line
            
        Returns:
            Dictionary with parsed log fields
        """
        if self.log_type == "web_server":
            return self._parse_web_server_log(log_line)
        elif self.log_type == "system":
            return self._parse_system_log(log_line)
        elif self.log_type == "security":
            return self._parse_security_log(log_line)
        elif self.log_type == "openstack":
            return self._parse_openstack_log(log_line)
        else:
            return {"raw": log_line}
    
    def _parse_web_server_log(self, log_line: str) -> Dict[str, Any]:
        """Parse web server log line
        
        Args:
            log_line: Raw log line
            
        Returns:
            Dictionary with parsed fields
        """
        match = self.compiled_pattern.match(log_line)
        if not match:
            return {"raw": log_line}
        
        # Extract HTTP method, URL, and protocol from request
        request_parts = match.group(3).split()
        http_method = request_parts[0] if len(request_parts) > 0 else ""
        url = request_parts[1] if len(request_parts) > 1 else ""
        protocol = request_parts[2] if len(request_parts) > 2 else ""
        
        return {
            "ip_address": match.group(1),
            "timestamp": match.group(2),
            "request": match.group(3),
            "http_method": http_method,
            "url": url,
            "protocol": protocol,
            "status_code": match.group(4),
            "bytes_sent": match.group(5),
            "raw": log_line
        }
    
    def _parse_system_log(self, log_line: str) -> Dict[str, Any]:
        """Parse system log line
        
        Args:
            log_line: Raw log line
            
        Returns:
            Dictionary with parsed fields
        """
        match = self.compiled_pattern.match(log_line)
        if not match:
            return {"raw": log_line}
        
        return {
            "timestamp": match.group(1),
            "hostname": match.group(2),
            "process": match.group(3),
            "message": match.group(4),
            "raw": log_line
        }
    
    def _parse_security_log(self, log_line: str) -> Dict[str, Any]:
        """Parse security log line
        
        Args:
            log_line: Raw log line
            
        Returns:
            Dictionary with parsed fields
        """
        match = self.compiled_pattern.match(log_line)
        if not match:
            return {"raw": log_line}
        
        return {
            "timestamp": match.group(1),
            "hostname": match.group(2),
            "service": match.group(3),
            "message": match.group(4),
            "raw": log_line
        }
    
    def _parse_openstack_log(self, log_line: str) -> Dict[str, Any]:
        """Parse OpenStack log line
        
        Args:
            log_line: Raw log line
            
        Returns:
            Dictionary with parsed fields
        """
        match = self.compiled_pattern.match(log_line)
        if not match:
            return {"raw": log_line}
        
        return {
            "timestamp": match.group(1),
            "process_id": match.group(2),
            "level": match.group(3),
            "component": match.group(4),
            "message": match.group(5),
            "raw": log_line
        }


def preprocess_logs(logs: List[str], log_type: str = "web_server") -> pd.DataFrame:
    """Preprocess logs into a structured DataFrame
    
    Args:
        logs: List of raw log lines
        log_type: Type of log
        
    Returns:
        DataFrame with structured log data
    """
    parser = LogParser(log_type)
    parsed_logs = [parser.parse(log) for log in logs if log.strip()]
    return pd.DataFrame(parsed_logs)


def detect_log_type(log_sample: str) -> str:
    """Attempt to detect log type from a sample
    
    Args:
        log_sample: Sample log line
        
    Returns:
        Detected log type
    """
    # Web server log patterns
    web_server_pattern = r'([\d\.]+) - .* \[(.*?)\] "(GET|POST|PUT|DELETE|HEAD|OPTIONS) .* HTTP/\d\.\d" \d+ \d+'
    if re.search(web_server_pattern, log_sample):
        return "web_server"
    
    # System log patterns
    system_pattern = r'\w{3}\s+\d+\s+\d+:\d+:\d+\s+\w+\s+\w+(\[\d+\])?:'
    if re.search(system_pattern, log_sample):
        return "system"
    
    # Security log patterns (auth.log)
    security_pattern = r'\w{3}\s+\d+\s+\d+:\d+:\d+\s+\w+\s+(sshd|sudo|auth):'
    if re.search(security_pattern, log_sample):
        return "security"
    
    # OpenStack log patterns
    openstack_pattern = r'.*? \d+ (INFO|WARNING|ERROR|CRITICAL) [\w\.]+:'
    if re.search(openstack_pattern, log_sample):
        return "openstack"
    
    # Default fallback
    return "generic"


def normalize_timestamp(timestamp: str, log_type: str) -> Optional[str]:
    """Normalize timestamp to ISO format
    
    Args:
        timestamp: Raw timestamp string
        log_type: Type of log
        
    Returns:
        Normalized timestamp string or None if parsing fails
    """
    # Different formats based on log type
    if log_type == "web_server":
        # Example: 21/Apr/2019:03:39:58 +0330
        try:
            import datetime
            from dateutil import parser
            return parser.parse(timestamp).isoformat()
        except:
            return None
    elif log_type in ["system", "security"]:
        # Example: Jun 14 15:16:01
        try:
            import datetime
            current_year = datetime.datetime.now().year
            timestamp_with_year = f"{timestamp} {current_year}"
            from dateutil import parser
            return parser.parse(timestamp_with_year).isoformat()
        except:
            return None
    else:
        return timestamp


def extract_features(logs_df: pd.DataFrame, log_type: str) -> pd.DataFrame:
    """Extract additional features from parsed logs
    
    Args:
        logs_df: DataFrame with parsed logs
        log_type: Type of log
        
    Returns:
        DataFrame with additional features
    """
    # Create a copy to avoid modifying original
    df = logs_df.copy()
    
    if log_type == "web_server":
        # Extract HTTP method, URL, status code categories
        if 'status_code' in df.columns:
            df['status_category'] = df['status_code'].astype(str).str[0] + "xx"
        
        # Extract URL path and query parameters
        if 'url' in df.columns:
            df['url_path'] = df['url'].str.split('?').str[0]
            
            # Extract query parameters
            def extract_query_params(url):
                if '?' not in str(url):
                    return {}
                params = {}
                query_string = url.split('?', 1)[1]
                for param in query_string.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = value
                return params
            
            df['query_params'] = df['url'].apply(extract_query_params)
    
    elif log_type in ["system", "security"]:
        # Extract process ID from process field
        if 'process' in df.columns:
            pid_pattern = r'\[(\d+)\]'
            df['process_id'] = df['process'].str.extract(pid_pattern)
            df['process_name'] = df['process'].str.split('[').str[0]
        
        # Identify authentication failures
        if 'message' in df.columns:
            df['is_auth_failure'] = df['message'].str.contains('authentication failure|failed login', case=False, regex=True)
            df['is_sudo'] = df['message'].str.contains('sudo|su:', case=False, regex=True)
    
    elif log_type == "openstack":
        # Extract request ID if present
        if 'message' in df.columns:
            req_pattern = r'req-([a-f0-9\-]+)'
            df['request_id'] = df['message'].str.extract(req_pattern)
            
            # Extract status codes
            status_pattern = r'status: (\d+)'
            df['status_code'] = df['message'].str.extract(status_pattern)
    
    # Add timestamp normalization for all log types
    if 'timestamp' in df.columns:
        df['normalized_timestamp'] = df['timestamp'].apply(
            lambda x: normalize_timestamp(x, log_type)
        )
    
    return df


def detect_anomalies(logs_df: pd.DataFrame, log_type: str) -> pd.DataFrame:
    """Detect potential anomalies in logs
    
    Args:
        logs_df: DataFrame with parsed logs
        log_type: Type of log
        
    Returns:
        DataFrame with anomaly flags
    """
    # Create a copy to avoid modifying original
    df = logs_df.copy()
    
    # Add anomaly flags column
    df['is_anomaly'] = False
    df['anomaly_reason'] = ''
    
    if log_type == "web_server":
        # Flag 4xx and 5xx status codes
        if 'status_code' in df.columns:
            error_mask = df['status_code'].astype(str).str[0].isin(['4', '5'])
            df.loc[error_mask, 'is_anomaly'] = True
            df.loc[error_mask, 'anomaly_reason'] = 'Error status code'
        
        # Flag unusual HTTP methods
        if 'http_method' in df.columns:
            unusual_methods = ~df['http_method'].isin(['GET', 'POST', 'HEAD'])
            df.loc[unusual_methods, 'is_anomaly'] = True
            df.loc[unusual_methods, 'anomaly_reason'] = 'Unusual HTTP method'
        
        # Flag potential SQL injection or XSS attempts
        if 'url' in df.columns:
            sqli_pattern = r'(\%27|\'|\-\-|\/\*|\%23|#)'
            xss_pattern = r'(\<script|\%3Cscript|\%3C\%2Fscript|\%22\%3E)'
            path_traversal_pattern = r'(\.\.\/|\.\.\\|\%2e\%2e\%2f)'
            
            sqli_mask = df['url'].str.contains(sqli_pattern, case=False, regex=True, na=False)
            xss_mask = df['url'].str.contains(xss_pattern, case=False, regex=True, na=False)
            pt_mask = df['url'].str.contains(path_traversal_pattern, case=False, regex=True, na=False)
            
            df.loc[sqli_mask, 'is_anomaly'] = True
            df.loc[sqli_mask, 'anomaly_reason'] = 'Potential SQL injection'
            
            df.loc[xss_mask, 'is_anomaly'] = True
            df.loc[xss_mask, 'anomaly_reason'] = 'Potential XSS attack'
            
            df.loc[pt_mask, 'is_anomaly'] = True
            df.loc[pt_mask, 'anomaly_reason'] = 'Potential path traversal'
    
    elif log_type in ["system", "security"]:
        # Flag authentication failures
        if 'message' in df.columns:
            auth_fail_mask = df['message'].str.contains('authentication failure|failed login|invalid user', case=False, regex=True, na=False)
            sudo_fail_mask = df['message'].str.contains('sudo.*incorrect password', case=False, regex=True, na=False)
            
            df.loc[auth_fail_mask, 'is_anomaly'] = True
            df.loc[auth_fail_mask, 'anomaly_reason'] = 'Authentication failure'
            
            df.loc[sudo_fail_mask, 'is_anomaly'] = True
            df.loc[sudo_fail_mask, 'anomaly_reason'] = 'Sudo authentication failure'
    
    elif log_type == "openstack":
        # Flag errors and warnings
        if 'level' in df.columns:
            error_mask = df['level'].isin(['ERROR', 'CRITICAL'])
            warning_mask = df['level'] == 'WARNING'
            
            df.loc[error_mask, 'is_anomaly'] = True
            df.loc[error_mask, 'anomaly_reason'] = 'Error or critical log'
            
            df.loc[warning_mask, 'is_anomaly'] = True
            df.loc[warning_mask, 'anomaly_reason'] = 'Warning log'
    
    return df


if __name__ == "__main__":
    # Example usage
    sample_logs = [
        '192.168.1.100 - - [21/Apr/2019:03:39:58 +0330] "GET /index.html HTTP/1.1" 200 1234',
        '192.168.1.101 - - [21/Apr/2019:03:40:00 +0330] "POST /login.php HTTP/1.1" 302 0',
        '192.168.1.102 - - [21/Apr/2019:03:40:01 +0330] "GET /admin.php?id=1%27%20OR%201=1-- HTTP/1.1" 200 5678',
        'Jun 14 15:16:01 server sshd[1234]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=192.168.1.200',
        'nova.osapi_compute.wsgi.server 1234 INFO req-abc123 1234 1234 - - - 192.168.1.100 "GET /v2/servers/detail HTTP/1.1" status: 200 len: 1234 time: 0.1234'
    ]
    
    # Auto-detect log type for each log
    for log in sample_logs:
        log_type = detect_log_type(log)
        parser = LogParser(log_type)
        parsed = parser.parse(log)
        print(f"Log type: {log_type}")
        print(f"Parsed: {parsed}")
        print("-" * 50)
    
    # Process a batch of web server logs
    web_logs = [log for log in sample_logs if detect_log_type(log) == "web_server"]
    if web_logs:
        df = preprocess_logs(web_logs, "web_server")
        df = extract_features(df, "web_server")
        df = detect_anomalies(df, "web_server")
        print(df)