import json
import pandas as pd
import re
import os
from typing import List, Dict, Any, Optional, Tuple
import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Initialize rich console for pretty printing
console = Console()

def load_logs_from_file(file_path: str) -> List[str]:
    """Load logs from a file
    
    Args:
        file_path: Path to log file
        
    Returns:
        List of log lines
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            return file.readlines()
    except Exception as e:
        console.print(f"[bold red]Error loading log file: {e}[/]")
        return []


def save_results_to_file(results: Dict[str, Any], output_path: str) -> bool:
    """Save analysis results to JSON file
    
    Args:
        results: Results dictionary
        output_path: Path to save results
        
    Returns:
        Boolean indicating success
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Convert non-serializable objects
        serializable_results = convert_to_serializable(results)
        
        with open(output_path, 'w', encoding='utf-8') as file:
            json.dump(serializable_results, file, indent=2)
        
        console.print(f"[bold green]Results saved to: {output_path}[/]")
        return True
    except Exception as e:
        console.print(f"[bold red]Error saving results: {e}[/]")
        return False


def convert_to_serializable(obj: Any) -> Any:
    """Convert non-serializable objects to serializable ones
    
    Args:
        obj: Object to convert
        
    Returns:
        Serializable object
    """
    if isinstance(obj, dict):
        return {k: convert_to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_serializable(item) for item in obj]
    elif isinstance(obj, tuple):
        return [convert_to_serializable(item) for item in obj]
    elif isinstance(obj, (pd.DataFrame, pd.Series)):
        return obj.to_dict()
    elif isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    elif isinstance(obj, set):
        return list(obj)
    elif hasattr(obj, '__dict__'):
        return convert_to_serializable(obj.__dict__)
    else:
        return obj


def print_analysis_results(analysis_results: Dict[str, Any]) -> None:
    """Print analysis results in formatted tables
    
    Args:
        analysis_results: Analysis results dictionary
    """
    # Print header
    console.print(Panel.fit(
        f"[bold yellow]Security Log Analysis Report[/]\n"
        f"[blue]{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]",
        border_style="yellow"
    ))
    
    # Print summary
    if "summary" in analysis_results:
        console.print(Panel(
            f"[bold white]Summary:[/]\n[cyan]{analysis_results['summary']}[/]\n\n"
            f"[bold {'red' if analysis_results.get('requires_immediate_attention', False) else 'green'}]"
            f"Requires Immediate Attention: {analysis_results.get('requires_immediate_attention', False)}[/]",
            border_style="blue"
        ))
    
    # Print security events
    if "events" in analysis_results and analysis_results["events"]:
        events_table = Table(show_header=True, header_style="bold red", show_lines=True)
        events_table.add_column("Event Type", style="red", width=20)
        events_table.add_column("Severity", style="yellow", width=10)
        events_table.add_column("Source IPs", style="cyan", width=15)
        events_table.add_column("Details", style="green")
        events_table.add_column("Recommendation", style="magenta", width=30)
        
        for event in analysis_results["events"]:
            ips = ", ".join(event.get("source_ips", [])) if event.get("source_ips") else "N/A"
            
            details = []
            if event.get("attack_type") != "UNKNOWN":
                details.append(f"Attack: {event.get('attack_type', 'Unknown')}")
            if event.get("http_method"):
                details.append(f"Method: {event.get('http_method')}")
            if event.get("url_pattern"):
                details.append(f"URL: {event.get('url_pattern')}")
            if event.get("status_code"):
                details.append(f"Status: {event.get('status_code')}")
            if event.get("username"):
                details.append(f"User: {event.get('username')}")
            
            details_str = "\n".join(details) or "No additional details"
            
            events_table.add_row(
                event.get("event_type", "Unknown"),
                event.get("severity", "UNKNOWN"),
                ips,
                details_str,
                event.get("recommendation", "N/A")
            )
        
        console.print("\n[bold red]⚠️  Security Events:[/]")
        console.print(events_table)
    
    # Print IP analysis
    if "ip_analysis" in analysis_results and analysis_results["ip_analysis"].get("suspicious"):
        ip_table = Table(show_header=True, header_style="bold magenta", show_lines=True)
        ip_table.add_column("Suspicious IP", style="cyan")
        ip_table.add_column("Request Count", style="yellow")
        ip_table.add_column("Suspicion Level", style="red")
        
        for ip in analysis_results["ip_analysis"]["suspicious"]:
            ip_table.add_row(
                ip.get("ip", "Unknown"),
                str(ip.get("request_count", 0)),
                ip.get("suspicion_level", "Low")
            )
        
        console.print("\n[bold magenta]🔍 Suspicious IP Addresses:[/]")
        console.print(ip_table)
    
    # Print recommendations
    if "recommendations" in analysis_results and analysis_results["recommendations"]:
        rec_table = Table(show_header=True, header_style="bold green", show_lines=True)
        rec_table.add_column("Recommendations", style="green")
        
        for rec in analysis_results["recommendations"]:
            rec_table.add_row(rec)
        
        console.print("\n[bold green]✅ Recommended Actions:[/]")
        console.print(rec_table)


def extract_log_format(log_sample: str) -> Optional[str]:
    """Extract log format string from a sample log
    
    Args:
        log_sample: Sample log line
        
    Returns:
        Log format string or None if format cannot be determined
    """
    # Web server log (Apache/Nginx)
    apache_pattern = r'^(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(.+?)" (\d+) (\d+)'
    if re.match(apache_pattern, log_sample):
        return '%h %l %u %t \"%r\" %>s %b'
    
    # System log
    syslog_pattern = r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s+(.+)'
    if re.match(syslog_pattern, log_sample):
        return '%date %hostname %program: %message'
    
    # OpenStack log
    openstack_pattern = r'^(\S+) (\d+) (\w+) ([^:]+): (.+)'
    if re.match(openstack_pattern, log_sample):
        return '%component %pid %level %name: %message'
    
    # Unknown format
    return None


def calculate_time_window(logs_df: pd.DataFrame, timestamp_col: str = 'timestamp') -> Tuple[Optional[str], Optional[str]]:
    """Calculate the time window covered by the logs
    
    Args:
        logs_df: DataFrame with parsed logs
        timestamp_col: Column name for timestamp
        
    Returns:
        Tuple of (start_time, end_time) as strings or (None, None) if timestamps cannot be parsed
    """
    if timestamp_col not in logs_df.columns:
        return None, None
    
    try:
        # Try to convert to datetime
        logs_df['_datetime'] = pd.to_datetime(logs_df[timestamp_col])
        start_time = logs_df['_datetime'].min()
        end_time = logs_df['_datetime'].max()
        
        # Remove temporary column
        logs_df.drop('_datetime', axis=1, inplace=True)
        
        return start_time.isoformat(), end_time.isoformat()
    except:
        return None, None


def load_and_preprocess_logs(file_path: str) -> Tuple[pd.DataFrame, str]:
    """Load and preprocess logs from a file
    
    Args:
        file_path: Path to log file
        
    Returns:
        Tuple of (preprocessed_df, log_type)
    """
    from src.data_preprocessing import detect_log_type, preprocess_logs, extract_features
    
    # Load logs
    logs = load_logs_from_file(file_path)
    if not logs:
        return pd.DataFrame(), "unknown"
    
    # Detect log type from first non-empty line
    for line in logs:
        if line.strip():
            log_type = detect_log_type(line.strip())
            break
    else:
        log_type = "generic"
    
    # Preprocess logs
    df = preprocess_logs(logs, log_type)
    df = extract_features(df, log_type)
    
    return df, log_type