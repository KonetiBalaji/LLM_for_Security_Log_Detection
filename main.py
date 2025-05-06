import argparse
import pandas as pd
import os
import json
from typing import List, Dict, Any
from datetime import datetime
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import project modules
from src.classify import LogClassifier
from src.security_analyzer import SecurityAnalyzer
from src.data_preprocessing import detect_log_type, preprocess_logs, extract_features, detect_anomalies
from src.utils import load_logs_from_file, save_results_to_file, print_analysis_results

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='log_detection.log'
)
logger = logging.getLogger(__name__)

# Initialize console for rich output
console = Console()

def process_file(file_path: str, output_dir: str = "output", print_results: bool = True) -> Dict[str, Any]:
    """Process a log file
    
    Args:
        file_path: Path to log file
        output_dir: Directory to save output
        print_results: Whether to print results
        
    Returns:
        Analysis results dictionary
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Get file name without extension
    file_name = os.path.basename(file_path).split('.')[0]
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        console=console
    ) as progress:
        # Load logs
        task = progress.add_task("[cyan]Loading logs...", total=None)
        logs = load_logs_from_file(file_path)
        if not logs:
            console.print(f"[bold red]Error: No logs found in {file_path}[/]")
            return {}
        
        # Detect log type
        task = progress.add_task("[cyan]Detecting log type...", total=None)
        log_type = None
        for line in logs:
            if line.strip():
                log_type = detect_log_type(line.strip())
                break
        
        if not log_type:
            log_type = "generic"
        
        console.print(f"[green]Detected log type: [bold]{log_type}[/][/]")
        
        # Preprocess logs
        task = progress.add_task("[cyan]Preprocessing logs...", total=None)
        df = preprocess_logs(logs, log_type)
        
        # Extract features
        task = progress.add_task("[cyan]Extracting features...", total=None)
        df = extract_features(df, log_type)
        
        # Detect anomalies
        task = progress.add_task("[cyan]Detecting anomalies...", total=None)
        df = detect_anomalies(df, log_type)
        
        # Add source column if not present
        if 'source' not in df.columns:
            df['source'] = file_name
        
        # Add log_message column if not present
        if 'log_message' not in df.columns:
            df['log_message'] = df['raw'] if 'raw' in df.columns else logs
        
        # Save preprocessed logs
        task = progress.add_task("[cyan]Saving preprocessed logs...", total=None)
        preprocessed_path = os.path.join(output_dir, f"{file_name}_preprocessed.csv")
        df.to_csv(preprocessed_path, index=False)
        
        # Initialize classifier
        task = progress.add_task("[cyan]Initializing classifier...", total=None)
        classifier = LogClassifier()
        
        # Classify logs
        task = progress.add_task("[cyan]Classifying logs...", total=None)
        classified_logs = classifier.classify(
            list(zip(df['source'], df['log_message']))
        )
        
        # Save classified logs
        task = progress.add_task("[cyan]Saving classified logs...", total=None)
        classified_df = pd.DataFrame(classified_logs)
        classified_path = os.path.join(output_dir, f"{file_name}_classified.csv")
        classified_df.to_csv(classified_path, index=False)
        
        # Initialize security analyzer
        task = progress.add_task("[cyan]Initializing security analyzer...", total=None)
        analyzer = SecurityAnalyzer()
        
        # Analyze logs
        task = progress.add_task("[cyan]Analyzing logs for security events...", total=None)
        analysis_results = analyzer.analyze(classified_logs)
        
        # Save analysis results
        task = progress.add_task("[cyan]Saving analysis results...", total=None)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_path = os.path.join(output_dir, f"{file_name}_analysis_{timestamp}.json")
        save_results_to_file(analysis_results, results_path)
    
    # Print results if requested
    if print_results:
        print_analysis_results(analysis_results)
    
    return analysis_results


def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description="LLM-based Security Log Analysis",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--input", "-i", 
        type=str, 
        required=True, 
        help="Input log file path or directory"
    )
    parser.add_argument(
        "--output", "-o", 
        type=str, 
        default="output", 
        help="Output directory"
    )
    parser.add_argument(
        "--format", "-f", 
        action="store_true", 
        help="Format and print analysis results"
    )
    parser.add_argument(
        "--recursive", "-r", 
        action="store_true", 
        help="Process directories recursively"
    )
    args = parser.parse_args()
    
    # Process input path
    input_path = args.input
    output_dir = args.output
    
    if os.path.isfile(input_path):
        # Process single file
        console.print(f"[bold cyan]Processing file: {input_path}[/]")
        process_file(input_path, output_dir, args.format)
    
    elif os.path.isdir(input_path):
        # Process directory
        console.print(f"[bold cyan]Processing directory: {input_path}[/]")
        
        if args.recursive:
            # Walk directory recursively
            for root, _, files in os.walk(input_path):
                for file in files:
                    if file.endswith(('.log', '.txt', '.csv')):
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, input_path)
                        file_output_dir = os.path.join(output_dir, os.path.dirname(rel_path))
                        
                        console.print(f"[bold cyan]Processing file: {rel_path}[/]")
                        process_file(file_path, file_output_dir, args.format)
        else:
            # Process files in directory (non-recursive)
            for file in os.listdir(input_path):
                file_path = os.path.join(input_path, file)
                if os.path.isfile(file_path) and file.endswith(('.log', '.txt', '.csv')):
                    console.print(f"[bold cyan]Processing file: {file}[/]")
                    process_file(file_path, output_dir, args.format)
    
    else:
        console.print(f"[bold red]Error: Input path '{input_path}' not found.[/]")
        return
    
    console.print("[bold green]Processing complete![/]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("[bold red]Processing interrupted by user.[/]")
    except Exception as e:
        logger.exception(f"Error: {str(e)}")
        console.print(f"[bold red]Error: {str(e)}[/]")
        console.print("[yellow]Check log_detection.log for details.[/]")