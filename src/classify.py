from src.processor_regex import classify_with_regex
from src.processor_bert import classify_with_bert
from src.processor_llm import classify_with_llm
import pandas as pd
from typing import List, Tuple, Dict, Any, Optional

def classify(logs):
    """Classify a list of log entries using the hybrid approach
    
    Args:
        logs: List of (source, log_message) tuples
        
    Returns:
        List of labels
    """
    labels = []
    for source, log_msg in logs:
        label = classify_log(source, log_msg)
        labels.append(label)
    return labels


def classify_log(source, log_msg):
    """Classify a single log entry using the hybrid approach
    
    Args:
        source: Source of the log (system name)
        log_msg: Log message
        
    Returns:
        Classification label
    """
    # Try regex first (fastest, simplest patterns)
    if source == "LegacyCRM":
        # For LegacyCRM, use LLM directly (as per original code)
        label = classify_with_llm(log_msg)
    else:
        # For other sources, try regex, then BERT if needed
        label = classify_with_regex(log_msg)
        if not label:
            label = classify_with_bert(log_msg)
    
    return label


def classify_csv(input_file, output_file="output.csv"):
    """Classify logs from a CSV file
    
    Args:
        input_file: Path to input CSV
        output_file: Path to output CSV (default: output.csv)
        
    Returns:
        Path to output file
    """
    # Read CSV file
    df = pd.read_csv(input_file)

    # Ensure required columns exist
    if "source" not in df.columns or "log_message" not in df.columns:
        raise ValueError("CSV must contain 'source' and 'log_message' columns.")

    # Perform classification
    df["target_label"] = classify(list(zip(df["source"], df["log_message"])))

    # Save the modified file
    df.to_csv(output_file, index=False)

    return output_file


class LogClassifier:
    """Enhanced log classification system using hybrid approach with analysis"""
    
    def __init__(self):
        """Initialize classifier components"""
        from src.processor_regex import RegexProcessor
        from src.processor_bert import BertProcessor
        from src.processor_llm import LLMProcessor
        
        self.regex_processor = RegexProcessor()
        self.bert_processor = BertProcessor()
        self.llm_processor = LLMProcessor()
    
    def classify(self, logs: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        """Classify logs using the hybrid approach with detailed results
        
        Args:
            logs: List of (source, log_message) tuples
            
        Returns:
            List of detailed classification results
        """
        results = []
        
        for source, log_message in logs:
            result = self.classify_log(source, log_message)
            results.append(result)
            
        return results
    
    def classify_log(self, source: str, log_message: str) -> Dict[str, Any]:
        """Classify a single log entry with detailed result
        
        Args:
            source: Source of the log (system name)
            log_message: Log message to classify
            
        Returns:
            Classification result dictionary
        """
        # Extract entities using regex
        entities = self.regex_processor.extract_entities(log_message)
        
        # Try regex first (fastest, simplest patterns)
        regex_result = self.regex_processor.classify_with_regex(log_message)
        
        if regex_result:
            return {
                "source": source,
                "log_message": log_message,
                "classification": regex_result,
                "method": "regex",
                "confidence": 1.0,  # Regex pattern matches are certain
                "entities": entities,
                "reasoning": "Matched rule-based pattern."
            }
        
        # If not Legacy CRM, try BERT
        if source != "LegacyCRM":
            bert_label, bert_confidence = self.bert_processor.classify_with_bert(log_message)
            
            if bert_label != "Unclassified" and bert_confidence >= 0.5:
                return {
                    "source": source,
                    "log_message": log_message,
                    "classification": bert_label,
                    "method": "bert",
                    "confidence": bert_confidence,
                    "entities": entities,
                    "reasoning": f"Classified with BERT embeddings (confidence: {bert_confidence:.2f})."
                }
        
        # Fall back to LLM for complex patterns
        llm_result = self.llm_processor.classify_with_llm(log_message)
        
        return {
            "source": source,
            "log_message": log_message,
            "classification": llm_result["category"],
            "method": "llm",
            "confidence": 0.8,  # Arbitrary confidence for LLM
            "entities": entities,
            "reasoning": llm_result["reasoning"]
        }
    
    def classify_csv(self, input_file: str, output_file: str = "output.csv") -> str:
        """Classify logs from a CSV file with enhanced output
        
        Args:
            input_file: Path to input CSV
            output_file: Path to output CSV
            
        Returns:
            Path to output file
        """
        df = pd.read_csv(input_file)
        
        # Ensure required columns exist
        if "source" not in df.columns or "log_message" not in df.columns:
            raise ValueError("CSV must contain 'source' and 'log_message' columns.")
        
        # Perform classification
        classification_results = self.classify(list(zip(df["source"], df["log_message"])))
        
        # Add classification results to DataFrame
        df["target_label"] = [result["classification"] for result in classification_results]
        df["method"] = [result["method"] for result in classification_results]
        df["confidence"] = [result["confidence"] for result in classification_results]
        df["reasoning"] = [result["reasoning"] for result in classification_results]
        
        # Save to output file
        df.to_csv(output_file, index=False)
        
        return output_file


if __name__ == '__main__':
    # Example usage when run directly
    classifier = LogClassifier()
    
    logs = [
        ("ModernCRM", "IP 192.168.133.114 blocked due to potential attack"),
        ("BillingSystem", "User 12345 logged in."),
        ("AnalyticsEngine", "File data_6957.csv uploaded successfully by user User265."),
        ("AnalyticsEngine", "Backup completed successfully."),
        ("ModernHR", "GET /v2/54fadb412c4e40cdbaed9335e4c35a9e/servers/detail HTTP/1.1 RCODE  200 len: 1583 time: 0.1878400"),
        ("ModernHR", "Admin access escalation detected for user 9429"),
        ("LegacyCRM", "Case escalation for ticket ID 7324 failed because the assigned support agent is no longer active."),
        ("LegacyCRM", "Invoice generation process aborted for order ID 8910 due to invalid tax calculation module."),
        ("LegacyCRM", "The 'BulkEmailSender' feature is no longer supported. Use 'EmailCampaignManager' for improved functionality."),
        ("LegacyCRM", "The 'ReportGenerator' module will be retired in version 4.0. Please migrate to the 'AdvancedAnalyticsSuite' by Dec 2025")
    ]
    
    results = classifier.classify(logs)
    
    for log, result in zip(logs, results):
        print(f"Source: {log[0]}")
        print(f"Log: {log[1]}")
        print(f"Classification: {result['classification']} (Method: {result['method']}, Confidence: {result['confidence']:.2f})")
        print(f"Reasoning: {result['reasoning']}")
        print("-" * 50)