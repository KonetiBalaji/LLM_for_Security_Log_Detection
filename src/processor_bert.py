import joblib
from sentence_transformers import SentenceTransformer
import numpy as np
import os
from typing import Tuple, List, Dict, Any, Optional

class BertProcessor:
    """Process logs using BERT embeddings and classification"""
    
    def __init__(self, model_path: str = None):
        """Initialize BERT processor
        
        Args:
            model_path: Path to trained classifier model
        """
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')  
        
        # Get the directory of the current script (src)
        script_dir = os.path.dirname(os.path.abspath(__file__))
    
        # Set default paths relative to the script's location
        if model_path is None:
        # Navigate from src to data directory (one level up, then into data)
          model_path = os.path.join(script_dir, "..", "models", "log_classifier.joblib")
        
        # Check if model exists, if not, create a dummy one
        if not os.path.exists(model_path):
            print(f"Warning: Model file {model_path} not found. Using a dummy classifier.")
            from sklearn.linear_model import LogisticRegression
            self.classifier = LogisticRegression()
            # Define some dummy classes
            self.classifier.classes_ = np.array([
                "HTTP Status", "Security Alert", "Critical Error", 
                "Error", "System Notification", "User Action",
                "Resource Usage", "Workflow Error", "Deprecation Warning"
            ])
        else:
            self.classifier = joblib.load(model_path)
    
    def embed(self, log_message: str) -> np.ndarray:
        """Generate embedding for log message
        
        Args:
            log_message: Log message to embed
            
        Returns:
            Embedding vector
        """
        return self.embedding_model.encode([log_message])[0]
    
    def classify_with_bert(self, log_message: str) -> Tuple[str, float]:
        """Classify log message using BERT embeddings
        
        Args:
            log_message: Log message to classify
            
        Returns:
            Tuple of (predicted_label, confidence)
        """
        embeddings = self.embedding_model.encode([log_message])
        
        try:
            probabilities = self.classifier.predict_proba(embeddings)[0]
            predicted_class_index = np.argmax(probabilities)
            predicted_label = self.classifier.classes_[predicted_class_index]
            confidence = probabilities[predicted_class_index]
            
            # Return "Unclassified" if confidence is too low
            if confidence < 0.5:
                return "Unclassified", 0.0
                
            return predicted_label, confidence
        except:
            # If an error occurs (e.g., dummy classifier), make a best guess
            # based on keywords in the log message
            log_lower = log_message.lower()
            
            if "http" in log_lower or "get" in log_lower or "post" in log_lower:
                return "HTTP Status", 0.7
            elif "error" in log_lower or "exception" in log_lower:
                return "Error", 0.7
            elif "security" in log_lower or "unauthorized" in log_lower:
                return "Security Alert", 0.7
            else:
                return "Unclassified", 0.0


# For backward compatibility
def classify_with_bert(log_message):
    processor = BertProcessor()
    label, _ = processor.classify_with_bert(log_message)
    return label


if __name__ == "__main__":
    # Test the processor with some examples
    processor = BertProcessor()
    test_logs = [
        "nova.osapi_compute.wsgi.server - 12.10.11.1 - API returned 404 not found error",
        "GET /v2/3454/servers/detail HTTP/1.1 RCODE   404 len: 1583 time: 0.1878400",
        "System crashed due to drivers errors when restarting the server",
        "Hey bro, chill ya!",
        "Multiple login failures occurred on user 6454 account",
        "Server A790 was restarted unexpectedly during the process of data transfer"
    ]
    
    for log in test_logs:
        label, confidence = processor.classify_with_bert(log)
        print(f"Log: {log}")
        print(f"Classification: {label} (Confidence: {confidence:.2f})")
        print("-" * 50)