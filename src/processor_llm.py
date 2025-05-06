import os
import re
from typing import Dict, List, Any, Optional
import requests
import json
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class LLMProcessor:
    """Process logs using LLM for context-aware classification and analysis"""
    
    def __init__(self, model_name: str = None):
        """Initialize LLM processor
        
        Args:
            model_name: Name of the model to use (defaults to environment variable or fallback)
        """
        # Try to get API key from environment
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model_name = model_name or os.getenv("LLM_MODEL") or "gpt-3.5-turbo"

        # OpenAI-compatible API
        self.api_type = "openai"
        self.api_url = "https://api.openai.com/v1/chat/completions"
            
        # If no API key is available, print a warning
        if not self.api_key:
            print("Warning: No API key found for LLM classification. Will use simulated responses.")
            
    def classify_with_llm(self, log_msg: str, custom_prompt: str = None) -> Dict[str, Any]:
        """Classify log message using LLM or perform custom analysis
        
        Args:
            log_msg: Log message to classify
            custom_prompt: Optional custom prompt for specialized analysis
            
        Returns:
            Dictionary with classification or analysis results
        """
        # Use custom prompt if provided, otherwise use standard classification prompt
        prompt = custom_prompt if custom_prompt else self._create_prompt(log_msg, None)
        
        # If no API key, simulate response
        if not self.api_key:
            if custom_prompt:
                # For custom prompts, provide a simpler simulated response
                if "root cause" in custom_prompt.lower():
                    return {
                        "raw_response": "<root_cause>Unable to determine specific cause without LLM API access. The system is falling back to rule-based analysis.</root_cause>",
                        "reasoning": "Simulated response - LLM API access required for detailed analysis"
                    }
                elif "recommendations" in custom_prompt.lower():
                    return {
                        "raw_response": "<recommendations>Unable to provide detailed recommendations without LLM API access. The system is falling back to rule-based analysis.</recommendations>",
                        "reasoning": "Simulated response - LLM API access required for detailed analysis"
                    }
                else:
                    return self._simulate_response(log_msg)
            else:
                # For standard classification, use the existing simulation
                return self._simulate_response(log_msg)
        
        # Set up headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        # Set up payload
        payload = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 500
        }
        
        try:
            # Make API call
            response = requests.post(
                self.api_url,
                headers=headers,
                data=json.dumps(payload)
            )
            
            # Check for errors
            if response.status_code != 200:
                print(f"API Error: {response.status_code}, {response.text}")
                return self._simulate_response(log_msg)
            
            # Parse response
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            
            # Parse LLM output
            return self._parse_response(content)
            
        except Exception as e:
            print(f"Error calling LLM API: {e}")
            return self._simulate_response(log_msg)
    
    def _create_prompt(self, log_message: str, context: Optional[str]) -> str:
        """Create enhanced prompt for LLM with more detailed reasoning request
        
        Args:
            log_message: Log message to classify
            context: Additional context
            
        Returns:
            Formatted prompt
        """
        prompt = f"""Analyze this log message and classify it into one of these categories: 
(1) Security Alert, (2) Critical Error, (3) System Notification, (4) HTTP Status,
(5) Resource Usage, (6) User Action, (7) Workflow Error, (8) Deprecation Warning.

If you can't determine a category, use "Unclassified".

Put the category inside <category> </category> tags.

Provide a detailed technical reasoning inside <reasoning> </reasoning> tags that includes:
1. What happened (the specific issue or event)
2. What specific component, service, or system is affected
3. The likely root cause of the issue (if it's an error or problem)
4. What specific steps might be taken to address the issue
5. Any technical implications or downstream impacts this might have

Log message: {log_message}"""

        if context:
            prompt += f"\n\nAdditional context: {context}"
            
        return prompt
    
    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response to extract classification and reasoning
        
        Args:
            response: LLM response text
            
        Returns:
            Dictionary with parsed results
        """
        category_match = re.search(r'<category>(.*?)</category>', response, re.DOTALL)
        reasoning_match = re.search(r'<reasoning>(.*?)</reasoning>', response, re.DOTALL)
        root_cause_match = re.search(r'<root_cause>(.*?)</root_cause>', response, re.DOTALL)
        recommendations_match = re.search(r'<recommendations>(.*?)</recommendations>', response, re.DOTALL)
        
        result = {
            "raw_response": response
        }
        
        if category_match:
            result["category"] = category_match.group(1).strip()
        else:
            result["category"] = "Unclassified"
        
        if reasoning_match:
            result["reasoning"] = reasoning_match.group(1).strip()
        else:
            result["reasoning"] = ""
            
        if root_cause_match:
            result["root_cause"] = root_cause_match.group(1).strip()
            
        if recommendations_match:
            result["recommendations"] = recommendations_match.group(1).strip()
            
        return result
    
    def _simulate_response(self, log_message: str) -> Dict[str, Any]:
        """Simulate LLM response when API is unavailable
        
        Args:
            log_message: Log message to classify
            
        Returns:
            Simulated classification results
        """
        log_lower = log_message.lower()
        
        if "authentication fail" in log_lower or "unauthorized" in log_lower or "suspicious" in log_lower:
            category = "Security Alert"
            reasoning = "The log indicates a potential security threat related to authentication or authorization."
        elif "error" in log_lower or "exception" in log_lower or "crash" in log_lower:
            category = "Critical Error"
            reasoning = "The log indicates a critical system error that may affect functionality."
        elif "backup" in log_lower or "update" in log_lower or "reboot" in log_lower:
            category = "System Notification"
            reasoning = "The log is a standard system notification about routine operations."
        elif "http" in log_lower or "get" in log_lower or "post" in log_lower or "status: " in log_lower:
            category = "HTTP Status"
            reasoning = "The log contains HTTP request information."
        elif "memory" in log_lower or "cpu" in log_lower or "disk" in log_lower or "usage" in log_lower:
            category = "Resource Usage"
            reasoning = "The log provides information about system resource utilization."
        elif "user" in log_lower or "login" in log_lower or "logged in" in log_lower:
            category = "User Action"
            reasoning = "The log describes an action taken by a user."
        elif "workflow" in log_lower or "process" in log_lower or "task" in log_lower or "failed" in log_lower:
            category = "Workflow Error"
            reasoning = "The log indicates a failure in a workflow or process."
        elif "deprecated" in log_lower or "will be removed" in log_lower or "outdated" in log_lower:
            category = "Deprecation Warning"
            reasoning = "The log contains a warning about deprecated functionality."
        else:
            category = "Unclassified"
            reasoning = "Unable to confidently classify this log message."
        
        return {
            "category": category,
            "reasoning": reasoning,
            "raw_response": f"<category>{category}</category><reasoning>{reasoning}</reasoning>"
        }


# For backward compatibility
def classify_with_llm(log_msg):
    processor = LLMProcessor()
    result = processor.classify_with_llm(log_msg)
    return result["category"]


if __name__ == "__main__":
    # Test the processor with some examples
    processor = LLMProcessor()
    test_logs = [
        "Case escalation for ticket ID 7324 failed because the assigned support agent is no longer active.",
        "The 'ReportGenerator' module will be retired in version 4.0. Please migrate to the 'AdvancedAnalyticsSuite' by Dec 2025",
        "System reboot initiated by user 12345."
    ]
    
    for log in test_logs:
        result = processor.classify_with_llm(log)
        print(f"Log: {log}")
        print(f"Classification: {result['category']}")
        print(f"Reasoning: {result['reasoning']}")
        print("-" * 50)