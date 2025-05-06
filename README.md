
# LLM-for-Security-Log-Detection

# LLM-based Security Log Detection and Analysis

<p align="center">
  <img src="static/logo.png" alt="Logo" width="200" height="200">
</p>

This project implements a hybrid log classification and security analysis system, leveraging LLMs (Large Language Models) to enhance security log detection and analysis capabilities. The system combines three complementary approaches to handle log patterns of varying complexity:

1. **Regular Expression (Regex)**: For simple, predictable patterns  
2. **BERT + Logistic Regression**: For complex patterns with sufficient training data  
3. **LLM-based Classification**: For complex patterns with limited training data

## Features

- **Hybrid Classification**: Efficiently categorizes logs using the appropriate method based on complexity  
- **Security Event Detection**: Identifies potential security threats and suspicious activities  
- **Root Cause Analysis**: Suggests underlying causes for security events  
- **Actionable Recommendations**: Provides concrete steps to address security issues  
- **User-friendly Interface**: Web interface and command-line options for analyzing logs  
- **Batch Processing**: Support for processing multiple log files and directories

## Project Structure

```

📦llm\_log\_detection
┣ 📂data                   # Sample data files
┣ 📂models                 # Trained models
┣ 📂src                    # Source code
┃ ┣ 📜processor\_regex.py   # Regex-based classification
┃ ┣ 📜processor\_bert.py    # BERT-based classification
┃ ┣ 📜processor\_llm.py     # LLM-based classification
┃ ┣ 📜classify.py          # Unified classification pipeline
┃ ┣ 📜security\_analyzer.py # Security event analysis
┃ ┣ 📜data\_preprocessing.py # Log parsing and normalization
┃ ┗ 📜utils.py             # Utility functions
┣ 📂static                 # Frontend assets
┣ 📂templates              # HTML templates
┣ 📜server.py              # FastAPI server
┣ 📜main.py                # CLI application
┣ 📜requirements.txt       # Dependencies
┗ 📜README.md              # This file

````

## Installation

```bash
git clone https://github.com/yourusername/llm_log_detection.git
cd llm_log_detection
pip install -r requirements.txt
````

## Usage

### Run the Web Server

```bash
uvicorn server:app --reload
```

Visit [http://127.0.0.1:8000](http://127.0.0.1:8000) to access the interface.

### CLI

```bash
python main.py --input logs/sample.log --output results.json
```

## License

This project is licensed under the MIT License.
