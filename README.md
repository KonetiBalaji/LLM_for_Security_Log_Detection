# LLM for Security Log Detection

A powerful hybrid log classification and security analysis system that leverages Large Language Models (LLMs) to enhance security log detection and analysis capabilities. This system combines multiple approaches to handle log patterns of varying complexity, providing comprehensive security insights and actionable recommendations.

## 🌟 Features

- **Hybrid Classification System**
  - Regular Expression (Regex) for simple, predictable patterns
  - BERT + Logistic Regression for complex patterns with sufficient training data
  - LLM-based Classification for complex patterns with limited training data

- **Advanced Security Analysis**
  - Real-time security event detection
  - Root cause analysis for identified threats
  - Actionable security recommendations
  - Severity assessment and prioritization

- **User-Friendly Interface**
  - Modern web interface for interactive analysis
  - Command-line interface for automation
  - Batch processing capabilities
  - Real-time analysis results

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/KonetiBalaji/LLM_for_Security_Log_Detection.git
cd LLM_for_Security_Log_Detection
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On Unix or MacOS
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## 💻 Usage

### Web Interface

1. Start the web server:
```bash
uvicorn server:app --reload
```

2. Open your browser and navigate to [http://127.0.0.1:8000](http://127.0.0.1:8000)

3. Use the web interface to:
   - Upload log files
   - View real-time analysis
   - Export results
   - Configure analysis parameters

### Command Line Interface

Process a single log file:
```bash
python main.py --input logs/sample.log --output results.json
```

Process multiple files:
```bash
python main.py --input logs/ --output results/ --batch
```

## 📂 Supported File Types

The system supports the following file types for log analysis:

| File Type | Description                | Example Use Case                |
|-----------|----------------------------|---------------------------------|
| .log      | Plain text log files       | System/application logs         |
| .txt      | Plain text files           | Exported logs, manual logs      |
| .csv      | Comma-separated log files  | Structured logs from SIEM tools |

- **.log**: Standard log files, each line is a log entry.
- **.txt**: Plain text files containing logs, one entry per line.
- **.csv**: Each row is a log entry, suitable for structured logs.

**How to Use:**
- In the web interface, click "Choose File" and select a `.log`, `.txt`, or `.csv` file to upload and analyze.
- You can also paste raw log text into the "Paste Raw Logs" box for quick analysis.
- The CLI also accepts these file types as input for batch or single-file processing.

## 📁 Project Structure

```
📦llm_log_detection
┣ 📂data                   # Sample data files
┣ 📂models                 # Trained models
┣ 📂src                    # Source code
┃ ┣ 📜processor_regex.py   # Regex-based classification
┃ ┣ 📜processor_bert.py    # BERT-based classification
┃ ┣ 📜processor_llm.py     # LLM-based classification
┃ ┣ 📜classify.py          # Unified classification pipeline
┃ ┣ 📜security_analyzer.py # Security event analysis
┃ ┣ 📜data_preprocessing.py # Log parsing and normalization
┃ ┗ 📜utils.py             # Utility functions
┣ 📂static                 # Frontend assets
┣ 📂templates              # HTML templates
┣ 📜server.py              # FastAPI server
┣ 📜main.py                # CLI application
┣ 📜requirements.txt       # Dependencies
┗ 📜README.md              # Documentation
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all contributors who have helped shape this project
- Special thanks to the open-source community for their invaluable tools and libraries

## 📧 Contact

Koneti Balaji - koneti.balaji08@gmail.com

Project Link: [https://github.com/KonetiBalaji/LLM_for_Security_Log_Detection](https://github.com/KonetiBalaji/LLM_for_Security_Log_Detection)
