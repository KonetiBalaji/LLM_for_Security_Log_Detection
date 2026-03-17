# SENTINEL

**Semantic-Enhanced Network Threat Intelligence for Enterprise Log Analysis**

[![CI](https://github.com/KonetiBalaji/LLM_for_Security_Log_Detection/actions/workflows/ci.yml/badge.svg)](https://github.com/KonetiBalaji/LLM_for_Security_Log_Detection/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-102%20passed-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-68%25-yellow.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Mission

*Advance AI-driven cybersecurity log intelligence to detect, classify, explain, and triage security threats across enterprise environments — augmenting human analysts and supporting U.S. cybersecurity resilience in healthcare, finance, federal, and critical infrastructure use cases.*

---

## Abstract

Security Operations Centers (SOCs) are overwhelmed by alert volumes that far exceed human investigative capacity, while the U.S. faces a cybersecurity workforce shortage of over 500,000 unfilled positions. SENTINEL addresses this by implementing a **hybrid multi-tier AI detection pipeline** that combines rule-based pattern matching, BERT-based transformer classification, and large language model-assisted analysis. The system automatically maps detected threats to the **MITRE ATT&CK framework**, generates root cause analysis and actionable recommendations, and provides analyst-friendly explainability. The project includes a benchmark framework for comparing the hybrid pipeline with single-method baselines on labelled log data, with broader public-dataset evaluation currently in progress.

---

## Problem Statement

Security operations and cyber defense present a critical national challenge:

- **Alert Fatigue**: The average SOC receives 10,000+ alerts per day; analysts can investigate only a fraction (Ponemon Institute)
- **Workforce Gap**: 500,000+ unfilled cybersecurity positions in the U.S. alone ((ISC)² Workforce Study)
- **Detection Complexity**: Modern threats span multiple log sources and require context that simple rule-based SIEM tools cannot provide
- **Compliance Burden**: Organizations across healthcare (HIPAA), finance (PCI-DSS/SOX), and federal sectors (FISMA/FedRAMP) must continuously monitor logs for regulatory compliance
- **Mean Time to Detect (MTTD)**: The average time to identify a breach is 204 days (IBM Cost of Data Breach Report) — intelligent automation can dramatically reduce this

SENTINEL directly addresses these challenges by creating an AI system that augments human security analysts, enabling organizations of all sizes to improve their threat detection capabilities.

## Why This Matters to U.S. Cybersecurity

This project supports the objectives outlined in:
- **Executive Order 14028** (Improving the Nation's Cybersecurity) — improved detection capabilities
- **National Cybersecurity Strategy** (March 2023) — shifting the burden of defense through technology
- **NIST Cybersecurity Framework 2.0** — Detect and Respond function automation
- **Cyberspace Solarium Commission** — workforce force-multiplication through AI

AI-augmented log analysis serves as a **cybersecurity workforce multiplier**: if automated systems can handle a substantial share of routine log classification and triage, existing analysts can focus on the cases that require human judgment and expertise.

---

## Key Innovations

1. **Hybrid Multi-Tier Detection Pipeline** — Three AI paradigms (rules, ML, LLM) combined via Chain of Responsibility pattern, where each tier either classifies or defers to the next
2. **Automated MITRE ATT&CK Mapping** — Every detected threat mapped to specific technique IDs and tactics (11 techniques across 7 tactics)
3. **Confidence-Aware Cascade** — Each classifier reports a confidence score, and the pipeline only accepts predictions above tier-specific thresholds
4. **Multi-Format Auto-Detection** — ParserRegistry automatically identifies and parses 6 log formats without manual configuration
5. **Explainable Security Analysis** — Root cause analysis, per-event recommendations, and MITRE context for every detected threat
6. **Enterprise Security Controls** — Authentication, rate limiting, input validation, XSS prevention, and CSP headers built into the API layer

---

## Technical Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          SENTINEL Platform                               │
│                                                                          │
│  ┌──────────────────┐    ┌──────────────────┐    ┌───────────────────┐  │
│  │  INGESTION LAYER  │    │  DETECTION LAYER  │    │  ANALYSIS LAYER   │  │
│  │  (parsers/)       │───▶│  (classifiers/)   │───▶│  (analyzers/)     │  │
│  │                   │    │                   │    │                   │  │
│  │  6 parsers with   │    │  Regex → BERT     │    │  7 sub-analyzers: │  │
│  │  auto-detection   │    │  → LLM cascade    │    │  Events, IPs,     │  │
│  │  via Registry     │    │                   │    │  URLs, MITRE,     │  │
│  │                   │    │  Chain of          │    │  Root Cause,      │  │
│  │  Strategy Pattern │    │  Responsibility   │    │  Recommendations, │  │
│  │                   │    │                   │    │  Time Analysis    │  │
│  └──────────────────┘    └──────────────────┘    └───────────────────┘  │
│                                                          │               │
│  ┌──────────────────┐    ┌──────────────────┐           │               │
│  │  API LAYER        │    │  EVALUATION       │           ▼               │
│  │  (api/)           │    │  (evaluation/)    │    ┌───────────────────┐  │
│  │                   │    │                   │    │  Facade:           │  │
│  │  FastAPI + Auth   │    │  Benchmark suite  │    │  SecurityAnalyzer  │  │
│  │  Rate Limiting    │    │  Multi-model      │    │  orchestrates all  │  │
│  │  Input Validation │    │  comparison       │    │  sub-modules       │  │
│  │  CSP Headers      │    │  P/R/F1/Accuracy  │    └───────────────────┘  │
│  └──────────────────┘    └──────────────────┘                            │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
Raw Log → Auto-Detect Format → Parse to Structured Dict
  → Classify via Hybrid Pipeline (Regex → BERT → LLM)
  → Extract Security Events (severity + attack type assignment)
  → Map to MITRE ATT&CK Techniques
  → Root Cause Analysis
  → Generate Recommendations
  → Aggregate into AnalysisResult (JSON)
```

### Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Single Responsibility** | Each of 9 analyzer modules handles exactly one concern |
| **Open/Closed** | New parsers and classifiers added without modifying existing code |
| **Liskov Substitution** | All parsers implement `LogParser` ABC; all classifiers implement `Classifier` ABC |
| **Interface Segregation** | `Classifier` and `EntityExtractor` are separate protocols |
| **Dependency Inversion** | Pipeline accepts abstract classifier list, not concrete classes |
| **Strategy Pattern** | 6 parsers selected at runtime via `ParserRegistry` auto-detection |
| **Chain of Responsibility** | Classification cascade: Regex → BERT → LLM with confidence thresholds |
| **Facade Pattern** | `SecurityAnalyzer` composes 7 sub-analyzers behind a single `analyze()` method |

See [docs/architecture.md](docs/architecture.md) for the full architecture document with ADR rationale.

---

## Detection Methods

### Tier 1 — Rule-Based Detection (Regex)

Fast, deterministic classification using 18 compiled regex patterns covering known log signatures: security alerts, HTTP status, user actions, system notifications, resource usage, errors, deprecation warnings, and workflow failures. Confidence is always 1.0 for matches. Runs in microseconds per log.

### Tier 2 — ML Classification (BERT + Logistic Regression)

Sentence-Transformer (`all-MiniLM-L6-v2`) generates 384-dimensional embeddings for each log message. A logistic regression classifier (trained with 5-fold stratified cross-validation on labeled log data) produces probability scores used by the cascade threshold logic. Predictions below the confidence threshold (default 0.5) are declined and passed to the next tier.

### Tier 3 — LLM Semantic Analysis (OpenAI API)

For complex or ambiguous log entries that neither rules nor ML can confidently classify, the system sends the log to a large language model (GPT-4o-mini by default) with a structured prompt requesting classification and technical reasoning. Includes retry logic with exponential backoff and rate-limit handling. Falls back to a clearly-labelled simulation when no API key is configured.

### Hybrid Fusion Strategy

The pipeline processes each log through the tiers in order. The first tier that returns a classification with confidence above its threshold wins. This ensures:
- **Speed**: Known patterns are handled instantly by regex (no model loading)
- **Accuracy**: Statistical patterns are caught by BERT embeddings
- **Coverage**: Novel or ambiguous entries get LLM reasoning
- **Cost Control**: Expensive LLM calls are only made when cheaper methods fail

---

## Benchmark & Evaluation

### How to Run

```bash
python -m sentinel.cli.main benchmark
```

### Approaches Compared

| # | Approach | Description |
|---|----------|-------------|
| 1 | Regex Only | 18 rule-based patterns |
| 2 | BERT Only | Sentence-Transformer + Logistic Regression |
| 3 | LLM (Simulated) | Keyword-based simulation of LLM classification |
| 4 | **Hybrid (Regex → BERT → LLM)** | Full cascade pipeline |

### Metrics Reported

- **Per-class**: Precision, Recall, F1-Score, Support
- **Aggregate**: Accuracy, F1 Macro, F1 Weighted
- **Operational**: Throughput (logs/second), latency
- **Confusion Matrix**: Full N×N matrix for error analysis

### Evaluated Datasets

| Dataset | Source | Records | Log Type |
|---------|--------|---------|----------|
| Synthetic | Generated | 2,410 | Mixed (OpenStack, CRM, HR, Billing, API) |

> **Note**: Integration with public datasets (HDFS from Loghub, BGL, Thunderbird) is supported via the HDFS parser and dataset loader framework. Cross-domain evaluation is part of the active research roadmap.

---

## MITRE ATT&CK Coverage

SENTINEL automatically maps every detected threat to MITRE ATT&CK Enterprise techniques:

| Detection | Technique ID | Technique Name | Tactic | ATT&CK Reference |
|-----------|-------------|----------------|--------|-------------------|
| Brute Force | T1110 | Brute Force | Credential Access | [Link](https://attack.mitre.org/techniques/T1110) |
| SQL Injection | T1190 | Exploit Public-Facing Application | Initial Access | [Link](https://attack.mitre.org/techniques/T1190) |
| XSS | T1189 | Drive-by Compromise | Initial Access | [Link](https://attack.mitre.org/techniques/T1189) |
| Command Injection | T1059 | Command and Scripting Interpreter | Execution | [Link](https://attack.mitre.org/techniques/T1059) |
| File Inclusion | T1190 | Exploit Public-Facing Application | Initial Access | [Link](https://attack.mitre.org/techniques/T1190) |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Privilege Escalation | [Link](https://attack.mitre.org/techniques/T1068) |
| Path Traversal | T1083 | File and Directory Discovery | Discovery | [Link](https://attack.mitre.org/techniques/T1083) |
| Network Scanning | T1046 | Network Service Scanning | Discovery | [Link](https://attack.mitre.org/techniques/T1046) |
| Denial of Service | T1499 | Endpoint Denial of Service | Impact | [Link](https://attack.mitre.org/techniques/T1499) |
| Malware Execution | T1204 | User Execution | Execution | [Link](https://attack.mitre.org/techniques/T1204) |
| Data Collection | T1005 | Data from Local System | Collection | [Link](https://attack.mitre.org/techniques/T1005) |

---

## Enterprise Deployment

### Local Development

```bash
pip install -e ".[dev]"
python -m sentinel.cli.main serve
```

### Docker

```bash
docker compose up --build
# API: http://localhost:8000
# Swagger: http://localhost:8000/docs
```

### AWS Reference Architecture (planned production deployment pattern)

```
Internet → API Gateway → ALB → ECS Fargate (SENTINEL API)
                                    ├── Classification Service
                                    ├── Analysis Service
                                    └── Explainability Service
                                         │
            ┌────────────────────────────┤
            ▼                            ▼
      SQS (async jobs)            S3 (log storage)
            │                            │
            ▼                            ▼
      ECS Workers               Athena (log query)
      (batch processing)
            │
            ▼
      RDS PostgreSQL          ElastiCache (Redis)
      (results, metadata)     (embedding cache)
            │
            ▼
      CloudWatch + Grafana
      (monitoring & alerting)
```

### Web Interface

Navigate to [http://localhost:8000](http://localhost:8000) to:
- Upload log files (.log, .txt, .csv)
- Paste raw log text for instant analysis
- View security events with severity colour-coding
- Browse MITRE ATT&CK technique mappings
- Read actionable recommendations per event

---

## Security & Compliance

| Control | Implementation |
|---------|---------------|
| **Authentication** | Optional Bearer token auth (`SENTINEL_AUTH_ENABLED`) |
| **Rate Limiting** | Per-IP sliding window, 120 requests/minute |
| **Input Validation** | File extension whitelist (.csv/.log/.txt), 50 MB size limit, 10K line limit for raw input |
| **XSS Prevention** | All user content escaped via `esc()` function; Content-Security-Policy header |
| **Secrets Management** | API keys via environment variables only; `.env` in `.gitignore` |
| **Dependency Security** | Pinned dependencies in `pyproject.toml`; CI-compatible with `safety` scanning |
| **Non-Root Container** | Dockerfile creates and uses a `sentinel` user |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check with version info |
| `POST` | `/v1/classify` | Classify a log file → returns CSV with labels, confidence, method |
| `POST` | `/v1/analyze` | Full security analysis of a log file → JSON with events, MITRE, recommendations |
| `POST` | `/v1/analyze/raw` | Analyse raw log text (form field) → JSON |
| `GET` | `/docs` | Interactive Swagger/OpenAPI documentation |

---

## Cross-Sector Applicability

SENTINEL's detection capabilities are designed for security log analysis use cases relevant across multiple U.S. industries:

| Sector | Use Case | Compliance Framework |
|--------|----------|---------------------|
| **Healthcare** | Monitor for unauthorized PHI access, anomalous EHR queries | HIPAA |
| **Financial Services** | Detect transaction log anomalies, fraud indicators | PCI-DSS, SOX |
| **Federal / Government** | Continuous monitoring, incident detection | FISMA, FedRAMP |
| **Cloud Infrastructure** | CloudTrail analysis, VPC flow log anomaly detection | SOC 2, CSA STAR |
| **Education** | Campus network intrusion detection, credential stuffing | FERPA |
| **Critical Infrastructure** | SCADA/ICS log monitoring, OT threat detection | NIST SP 800-82 |

---

## Project Structure

```
sentinel/
├── src/sentinel/
│   ├── core/              # Domain models, enums, config, exceptions
│   │   ├── enums.py       # SeverityLevel, AttackType, LogType, MitreTactic
│   │   ├── models.py      # ClassificationResult, SecurityEvent, AnalysisResult
│   │   ├── config.py      # Pydantic Settings (env vars, paths)
│   │   └── exceptions.py  # Custom exception hierarchy
│   ├── parsers/           # Log format parsers (Strategy pattern)
│   │   ├── base.py        # Abstract LogParser
│   │   ├── web_server.py  # Apache/Nginx
│   │   ├── syslog.py      # Syslog + auth.log
│   │   ├── openstack.py   # OpenStack services
│   │   ├── hdfs.py        # Hadoop HDFS
│   │   ├── generic.py     # Fallback
│   │   └── registry.py    # Auto-detection registry
│   ├── classifiers/       # Hybrid classification pipeline
│   │   ├── base.py        # Classifier + EntityExtractor protocols
│   │   ├── regex.py       # Rule-based (18 patterns)
│   │   ├── bert.py        # BERT embeddings + LogReg
│   │   ├── llm.py         # LLM API + simulation fallback
│   │   └── pipeline.py    # Chain of Responsibility orchestrator
│   ├── analyzers/         # Security analysis (7 focused modules)
│   │   ├── event_extractor.py    # Security event identification
│   │   ├── ip_analyzer.py        # IP frequency + suspicious detection
│   │   ├── url_analyzer.py       # URL attack pattern detection
│   │   ├── time_analyzer.py      # Temporal distribution
│   │   ├── mitre_mapper.py       # MITRE ATT&CK technique mapping
│   │   ├── root_cause.py         # Root cause analysis
│   │   ├── recommendation.py     # Actionable recommendations
│   │   ├── entity_extraction.py  # IP/URL/user extraction
│   │   └── orchestrator.py       # Facade composing all above
│   ├── api/               # FastAPI application
│   │   ├── app.py         # App factory with middleware
│   │   ├── middleware.py   # Auth, rate limit, size limit
│   │   ├── dependencies.py # DI providers
│   │   └── routes/         # /v1/classify, /v1/analyze, /health
│   ├── cli/               # Command-line interface
│   │   └── main.py        # analyze, serve, benchmark, train
│   ├── evaluation/        # Benchmarking and training
│   │   ├── benchmark.py   # Multi-model comparison harness
│   │   ├── metrics.py     # P/R/F1/accuracy computation
│   │   ├── datasets.py    # Dataset loaders
│   │   └── train.py       # 5-fold CV BERT classifier training
│   └── utils/             # I/O and serialization
│       └── io.py
├── tests/                 # 102 tests (unit + integration)
│   ├── conftest.py        # Shared fixtures
│   ├── unit/              # Parsers, classifiers, analyzers, models
│   └── integration/       # Pipeline end-to-end, API endpoints
├── data/                  # Log datasets
│   └── synthetic_logs.csv # 2,410 labelled entries
├── models/                # Trained model artifacts
│   └── log_classifier.joblib
├── templates/             # Web UI (Bootstrap + XSS-safe JS)
├── docs/                  # Architecture documentation
│   └── architecture.md
├── .github/workflows/     # CI/CD (lint, test, coverage)
│   └── ci.yml
├── Dockerfile             # Multi-stage build, non-root user
├── docker-compose.yml     # Local deployment
├── pyproject.toml         # Modern Python packaging + tool config
├── .env.example           # Documented environment variables
├── .gitignore
├── LICENSE
└── README.md
```

---

## Technology Stack

| Component | Technology | Justification |
|-----------|-----------|---------------|
| Language | Python 3.10+ | Industry standard for ML/security tooling |
| API Framework | FastAPI + Uvicorn | Async, auto-generated OpenAPI docs, high performance |
| ML Embeddings | Sentence-Transformers (`all-MiniLM-L6-v2`) | Fast, high-quality 384-dim embeddings |
| Classifier | scikit-learn (Logistic Regression) | Interpretable classifier with probability-based thresholds |
| LLM Integration | OpenAI API (GPT-4o-mini) | Cost-effective, structured output parsing |
| Configuration | Pydantic Settings | Type-safe, env var + .env support |
| Testing | pytest + pytest-cov (102 tests, 68% coverage) | Fast, well-supported, CI-ready |
| CI/CD | GitHub Actions | Native GitHub integration |
| Containerisation | Docker (multi-stage, non-root) | Reproducible, secure deployment |
| Threat Framework | MITRE ATT&CK Enterprise | Industry standard for threat classification |

---

## Roadmap

### Completed

- [x] Hybrid multi-tier classification pipeline (Regex → BERT → LLM)
- [x] MITRE ATT&CK technique mapping (11 techniques, 7 tactics)
- [x] Security hardening (auth, rate limiting, input validation, XSS prevention)
- [x] SOLID architecture with Strategy, Chain of Responsibility, and Facade patterns
- [x] 102 automated tests (unit + integration)
- [x] CI/CD pipeline (GitHub Actions)
- [x] Docker containerisation
- [x] Web interface with MITRE display
- [x] Multi-format log parsing (6 formats with auto-detection)
- [x] Benchmark harness for multi-model comparison

### In Progress

- [ ] Cross-domain evaluation on HDFS, BGL, and Thunderbird public datasets
- [ ] Confidence calibration (Platt scaling on BERT outputs)
- [ ] Technical white paper: "Hybrid Multi-Tier Approaches to Security Log Classification"
- [ ] MLflow experiment tracking integration

### Planned

- [ ] Isolation Forest anomaly detection tier
- [ ] SHAP explainability for ML classifier decisions
- [ ] Streaming ingestion (Kafka consumer)
- [ ] SOC analyst feedback loop (true/false positive marking)
- [ ] Adversarial robustness testing (log poisoning, prompt injection)
- [ ] AWS Terraform deployment (ECS Fargate + S3 + RDS)
- [ ] Zero-shot / few-shot classification evaluation on unseen log formats
- [ ] Privacy-preserving log analysis (PII detection and masking)

---

## Future Research Directions

1. **Cross-Domain Generalisation Study** — Evaluate how the hybrid pipeline transfers across healthcare, financial, federal, and cloud log environments without retraining
2. **Zero-Shot Incident Classification** — Test LLM capability to classify log types never seen during training
3. **SOC Analyst Copilot** — Interactive LLM-based investigation assistant for log triage and attack narrative generation
4. **Adversarial Robustness** — Defence against log poisoning attacks and prompt injection targeting the LLM tier
5. **Cost-Performance Tradeoff Analysis** — Quantify the marginal detection improvement of LLM calls vs. inference cost
6. **Detection Explainability Research** — SHAP feature attribution + LLM rationale chains for analyst trust
7. **Low-Resource SOC Automation** — Evaluate SENTINEL's value for mid-sized U.S. organisations that cannot afford full SOC teams

---

## Quick Start

### Installation

```bash
git clone https://github.com/KonetiBalaji/LLM_for_Security_Log_Detection.git
cd LLM_for_Security_Log_Detection

# Install with development dependencies
pip install -e ".[dev]"

# (Optional) Configure LLM API access
cp .env.example .env
# Edit .env with your SENTINEL_OPENAI_API_KEY
# System works without API key using simulated LLM fallback
```

### Run Tests

```bash
pytest                          # All 102 tests
pytest --cov=sentinel           # With coverage report
pytest tests/unit/              # Unit tests only
pytest tests/integration/       # Integration tests only
```

### Start the API Server

```bash
python -m sentinel.cli.main serve
# API: http://localhost:8000
# Swagger: http://localhost:8000/docs
# Web UI: http://localhost:8000
```

### Analyse a Log File

```bash
python -m sentinel.cli.main analyze data/synthetic_logs.csv -o results/
```

### Run Benchmarks

```bash
python -m sentinel.cli.main benchmark
```

### Docker Deployment

```bash
docker compose up --build
```

---

## Citation

If you use SENTINEL in your research or work, please cite:

```bibtex
@software{koneti2025sentinel,
  author = {Koneti, Balaji},
  title = {SENTINEL: Semantic-Enhanced Network Threat Intelligence for Enterprise Log Analysis},
  year = {2025},
  url = {https://github.com/KonetiBalaji/LLM_for_Security_Log_Detection}
}
```

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/improvement`)
3. Write tests for your changes
4. Ensure all tests pass (`pytest`)
5. Lint your code (`ruff check src/ tests/`)
6. Submit a Pull Request

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**Koneti Balaji** — [koneti.balaji08@gmail.com](mailto:koneti.balaji08@gmail.com)

Project Link: [https://github.com/KonetiBalaji/LLM_for_Security_Log_Detection](https://github.com/KonetiBalaji/LLM_for_Security_Log_Detection)
