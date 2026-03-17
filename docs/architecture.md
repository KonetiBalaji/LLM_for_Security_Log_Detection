# SENTINEL Architecture

## System Overview

SENTINEL is a multi-tier AI-driven security log analysis platform that combines rule-based pattern matching, transformer-based machine learning, and large language model reasoning to detect, classify, and explain cybersecurity threats in enterprise log data.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          SENTINEL Platform                               │
│                                                                          │
│  ┌─────────────────────┐                                                │
│  │   INGESTION LAYER    │  Supports: CSV, .log, .txt, raw text          │
│  │   (parsers/)         │  Formats:  Web Server, Syslog, Security,      │
│  │                      │            OpenStack, HDFS, Generic            │
│  │  Auto-detection via  │                                                │
│  │  ParserRegistry      │                                                │
│  └──────────┬──────────┘                                                │
│             │                                                            │
│             ▼                                                            │
│  ┌─────────────────────┐                                                │
│  │  CLASSIFICATION      │  Tier 1: Regex (18 patterns, ~1.0 conf)       │
│  │  PIPELINE            │  Tier 2: BERT + LogReg (MiniLM-L6-v2)        │
│  │  (classifiers/)      │  Tier 3: LLM (GPT-4o / Claude API)           │
│  │                      │                                                │
│  │  Chain of            │  Each tier either classifies or declines,     │
│  │  Responsibility      │  cascading to the next tier.                  │
│  └──────────┬──────────┘                                                │
│             │                                                            │
│             ▼                                                            │
│  ┌─────────────────────┐                                                │
│  │  ANALYSIS ENGINE     │  Sub-modules:                                  │
│  │  (analyzers/)        │  • EventExtractor   — security event ID       │
│  │                      │  • RootCauseAnalyzer — probable cause          │
│  │  Facade Pattern:     │  • MitreMapper       — ATT&CK technique map   │
│  │  SecurityAnalyzer    │  • RecommendationEngine — actionable advice   │
│  │  orchestrates all    │  • IPAnalyzer        — frequency/suspicious   │
│  │  sub-analyzers       │  • URLAnalyzer       — attack pattern detect  │
│  │                      │  • TimeAnalyzer      — distribution analysis  │
│  └──────────┬──────────┘                                                │
│             │                                                            │
│             ▼                                                            │
│  ┌─────────────────────┐                                                │
│  │  PRESENTATION LAYER  │  • FastAPI REST API (v1)                      │
│  │  (api/, cli/)        │  • Web dashboard (Bootstrap)                  │
│  │                      │  • CLI (argparse)                              │
│  │  Security:           │  • Auth middleware (Bearer token)              │
│  │  Rate limiting,      │  • Rate limiting (per-IP sliding window)      │
│  │  Input validation    │  • Request size limits                        │
│  └─────────────────────┘                                                │
│                                                                          │
│  ┌─────────────────────┐                                                │
│  │  EVALUATION LAYER    │  • Benchmark harness (multi-model comparison) │
│  │  (evaluation/)       │  • Metrics: P/R/F1/Accuracy per class         │
│  │                      │  • Dataset loaders (synthetic, HDFS)           │
│  │                      │  • Cross-validation training                   │
│  └─────────────────────┘                                                │
└─────────────────────────────────────────────────────────────────────────┘
```

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Single Responsibility** | Each analyzer (IP, URL, MITRE, etc.) is its own module |
| **Open/Closed** | New parsers/classifiers added without modifying existing code |
| **Liskov Substitution** | All parsers implement `LogParser` ABC; all classifiers implement `Classifier` ABC |
| **Interface Segregation** | `Classifier` and `EntityExtractor` are separate protocols |
| **Dependency Inversion** | `ClassificationPipeline` accepts abstract `Classifier` list, not concrete classes |
| **Strategy Pattern** | Parsers selected at runtime based on log format detection |
| **Chain of Responsibility** | Classification cascade: Regex → BERT → LLM |
| **Facade Pattern** | `SecurityAnalyzer` composes 7 sub-analyzers behind a single `analyze()` call |

## Data Flow

```
Raw Log → Parser (auto-detect) → Structured Dict → ClassificationResult
  → SecurityEvent (if security-relevant) → MITRE Mapping → Root Cause
  → Recommendation → AnalysisResult (JSON output)
```

## MITRE ATT&CK Coverage

| Attack Type | Technique ID | Tactic |
|-------------|-------------|--------|
| Brute Force | T1110 | Credential Access |
| SQL Injection | T1190 | Initial Access |
| XSS | T1189 | Initial Access |
| Command Injection | T1059 | Execution |
| Path Traversal | T1083 | Discovery |
| Privilege Escalation | T1068 | Privilege Escalation |
| Denial of Service | T1499 | Impact |
| Enumeration | T1046 | Discovery |
| Malware | T1204 | Execution |
| Information Disclosure | T1005 | Collection |
