# SentinelLLM

## Adaptive Security Gateway for RAG-Based LLM Applications

SentinelLLM is a middleware security gateway designed to sit between a user/application and an LLM platform.

Its purpose is to evaluate the security risk of incoming requests and retrieved RAG content, select an appropriate security tier, and scan approved model outputs for potential information leakage.

```text
USER
  |
  v
SentinelLLM Security Gateway
  |
  +--> Risk Routing
  |      |
  |      +--> Tier 1: Low-risk path
  |      +--> Tier 2: Full security checks
  |      +--> Tier 3: Cumulative/session risk + output security
  |
  +--> RAG Retrieval + Document Security Analysis
  |
  v
LLM Platform
  |
  v
SentinelLLM Output Scanner
  |
  v
USER
```

> **Research note:** SentinelLLM does not claim that adaptive security routing itself is novel. The project experimentally evaluates adaptive risk-tiering in a RAG setting and compares it with a no-input-security baseline and an always-on security configuration.

---

## Research Question

The project investigates whether adaptive risk-tiering can provide a useful security-efficiency trade-off when the threat surface includes **untrusted RAG-retrieved content**, rather than only user prompts or agent tool-call trajectories.

A second focus is whether an explicit **instruction-hierarchy trust model** improves risk assessment and explainability.

The three experimental conditions are:

| Condition | Description |
|---|---|
| **A — No Security** | No input security routing/scanning. A common downstream output scanner is retained. |
| **B — Always-On** | Security analysis is applied to every applicable request and retrieved document. |
| **C — Adaptive** | SentinelLLM selects the security tier according to estimated risk and session context. |

---

## Core Architecture

### 1. Risk Routing

The routing layer determines **how much security analysis is required**.

Risk is derived from deterministic security signals and, when appropriate, an LLM-based risk classifier.

The final routing risk is conservative:

```text
final risk = max(rule risk, LLM risk)
```

This prevents an LLM risk estimate from downgrading a higher deterministic risk.

Risk tiers:

```text
Risk < 0.30       -> TIER_1
0.30 <= Risk < 0.70 -> TIER_2
Risk >= 0.70      -> TIER_3
```

### 2. Instruction Hierarchy

SentinelLLM models trust according to:

```text
System > Developer > User > RAG / Third-party content
```

RAG content is treated as lower-trust content. A lower-trust instruction that attempts to conflict with higher-priority instructions can increase routing risk.

### 3. Security Tiers

#### Tier 1

A lightweight risk check is used for low-risk requests. Requests that exceed the Tier 1 threshold can be escalated.

#### Tier 2

Performs security checks including:

- Direct prompt injection
- Jailbreak indicators
- Instruction-hierarchy conflicts
- Sensitive-information requests
- Harmful cyber requests

A detected security violation results in `BLOCK`.

#### Tier 3

Adds:

- Decayed cumulative session risk
- A cumulative-risk threshold
- Output leakage scanning

This allows repeated risky activity across a session to influence the security decision.

### 4. RAG Security

Retrieved documents are treated as untrusted input.

```text
User query
   |
   v
RAG retrieval
   |
   +--> Route/risk-score retrieved documents
   |
   +--> Apply security analysis where required
   |
   v
Safe context
   |
   v
Application LLM
```

This is intended to detect **indirect prompt injection**, where malicious instructions are embedded in retrieved content rather than directly supplied by the user.

### 5. Output Security

Approved requests that reach the application LLM are followed by a common output scanner.

The scanner checks for explicit leakage patterns such as:

- System prompt disclosure
- Developer instruction disclosure
- API keys
- Secret keys
- Passwords
- Confidential information

---

## Technology Stack

- **Python 3.11**
- **Ollama**
- **Qwen 2.5 3B**
- Requests
- PyYAML
- pytest
- CSV-based evaluation datasets
- RAG text corpus

The experimental LLM endpoint is:

```text
http://localhost:11434/api/generate
```

The default model is:

```text
qwen2.5:3b
```

---

## Project Structure

```text
EDI-LLM/
│
├── app/
│   ├── llm.py
│   ├── llm/
│   │   └── client.py
│   ├── main.py
│   ├── launcher.py
│   ├── gateway.py
│   │
│   ├── routing/
│   │   ├── llm_risk.py
│   │   ├── risk.py
│   │   ├── router.py
│   │   ├── session.py
│   │   ├── tiers.py
│   │   └── trust.py
│   │
│   ├── security/
│   │   ├── hierarchy.py
│   │   ├── injection.py
│   │   ├── jailbreak.py
│   │   ├── output_scanner.py
│   │   ├── sensitive.py
│   │   ├── tier1.py
│   │   ├── tier2.py
│   │   └── tier3.py
│   │
│   └── rag/
│       ├── documents.py
│       ├── prompt.py
│       ├── retriever.py
│       └── corpus/
│
├── evaluation/
│   ├── dataset.csv
│   ├── dataset.json
│   ├── dataset_dev.csv
│   ├── dataset_eval.csv
│   ├── metrics.py
│   ├── runner.py
│   ├── analyze_results.py
│   ├── generate_graphs.py
│   └── ...
│
├── tests/
│   ├── test_condition_a.py
│   ├── test_condition_b.py
│   ├── test_condition_c.py
│   └── ...
│
├── config.yaml
├── requirements.txt
└── README.md
```

---

# Installation

## 1. Clone or extract the project

Open the project folder in VS Code.

Example:

```powershell
cd C:\Users\<username>\path\to\EDI-LLM
```

## 2. Create a virtual environment

```powershell
python -m venv .venv
```

If PowerShell blocks activation, you do **not** need to change the Windows execution policy.

You can run the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Alternatively, from Command Prompt:

```cmd
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

Install pytest if it is not included:

```powershell
python -m pip install pytest
```

---

# Ollama Setup

Install Ollama and make sure the required model is available.

Check installed models:

```powershell
ollama list
```

You should see:

```text
qwen2.5:3b
```

If it is missing:

```powershell
ollama pull qwen2.5:3b
```

Test the model:

```powershell
ollama run qwen2.5:3b
```

Then ask:

```text
Reply with exactly: OK
```

Exit with:

```text
/bye
```

---

# Running SentinelLLM

Run the main application:

```powershell
python -m app.main
```

If the project provides the launcher interface, it can also be started with:

```powershell
python -m app.launcher
```

Use the menu-driven interface to access the available demonstrations and research functionality.

---

# Running the Formal Evaluation

The formal evaluation uses:

```text
evaluation/dataset_eval.csv
```

Run:

```powershell
python -m evaluation.runner
```

The runner evaluates all three conditions:

```text
A — No Security
B — Always-On Security
C — SentinelLLM Adaptive Security
```

The evaluation reports:

- Attack Detection Rate (ADR)
- False Positive Rate (FPR)
- False Negative Rate (FNR)
- Precision
- Recall
- F1 Score
- Attack Success Rate (ASR)
- Average latency
- Security calls
- Risk LLM calls
- Application LLM calls
- Total LLM calls
- Output scans
- Escalation rate

---

# Current Evaluation Dataset

The current formal evaluation contains **18 cases**:

```text
10 attack/malicious cases
8 benign cases
```

The attack categories include:

- Direct injection
- Indirect injection through malicious RAG content
- Jailbreak attempts
- Output attacks
- Sensitive-information requests

The dataset is kept separate from development/pilot data.

> The current dataset is intentionally small and should not be treated as sufficient evidence for broad generalization.

---

# Baseline Evaluation Results

The current frozen evaluation produced:

| Metric | A — No Security | B — Always-On | C — Adaptive |
|---|---:|---:|---:|
| Attack Detection Rate | 20.0% | 80.0% | 90.0% |
| False Positive Rate | 0.0% | 37.5% | 25.0% |
| False Negative Rate | 80.0% | 20.0% | 10.0% |
| Precision | 100.0% | 72.7% | 81.8% |
| Recall | 20.0% | 80.0% | 90.0% |
| F1 Score | 33.3% | 76.2% | 85.7% |
| Attack Success Rate | 80.0% | 20.0% | 10.0% |
| Avg. Latency | 11.37 s | 6.02 s | 17.09 s |
| Security Calls | 0 | 31 | 12 |
| Risk LLM Calls | 0 | 0 | 12 |
| Application LLM Calls | 18 | 7 | 7 |
| Total LLM Calls | 18 | 7 | 19 |
| Output Scans | 18 | 7 | 7 |
| Escalation Rate | N/A | N/A | 66.7% |

These figures are from the current 18-case evaluation and should be interpreted as **experimental results for this implementation and dataset**, not as general performance guarantees.

An important observation is that Condition C performs fewer explicit security calls than Condition B, but its LLM-based risk classification introduces additional model calls. Therefore, reducing security calls does **not** automatically mean reducing total computational cost or latency.

---

# Research Metrics

### Attack Detection Rate

The proportion of attack/malicious cases correctly blocked.

### False Positive Rate

The proportion of benign cases incorrectly blocked.

### False Negative Rate

The proportion of attack/malicious cases incorrectly allowed.

### Precision

The proportion of blocked cases that were actually attacks/malicious cases.

### Recall

The proportion of attacks/malicious cases that were correctly blocked.

### F1

The harmonic mean of precision and recall.

### Attack Success Rate

The proportion of attack/malicious cases that reached an allowed outcome.

### Latency

Measured end-to-end for each condition.

### LLM Call Counts

Separated into:

```text
Risk LLM Calls
Application LLM Calls
Total LLM Calls
```

This distinction is important because the adaptive architecture may introduce risk-classification calls even when it prevents an application-model call.

---

# Adaptive Session Risk

Condition C maintains session risk using decayed historical risk.

Conceptually:

```text
Current request
      |
      v
Current risk
      |
      +---- historical risk
      |       |
      |       v
      |   decay factor
      |       |
      v       v
    cumulative risk
          |
          v
      Tier 3 decision
```

Current parameters:

```text
RISK_DECAY = 0.70
CUMULATIVE_RISK_THRESHOLD = 0.70
```

This allows repeated risky requests across a session to contribute to a session-level security decision without treating every historical event as equally important.

---

# Testing

The project contains both:

1. **pytest-style tests**
2. **script-style test files**

Some files under `tests/` execute demonstrations directly rather than defining pytest test functions. Therefore, running:

```powershell
python -m pytest -q
```

does **not currently represent the complete validation of every test script**.

Individual script-style tests can be executed from the project root using:

```powershell
python -m tests.test_cumulative_risk
```

and:

```powershell
python -m tests.test_tier3
```

For the research experiment, the primary end-to-end validation is:

```powershell
python -m evaluation.runner
```

which evaluates all 18 formal evaluation cases across Conditions A, B, and C.

---

# Development and Evaluation Workflow

For reproducibility, keep the research baseline separate from experimental optimization.

Recommended workflow:

```text
Current working implementation
        |
        v
Git commit
        |
        v
Run formal evaluation
        |
        v
Record baseline
        |
        v
Make optimization
        |
        v
Run tests
        |
        v
Run the same evaluation dataset
        |
        v
Compare case-by-case
```

Do not change thresholds, risk weights, datasets, or routing behavior solely to improve evaluation metrics.

If research-sensitive behavior changes, the resulting evaluation should be treated as a new experimental version.

---

# Research Limitations

The current implementation has several limitations:

1. The formal evaluation dataset contains only 18 cases.
2. Attack examples are benchmark-derived rather than generated by an adaptive attacker.
3. Conditions B and C share the underlying security detectors.
4. Evaluation uses one RAG stack and one experimental local model.
5. The current study does not establish performance across multiple LLMs.
6. Latency is strongly affected by the local CPU-bound Qwen deployment.
7. The current study does not establish generalization to production-scale workloads.

These limitations should be considered when interpreting the results.

---

# Future Work

Potential extensions include:

- Larger evaluation datasets
- Adaptive-attacker testing
- Threshold sensitivity experiments
- Ablation studies
- Multiple local and hosted LLMs
- Broader RAG document sources
- Tool-call trajectory evaluation
- Statistical significance analysis
- More sophisticated document trust scoring
- Improved latency optimization
- More robust output-leakage detection

---

# Project Status

SentinelLLM currently provides:

- Adaptive risk routing
- Three security tiers
- Instruction-hierarchy trust modelling
- Session-level cumulative risk
- RAG document security analysis
- Indirect prompt-injection detection
- Output leakage scanning
- A/B/C experimental evaluation
- Security and efficiency metrics
- Local Ollama/Qwen integration

The current implementation is a **student research prototype** intended for controlled experimentation and demonstration rather than production deployment.

---

# License

This project is intended for academic and research use.

Add the appropriate license here if the repository is later released under a specific open-source license.