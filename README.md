# SentinelLLM
## Adaptive Security Gateway for RAG-Based LLM Applications
SentinelLLM is an experimental security gateway designed to protect Retrieval-Augmented Generation (RAG) applications from prompt injection, jailbreak attempts, malicious retrieved content, and unsafe model outputs.
The project investigates whether **adaptive, risk-tiered security analysis** can reduce unnecessary security-analysis overhead while maintaining strong security performance and avoiding excessive false positives.
## Research Question
> Can SentinelLLM reduce unnecessary security-analysis overhead while maintaining competitive security performance and avoiding excessive false positives in a RAG-based application setting?
The project focuses on the security-efficiency trade-off of adaptive routing rather than claiming that adaptive routing itself is a new concept.
## Key Idea
Instead of applying the full security stack to every request, SentinelLLM estimates the risk of an interaction and assigns it to an appropriate security tier.

                    User Query
                        |
                        v
                  RAG Retrieval
                        |
                        v
                +----------------+
                | Routing Layer  |
                | Risk Analysis  |
                +-------+--------+
                        |
             +----------+----------+
             |          |          |
             v          v          v
          TIER 1     TIER 2     TIER 3
          Low Risk   Medium     High Risk
             |          |          |
             |          v          v
             |       Security   Advanced
             |        Checks     Analysis
             |          |          |
             +----------+----------+
                        |
                        v
                 ALLOW / BLOCK
                        |
                        v
                   LLM Generation
                        |
                        v
                  Output Scanner
                        |
                        v
                   Final Response

Architecture
SentinelLLM separates the system into a Routing Layer and a Security Layer.
Routing Layer
The Routing Layer answers:
How much security analysis should be performed?
It currently includes:
Rule-based risk scoring
Risk-tier assignment
Escalation decisions
Instruction-source trust levels
Security Layer
The Security Layer answers:
Is this interaction or content dangerous?
It currently includes:
Prompt-injection detection
Jailbreak detection
Instruction-hierarchy conflict checking
Output security scanning
Cumulative multi-turn risk analysis
Security Tiers
Tier 1 — Low Risk
Uses lightweight risk assessment.
Normal requests can continue without expensive security analysis.
Tier 2 — Medium Risk
Performs additional security analysis including:
Prompt-injection detection
Jailbreak detection
Instruction-hierarchy analysis
Tier 3 — High Risk
Provides the strongest analysis and includes:
Tier 2 security checks
Cumulative risk tracking
Risk decay across turns
Output security scanning
Instruction Trust Hierarchy
Retrieved RAG content is treated as untrusted.
The current prototype uses the following trust ordering:

SYSTEM       4
DEVELOPER    3
USER         2
RAG          1

This allows SentinelLLM to reason about conflicts between instructions originating from different sources.
For example, an instruction embedded inside a retrieved document should not automatically override higher-trust application instructions.

RAG Security
RAG is intentionally kept lightweight in this project.

The RAG layer provides:
A small local document corpus
Document loading
Source tagging
Lightweight retrieval

Malicious retrieved-document testing
A malicious document is included to test indirect prompt injection, where instructions are introduced through retrieved content rather than directly through the user's query.
RAG is treated primarily as the application threat surface, rather than the main research contribution.

Experimental Conditions
The project uses three controlled conditions.

Condition A — No Security
Security routing and security analysis are skipped.

Request
   |
   v
RAG
   |
   v
LLM
   |
   v
Response
This provides a baseline for attack success and normal application latency.

Condition B — Always-On
Every request receives the full security analysis.
This measures the security and computational cost of exhaustive security checking.

Condition C — SentinelLLM Adaptive

The routing layer decides which security tier should be applied to each request.
This measures the security-efficiency trade-off of adaptive security analysis.
The same evaluation cases are used across all three conditions.

Evaluation Metrics
The evaluation framework measures:

Metric	Purpose
Accuracy	Overall classification correctness
Precision	Proportion of blocked/flagged cases that are actually malicious
Recall	Proportion of attacks successfully detected
F1 Score	Balance between precision and recall
FPR	Legitimate requests incorrectly blocked
FNR	Attacks incorrectly allowed
ASR	Attacks that successfully bypass security
Average Latency	Request-to-response time
Security Calls	Number of security-analysis calls
LLM Calls	Number of model calls
Escalation Rate	Requests sent to higher security tiers
Security and efficiency are evaluated together because a system that simply blocks everything could appear secure while being unusable.

Multi-Turn Risk
SentinelLLM also includes a prototype cumulative-risk mechanism.
Previous suspicious behavior contributes to future risk, but its influence decreases over time.
Example:

Turn 1
Suspicious behavior
      |
      v
Risk = 0.50

Turn 2
Benign request
      |
      v
Historical risk decays

Turn 3
Additional suspicious behavior
      |
      v
Risk accumulates

Turn 4
Cumulative risk crosses threshold
      |
      v
BLOCK

This is intended to detect sequences where individual requests may appear ambiguous but become suspicious when considered together.

Current Implementation
The current prototype includes:

Python implementation
Local RAG corpus
Lightweight document retrieval
Rule-based risk scoring
Instruction trust hierarchy
Tier 1 / Tier 2 / Tier 3 routing
Prompt-injection detection
Jailbreak detection
Hierarchy conflict detection
Output scanning
Multi-turn cumulative risk
Risk decay
Local LLM integration through Ollama
A/B/C experimental harness
CSV/JSON evaluation datasets
Automated metric calculation
Latency measurement
Unit and integration tests

Project Structure

SentinelLLM/
│
├── app/
│   ├── llm.py
│   ├── main.py
│   │
│   ├── rag/
│   │   ├── documents.py
│   │   ├── prompt.py
│   │   ├── retriever.py
│   │   └── corpus/
│   │
│   ├── routing/
│   │   ├── risk.py
│   │   ├── router.py
│   │   ├── tiers.py
│   │   ├── trust.py
│   │   └── llm_risk.py
│   │
│   └── security/
│       ├── injection.py
│       ├── jailbreak.py
│       ├── hierarchy.py
│       ├── tier2.py
│       └── tier3.py
│
├── evaluation/
│   ├── dataset.csv
│   ├── dataset.json
│   ├── metrics.py
│   ├── runner.py
│   └── run_experiment.py
│
├── tests/
│   ├── test_router.py
│   ├── test_security.py
│   ├── test_tier3.py
│   ├── test_cumulative_risk.py
│   ├── test_multiturn.py
│   └── ...
│
├── config.yaml
├── requirements.txt
├── .gitignore
└── README.md

Requirements
Python 3.x
Ollama
A local LLM compatible with Ollama
Python packages listed in requirements.txt

The current development setup uses a small local model so that experiments can be performed without relying on paid model APIs.

Installation
Clone the repository:
git clone https://github.com/ArjunG07/Sentinel-LLM.git
cd Sentinel-LLM

Create a virtual environment:
Windows
python -m venv .venv
.venv\Scripts\activate

Install dependencies:
pip install -r requirements.txt
Make sure Ollama is installed and the configured local model is available.

Running Tests
Run individual tests using Python modules:

python -m tests.test_router
python -m tests.test_security
python -m tests.test_tier3

Test cumulative multi-turn risk:
python -m tests.test_cumulative_risk
Test the integrated multi-turn pipeline:

python -m tests.test_multiturn_pipeline
Running the Evaluation

Run the A/B/C experiment:
python evaluation\runner.py

Then calculate the metrics:
python -m evaluation.metrics

The evaluation produces structured results that can be used for further analysis of security performance, latency, security-analysis calls, and escalation behavior.

Research Status
This repository contains an experimental research prototype.
The system has demonstrated:

Working RAG retrieval
Adaptive risk routing
Security-tier escalation
Detection of malicious retrieved content
Output security scanning
Multi-turn cumulative-risk behavior
Controlled A/B/C evaluation

The current evaluation should be interpreted as a feasibility study, not as evidence of universal security effectiveness.

Further work is required to:

Expand and freeze the evaluation dataset
Separate development and final evaluation data
Perform broader attack evaluation
Tune thresholds using the research protocol
Perform failure analysis
Evaluate false-positive behavior at larger scale
Compare security-analysis overhead more thoroughly
Improve reproducibility and reporting
Limitations

Current limitations include:

Small local evaluation environment
Lightweight RAG corpus
Keyword-based retrieval
Rule-based prototype risk scoring
Limited attack diversity
Limited multi-turn attack coverage
Dependence on the selected local LLM
Simplified security detectors
Controlled output-attack testing
Local hardware latency measurements

The adaptive routing mechanism itself is not presented as a novel routing algorithm. The research focus is the experimentally measured security-efficiency trade-off when adaptive routing is applied to a RAG-based threat surface.

Future Work
Potential future extensions include:

Larger RAG security datasets
Stronger indirect-injection attacks
More realistic multi-turn attacks
Improved risk models
Tool-use security
Agentic-system evaluation
Multimodal attack detection
Larger-scale benchmarking
Cloud deployment
Tamper-evident or blockchain-based audit logging
Research Focus

SentinelLLM focuses on three central questions:
Can adaptive security routing reduce unnecessary security-analysis overhead?
Can it maintain competitive attack-detection performance?
Can it do so without introducing excessive false positives?

The project therefore evaluates security, efficiency, and false-positive behavior together rather than optimizing for attack blocking alone.

Disclaimer

SentinelLLM is an academic research prototype and is not intended to provide production-grade security guarantees.

Results depend on the evaluation dataset, model, thresholds, hardware, and experimental configuration.

License
License information will be added as the project is finalized.
