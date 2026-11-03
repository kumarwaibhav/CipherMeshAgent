# CipherMesh - Assignment 1.2

**Student:** Kumar Waibhav Akshat  
**Register No.:** RA2212704010027  
**Programme:** M.Tech Integrated - CSE Data Science  
**Section:** AG1

CipherMesh is a simple reflex privacy agent that inspects each LLM request before it can reach AWS Bedrock, Azure AI, GCP Vertex AI, or a local Ollama model. It detects synthetic examples of cloud credentials, API tokens, personal information, IP addresses, and internal URLs, then applies a highest-risk-wins policy: **ALLOW, REDACT, REVIEW, or BLOCK**.

## Run for free

```text
python ciphermesh_agent.py
```

The prototype uses only the Python standard library, requires no cloud account or paid API, and never transmits data. All included credentials are intentionally invalid examples.

## Files

- `ciphermesh_agent.py` - fully commented executable rule engine.
- `mock_llm_requests.jsonl` - mocked real-time multi-provider request stream.
- `execution_log.txt` - captured successful execution.

## Production evolution

Wrap the rule engine in FastAPI as an OpenAI-compatible gateway; add Microsoft Presidio for contextual PII recognition; use provider adapters for Bedrock, Azure AI and Vertex AI; use Ollama for free local inference; add encrypted policies, authentication, rate limits, immutable privacy-safe audit events, metrics, tests, Docker, and Kubernetes manifests. Cloud forwarding remains optional: the full protection and local-model demonstration works without paid services.
