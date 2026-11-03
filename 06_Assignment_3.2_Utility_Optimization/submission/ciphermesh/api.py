"""Optional local REST API for app integration."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .agent import CipherMeshAgent
from .models import AgentState
from .gateway import prepare_request

app = FastAPI(title="CipherMesh Privacy Gateway", version="0.1.0")
agent = CipherMeshAgent("Agent-Local")


class InspectRequest(BaseModel):
    text: str
    provider: str = "local"


@app.get("/health")
def health():
    return {"status": "ok", "agent_id": agent.state.agent_id, "policy_version": agent.state.policy_version}


@app.get("/state")
def state():
    return agent.safe_state_payload()


@app.post("/inspect")
def inspect(request: InspectRequest):
    if request.provider not in agent.state.provider_allowlist:
        raise HTTPException(status_code=403, detail="provider is not allowlisted")
    result = agent.inspect(request.text)
    return result.model_dump(mode="json")


@app.post("/gateway/prepare")
def gateway_prepare(request: InspectRequest):
    """Return a provider-ready decision; this endpoint does not call an LLM."""
    prepared = prepare_request(request.text, request.provider, agent.state)
    return {
        "provider": prepared.provider,
        "decision": prepared.inspection.decision.value,
        "findings": [f.model_dump(mode="json") for f in prepared.inspection.findings],
        "reasons": prepared.inspection.reasons,
        "forwardable": prepared.forwardable,
        "content_for_provider": prepared.content_for_provider,
        "note": prepared.note,
        "policy_version": prepared.inspection.policy_version,
    }
