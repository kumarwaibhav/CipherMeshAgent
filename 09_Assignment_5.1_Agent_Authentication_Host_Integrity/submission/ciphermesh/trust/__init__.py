"""CipherMesh trust layer: agent authentication and host integrity verification (Assignment 5.1).

Author: Kumar Waibhav Akshat (RA2212704010027).

Public API (stable; imported by the Capstone 5.2 build):

* keys       - :class:`SigningIdentity`, :class:`TrustStore`, PEM helpers
* envelope   - :func:`create_command`, :func:`sign`, :func:`parse_and_verify`, :class:`SignedCommand`
* verifier   - :class:`CommandVerifier`, :class:`Verdict`, :class:`Origin`, ``CHECKPOINTS``
* integrity  - :func:`build_manifest`, :func:`sign_manifest`, :func:`self_attest`, :func:`measure`
* agent      - :class:`SecureCipherMeshAgent`, :class:`SystemCommandChannel`
* server     - :func:`serve`, :class:`BackgroundServer`; client - :class:`SecureClient`
"""
from .canonical import canonicalize, strict_loads
from .client import ClientReply, SecureClient, verify_reply
from .envelope import (COMMAND_CONTEXT, REPLY_CONTEXT, EnvelopeError, SignedCommand, create_command, encode,
                       parse, parse_and_verify, sign)
from .integrity import (IntegrityError, IntegrityReport, build_manifest, measure, self_attest, sign_manifest,
                        verify_manifest_signature)
from .keys import SigningIdentity, TrustStore, TrustStoreError
from .secure_agent import AgentConfig, HandleResult, SecureCipherMeshAgent, SystemCommandChannel
from .secure_server import BackgroundServer, serve
from .verifier import CHECKPOINTS, CommandVerifier, FailureLimiter, Origin, ReplayCache, Verdict

__all__ = [
    "canonicalize", "strict_loads", "ClientReply", "SecureClient", "verify_reply", "COMMAND_CONTEXT",
    "REPLY_CONTEXT", "EnvelopeError", "SignedCommand", "create_command", "encode", "parse", "parse_and_verify",
    "sign", "IntegrityError", "IntegrityReport", "build_manifest", "measure", "self_attest", "sign_manifest",
    "verify_manifest_signature", "SigningIdentity", "TrustStore", "TrustStoreError", "AgentConfig",
    "HandleResult", "SecureCipherMeshAgent", "SystemCommandChannel", "BackgroundServer", "serve", "CHECKPOINTS",
    "CommandVerifier", "FailureLimiter", "Origin", "ReplayCache", "Verdict",
]
