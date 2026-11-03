# CipherMesh — 21CSE525T Agent Technology

**The privacy control plane for enterprise AI.** Coursework repository for the AG1 Agent Technology course.

| | |
|---|---|
| Student | Kumar Waibhav Akshat (RA2212704010027) |
| Programme | M.Tech (Integrated) Computer Science and Engineering with specialization in Data Science |
| Guide | Dr. Prabhu Kavin B, Assistant Professor, Department of Data Science and Business Systems |
| Institution | SRM Institute of Science and Technology, Kattankulathur |
| Live console | https://ciphermesh-console.vercel.app |
| Live API docs | https://ciphermesh-api.vercel.app/docs |

CipherMesh is an autonomous agent that sits between a company's applications and AI models. It inspects every prompt before it leaves, hides or blocks private data, keeps Indian personal data in India, and routes the rest to the best allowed model. Each assignment below added one capability, and the capstone (5.2) brings them together into one platform.

---

## Assignments

| # | Assignment | What was delivered | Start here |
|---|---|---|---|
| 1.1 | Project Ideation, Environment Modeling and PEAS Matrix Definition | Design specification: domain, PEAS profile, agent vs. object-oriented contrast, environment classification | [`01_…/report`](01_Assignment_1.1_PEAS_Design_Specification/report/) |
| 1.2 | Rule-Based Environmental Reasoner Implementation | Condition–action reflex agent over a mock request stream, with an execution log | [`02_…`](02_Assignment_1.2_Rule_Based_Reasoner/) |
| 2.1 | Concurrent Task Daemonization using Threads and Workers | Worker pool, bounded queue, background monitor daemon, benchmark (7.6× throughput with 8 workers) | [`03_…`](03_Assignment_2.1_Concurrent_Task_Daemonization/) |
| 2.2 | Distributed Agent Messaging using Sockets/RPC | Two-terminal TCP messaging: Agent-A transfers typed state to Agent-B | [`04_…`](04_Assignment_2.2_Distributed_Agent_Messaging/) |
| 3.1 | Multi-Agent Coordination Protocol Execution | Contract-Net negotiation: multi-turn offers and a consensus handshake | [`05_…`](05_Assignment_3.1_Multi_Agent_Coordination/) |
| 3.2 | Self-Interested Agent Utility Optimization | Weighted utility function choosing the optimal option out of 10 (ECO-08, U = 71.24) | [`06_…`](06_Assignment_3.2_Utility_Optimization/) |
| 4.1 | Belief-Desire-Intention (BDI) Goal-Driven Modeling | BDI engine; 11 verification runs, 12 intention shifts; 188 tests | [`07_…`](07_Assignment_4.1_BDI_Goal_Driven_Modeling/) |
| 4.2 | Knowledge Representation and Adaptive API Integration | JSON-LD knowledge graph and 6 live public APIs that change agent behaviour; 242 tests | [`08_…`](08_Assignment_4.2_Knowledge_Representation_Adaptive_API/) |
| 5.1 | Agent Authentication and Host Integrity Verification | Ed25519-signed commands, 13 checkpoints, code self-attestation; 41/41 attacks blocked; 269 tests | [`09_…`](09_Assignment_5.1_Agent_Authentication_Host_Integrity/) |
| 5.2 | Capstone Project Consolidation and Secure Deployment | Unified platform run: 82 requests, 18/18 attacks blocked, 3-minute video, architecture schematic; 563 tests | [`10_…`](10_Assignment_5.2_Capstone_Secure_Deployment/) |
| — | Final review | 56-page project report and the review presentation | [`11_Final_Review`](11_Final_Review/) |

## Final review rubric → evidence

| Rubric area (2.5 marks each) | Where to see it |
|---|---|
| **Architecture & BDI integration**: layered consolidation, BDI data architecture, background daemons, knowledge representation / API integration | 5.2 architecture schematic and report; 4.1 BDI engine; 2.1 workers and daemons; 4.2 knowledge graph and live APIs |
| **Autonomous execution & optimization**: sensory input, utility function, dynamic re-planning, no human intervention | 3.2 utility function; 4.1 intention shifts; 5.2 production cycle log (one command, phases P0–P6) |
| **Multi-agent coordination & security**: socket/RPC messaging, multi-turn negotiation with consensus handshake, cryptographic verification | 2.2 TCP messaging; 3.1 negotiation timeline; 5.1 breach simulation logs |
| **System UI & documentation**: live dashboard, architecture schematic, full lifecycle presentation | 5.2 dashboard snapshots, schematic, lifecycle video; final review presentation |

## Repository layout

Each assignment folder contains:

- `README.md`: what the assignment asked for, what was delivered and where the evidence is.
- `submission/`: the files as submitted (code, tests, logs, report).
- `report/`: the standalone report, where one was submitted separately.

For the capstone (5.2), this repository holds the report, logs, schematic, dashboard captures and video. The unified product source is maintained privately and can be demonstrated live on request.

## Ownership

© 2026 Kumar Waibhav Akshat. All rights reserved. See [`LICENSE`](LICENSE). Shared for academic evaluation only.
