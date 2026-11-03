# CipherMesh v3.0 capstone video: narration script

Kumar Waibhav Akshat (RA2212704010027) · 21CSE525T Agent Technology · SRM Institute of Science and Technology

Video: `video/CipherMesh_Capstone_Lifecycle.mp4` (3:05, 1920×1080, 30 fps, silent with burned-in captions).
Read this script aloud over the video, or record it as a voice-over track. At a calm pace (about 140 words per
minute) each block fits its time window. The dashboard footage is a real recording of the run in `logs/`.

| Time | On screen | Say |
|---|---|---|
| 0:00–0:08 | Title card | "This is CipherMesh version three, my capstone for Agent Technology. It joins everything I built in Units one to five into one secure agent platform." |
| 0:08–0:22 | The problem | "Companies send prompts to AI models all day. Those prompts can contain API keys, Aadhaar and PAN numbers, phone numbers and internal links. CipherMesh checks every prompt before it leaves. The capstone question is: can the five separate units run together, on their own, across more than one host, and stay safe?" |
| 0:22–0:40 | Architecture schematic | "Each AgentHost stacks all five units. Unit five is the trust gate: every inbound command is checked at thirteen Ed25519 checkpoints before it is parsed. Unit two gives the worker pool and the TCP listener. Unit one is the reflex policy. Unit four turns live feeds into beliefs and runs a BDI deliberation for every request. Unit three negotiates provider contracts, routes by utility and shares load. Two gateways, a security console and an attacker talk over real TCP." |
| 0:40–0:46 | Lifecycle card | "One command runs all seven phases with no manual step. This is the live ops dashboard during that run." |
| 0:46–0:50 | P0 on the dashboard | "Phase zero: keys are created, and both gateways prove their own code matches the signed release." |
| 0:50–0:58 | P1 | "Phase one: six real public feeds are fetched. The threat posture becomes elevated, the rupee budget is converted at the live rate, and the prompt size limit is tightened. Beta learns these beliefs from alpha's signed heartbeats." |
| 0:58–1:28 | P2 | "Phase two: forty enterprise prompts go through alpha's worker pool. Watch the current intention panel: every request gets its own intention with step progress. Secrets are blocked, personal data is masked, internal links wait for a human, and Aadhaar data is only sent to Indian or local providers." |
| 1:28–1:35 | P3 | "Phase three: a burst fills alpha's queue. Alpha announces each task, beta bids, alpha awards it, and beta returns a signed result. Blocked and review prompts never leave alpha." |
| 1:35–1:49 | P4 | "Phase four: GCP Vertex fails in the middle of a plan. The belief changes, the running intention is dropped and re-planned to a safe provider, and the circuit breaker opens. A clearly labelled what-if replay of the Azure status feed takes Azure down too, and beta learns the outage from alpha." |
| 1:49–2:08 | P5 | "Phase five: the security console sends signed admin commands, and they are accepted. Then the attacker sends eighteen hostile frames: forged signatures, a replay, a tampered payload, an oversized frame, a stolen peer key asking for admin rights, and a brute-force run. Every one is blocked at the expected checkpoint, and the engine state does not change." |
| 2:08–2:26 | P6 | "Phase six: a lockdown drill. While it is active every prompt is blocked and nothing is sent. The console releases it, both gateways drain gracefully, and the evidence ledgers verify." |
| 2:26–2:43 | Breach card and zoom | "Here is the security event stream up close: each blocked command with the checkpoint that stopped it, from C1 to C13, and the lockout gate L0." |
| 2:43–2:57 | Results card | "In this recorded run: eighty-two requests, ten tasks shared with the peer, an intention shift after a provider outage, and eighteen out of eighteen attacks blocked." |
| 2:57–3:05 | Close | "CipherMesh: protect every prompt, across every model, before data leaves. The code, logs and report are in the repository. Thank you." |

Numbers on screen and in this script come from `logs/production_summary.json` of the recorded run.
