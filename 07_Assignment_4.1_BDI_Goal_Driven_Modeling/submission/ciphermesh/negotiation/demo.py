"""Run a reproducible multi-agent Contract-Net-inspired negotiation timeline."""
from __future__ import annotations

import argparse
from pathlib import Path

from .agents import InspectionCapacitySupplierAgent, WorkloadBuyerAgent
from .models import NegotiationStatus
from .protocol import ContractNetNegotiator


def money(value):
    return f"${value:,.2f}" if isinstance(value, (int, float)) else "n/a"


def render_timeline(result, buyer_id: str = "WORKLOAD_BUYER",
                    supplier_id: str = "INSPECTION_SUPPLIER") -> str:
    lines = [
        "CIPHERMESH MULTI-AGENT COORDINATION / CONTRACT-NET-INSPIRED DEMO",
        "=" * 78,
        f"Negotiation ID : {result.negotiation_id}",
        f"Participants  : {buyer_id} <-> {supplier_id}",
        "Transport     : JSON serialize/validate round-trip (local deterministic message bus)",
        f"Completed rounds: {result.rounds_completed}",
        "-" * 78,
        "EXECUTION TIMELINE (each TX has a typed request and a validated typed response)",
        "-" * 78,
    ]
    for event in result.timeline:
        direction = f"{event.sender} -> {event.recipient}"
        bytes_text = f"{event.message_bytes} B" if event.message_bytes else "local"
        lines.append(f"[{event.sequence:02d} | turn {event.turn:02d}] {direction:<48} {event.stage:<22} {bytes_text}")
        if event.summary:
            lines.append(f"     {event.summary}")
    lines.extend(["-" * 78, "FINAL RESULT", "-" * 78,
                  f"Status         : {result.status.value}",
                  f"Rounds         : {result.rounds_completed}",
                  f"Wire messages : {result.message_count}",
                  f"Timeline events: {len(result.timeline)}"])
    if result.agreed_terms:
        terms = result.agreed_terms
        lines.extend([
            f"Agreed price   : {money(terms.price_per_1000_requests)} per 1,000 requests",
            f"Service profile: capacity={terms.capacity_rps} req/s | p95={terms.p95_latency_ms:.1f} ms | estimated recall={terms.estimated_recall:.1%}",
            f"Buyer utility  : {result.buyer_utility:.2f}/100 (reservation >= 40)",
            f"Supplier utility: {result.supplier_utility:.2f}/100 (reservation >= 40)",
            f"Contract digest: {result.contract_digest}",
        ])
    lines.append(f"Termination    : {result.termination_reason}")
    if result.notes:
        lines.append("Notes          : " + " | ".join(result.notes))
    lines.append("\nNOTE: service metrics are synthetic, configured demo assumptions - not empirical benchmarks.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="CipherMesh multi-agent Contract-Net-inspired negotiation demo")
    parser.add_argument("--max-rounds", type=int, default=8)
    parser.add_argument("--buyer-max-price", type=float, default=180.0,
                        help="Set low (for example 120) to demonstrate bounded no-consensus termination")
    parser.add_argument("--json-out", type=Path, help="Optional path to export result/timeline as JSON")
    parser.add_argument("--quiet-timeline", action="store_true", help="Print only the final result")
    args = parser.parse_args(argv)
    buyer = WorkloadBuyerAgent(max_price=args.buyer_max_price)
    supplier = InspectionCapacitySupplierAgent()
    result = ContractNetNegotiator(buyer=buyer, supplier=supplier, max_rounds=args.max_rounds).run()
    print(f"status={result.status.value}; rounds={result.rounds_completed}; reason={result.termination_reason}"
          if args.quiet_timeline else render_timeline(result))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nTimeline JSON written to: {args.json_out}")
    if result.status != NegotiationStatus.AGREED:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
