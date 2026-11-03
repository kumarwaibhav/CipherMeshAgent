"""Run the Assignment 5.1 breach simulation and write the runtime/audit/summary logs.

Author: Kumar Waibhav Akshat (RA2212704010027).
Usage (from the deliverable root):  python demo/run_breach_simulation.py
Prerequisite: python -m ciphermesh.trust.provision
"""
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # source-only release: no __pycache__ under ciphermesh/ (see integrity.py)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ciphermesh.trust.attack_sim import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
