"""Test-session set-up for the CipherMesh suite.

Author: Kumar Waibhav Akshat (RA2212704010027).
The release is source-only: self-attestation fails if bytecode caches exist under ciphermesh/,
so the test session must not write any (equivalent to PYTHONDONTWRITEBYTECODE=1).
"""
import sys

sys.dont_write_bytecode = True
