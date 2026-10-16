"""Bounded LLM gateway (ADR-009/018): optional, local-only, no tools, output is a candidate.

Nothing in this package can reach a network host other than the configured loopback endpoint, and
nothing a model returns is used until ``validator.validate_narrative`` and Agent 7 accept it.
"""
