"""Bounded LLM gateway (ADR-009/018/020): optional, no tools, output is a candidate.

The model is either a local runtime on loopback (default) or, when explicitly configured and
approved, an Astra / Azure OpenAI deployment over https (ADR-020). Nothing in this package can reach
any other host, and nothing a model returns is used until ``validator.validate_narrative`` and
Agent 7 accept it.
"""
