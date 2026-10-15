# ADR-010: Graph storage

**Status:** Accepted (M0, approved with development plan)

## Decision
Relational edge tables in PostgreSQL; edges typed OBSERVED/CONFIGURED/INFERRED with source, confidence, timestamp. No graph database.

## Context
Blueprint Appendix C/D.3 defers graph DB until query evidence justifies it.

## Consequences
Recursive CTE queries for path-style questions; revisit with measured needs.

## Alternatives considered
Neo4j-style graph DB.
