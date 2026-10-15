# ADR-001: Technology stack

**Status:** Accepted (M0, approved with development plan)

## Decision
Python 3.12 + FastAPI + Pydantic v2 (backend); React + TypeScript + Vite (UI).

## Context
Greenfield repo. Blueprint section 5/F.5 recommends React+TS+Vite when no UI exists; adapters need strong parsing/tooling ecosystems (nmap XML, SCAP, Prowler JSON).

## Consequences
Backend contracts are Pydantic models exported as JSON Schema; UI types are generated from them (schema-drift check in CI). Two languages to maintain.

## Alternatives considered
All-TypeScript: one language, weaker security-tooling ecosystem.
