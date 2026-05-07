# Architecture

## Overview

The project is built as a read-only audit pipeline with clear separation of
concerns:

- Bash acts as the Linux sensor
- PowerShell acts as the Windows sensor
- Python acts as the orchestrator, analysis engine, and reporting layer

## Data Flow

1. The platform sensor gathers evidence and writes structured output files.
2. Python loads the collected files or falls back to approved fallback sources.
3. Parsers and validators normalize the evidence into a consistent structure.
4. Correlation logic links identities, privileges, events, and policy data.
5. Anomaly detection and scoring convert the correlated model into findings.
6. Reporting writes text, JSON, and alert outputs.

## Separation of Concerns

The architecture keeps each layer focused on one responsibility:

- collectors only gather evidence
- parsers only read and validate files
- analysis modules only correlate and score
- reporting modules only write outputs
- utility modules provide shared helpers such as logging, paths, and safe exit

This separation keeps the tool easier to test, safer to maintain, and simpler
to explain in an audit context.
