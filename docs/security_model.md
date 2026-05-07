# Security Model

## Read-Only First

The tool is designed to inspect evidence, not to change it. This reduces risk
and keeps the workflow suitable for audit and teaching use.

## Least Privilege

The sensors should only run with the permissions they need to read local data.
If a source cannot be read safely, the application logs the issue and falls
back or exits safely.

## Command Injection Risk

External commands are executed through controlled wrappers and list-style
arguments. This keeps command parsing explicit and avoids shell injection
patterns.

## Credential Exposure

The tool does not request or store secrets as part of its normal flow. It
should only process evidence that already exists in the environment.

## Logging and Audit Trail

Detailed logging is written to log files, while the console remains concise.
This preserves traceability without overwhelming the operator.

## Execution Policy

Windows execution policy and Linux shell behavior are treated as read-only
inputs for evidence collection. The tool does not try to relax or bypass system
policy settings.

## Safe Exit

If data is missing or invalid, the tool exits in a controlled way instead of
continuing with an unsafe or misleading analysis result.
