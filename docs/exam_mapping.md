# Exam Mapping

| Examinationskrav | Projektkomponent | Bevis |
| --- | --- | --- |
| Read-only säkerhetsanalys | `app.py`, collectors, analysis modules | Verktyget läser evidence och skriver rapporter utan att ändra systemet |
| Linux-insamling | `bash/linux_identity_audit.sh` | Bash-sensorn samlar Linux-identitet, policy och loggevidence |
| Windows-insamling | `powershell/windows_identity_audit.ps1` | PowerShell-sensorn samlar Windows-identitet, eventloggar och policydata |
| Korrelation av identitet och privilegier | `src/analysis/correlation.py` | Normaliserad modell med baselines, events och policykopplingar |
| Riskklassificering | `src/analysis/risk_rules.py`, `src/analysis/scoring.py` | CRITICAL/HIGH/MEDIUM/LOW och prioritering av findings |
| Rapportering | `src/reporting/` | Text-, JSON- och alertutdata genereras från analysis_result |
| Safe exit | `src/utils/safe_exit.py` | Kontrollerad avslutning när data saknas eller bootstrap misslyckas |
| CI-kontroller | `.github/workflows/` | Struktur-, test- och säkerhetskontroller körs automatiskt |

This mapping summarizes how the implemented code supports the project’s
assessment requirements through observable modules and outputs.
