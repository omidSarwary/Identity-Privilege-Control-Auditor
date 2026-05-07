# Installation

## Prerequisites

- Visual Studio Code or another editor
- Python 3.11 or newer
- Bash for the Linux sensor
- PowerShell 7+ or Windows PowerShell for the Windows sensor
- Git for local repository work

## Python Environment

Create and activate a virtual environment:

```bash
python -m venv .venv
```

Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

## Editor Setup

Visual Studio Code is recommended because it works well with Python, Bash, and
PowerShell files in one workspace. The project does not require special editor
extensions, but Python linting and test integration are useful during
development.

## Bash and PowerShell

The repository includes both platform sensors:

- `bash/linux_identity_audit.sh`
- `powershell/windows_identity_audit.ps1`

Ensure the relevant shell is available before running the matching sensor.

## Git Usage

Typical local workflow:

1. clone the repository
2. create a virtual environment
3. install dependencies
4. run tests locally
5. commit changes when the working tree is ready

The project is intended for local repository use and does not require creating
a GitHub repository through the command line.
