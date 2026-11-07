# sca-Dependency-Risk-Analyzer
Analyzes a project's software dependencies by reading the requirements file named with `-r` and flags dependencies with known vulnerabilities (using `safety` and the CVE database). The parsed dependency list is a presence check only: `safety` reads the requirements file itself for the actual check. Outputs a report of vulnerable dependencies and their associated risk scores. - Focused on Tools for assessing the security posture of third-party dependencies and supply chain components. Includes functionalities for identifying known vulnerabilities, license compliance issues, and suspicious code patterns within external libraries.

If the `safety` command is not found, the run exits 1 with a plain not installed message. The run also refuses at exit 1 when the resolved `--output` path equals the resolved requirements path.

## Install
`git clone https://github.com/ShadowGuard-AI/sca-dependency-risk-analyzer`
`pip install -r requirements.txt`

The install names `safety`. The code does not import `safety`; it runs the `safety` command as a subprocess, so that command must be installed and on the PATH.

## Usage
`python3 main.py [-r requirements.txt] [-o dependency_report.json] [--ignore ID,ID]`

Example: `python3 main.py -r requirements.txt -o report.json --ignore CVE-2020-0001,CVE-2021-0002`

## Parameters
- `-h, --help`: Show help message and exit
- `-r, --requirements`: Path to the requirements.txt file. (default: `requirements.txt`)
- `-o, --output`: Path to the output report file. (default: `dependency_report.json`)
- `--ignore`: Comma-separated list of vulnerability IDs to ignore. (default: empty)

## License
MIT License. See LICENSE.
