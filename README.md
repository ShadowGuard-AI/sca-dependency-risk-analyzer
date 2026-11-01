# sca-Dependency-Risk-Analyzer
Analyzes a project's software dependencies by reading the requirements file named with `-r` and flags dependencies with known vulnerabilities (using `safety` and the CVE database). The parsed dependency list is a presence check only: `safety` reads the requirements file itself for the actual check. Outputs a report of vulnerable dependencies and their associated risk scores. - Focused on Tools for assessing the security posture of third-party dependencies and supply chain components. Includes functionalities for identifying known vulnerabilities, license compliance issues, and suspicious code patterns within external libraries.

If the `safety` command is not found, the run exits 1 with a plain not installed message. The run also refuses at exit 1 when the resolved `--output` path equals the resolved requirements path.

## Install
`git clone https://github.com/ShadowStrikeHQ/sca-dependency-risk-analyzer`
`pip install -r requirements.txt`

## Usage
`./sca-dependency-risk-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-r`: Path to the requirements.txt file.
- `-o`: Path to the output report file.
- `--ignore`: Comma-separated list of vulnerability IDs to ignore.

## License
Copyright (c) ShadowStrikeHQ
