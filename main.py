import argparse
import subprocess
import json
import logging
import sys
from typing import List, Dict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the CLI.
    """
    parser = argparse.ArgumentParser(description="sca-Dependency-Risk-Analyzer: Analyzes project dependencies for vulnerabilities.")
    parser.add_argument("-r", "--requirements", help="Path to the requirements.txt file.", default="requirements.txt")
    parser.add_argument("-o", "--output", help="Path to the output report file.", default="dependency_report.json")
    parser.add_argument("--ignore", help="Comma-separated list of vulnerability IDs to ignore.", default="")  # Add ignore argument
    return parser.parse_args()


def get_dependencies(requirements_file: str) -> List[str]:
    """
    Reads dependencies from the requirements.txt file.

    Args:
        requirements_file: Path to the requirements.txt file.

    Returns:
        A list of dependency strings (e.g., ['requests==2.26.0', 'beautifulsoup4==4.10.0']).
        Returns an empty list if the file doesn't exist or is empty.
    """
    try:
        with open(requirements_file, "r") as f:
            dependencies = [s for line in f if (s := line.strip()) and not s.startswith("#")] # Ignore comments and empty lines, including indented comments
        return dependencies
    except FileNotFoundError:
        logging.error(f"Requirements file not found: {requirements_file}")
        return []
    except Exception as e:
        logging.error(f"Error reading requirements file: {e}")
        return []


def run_safety_check(requirements_file: str, ignore_vulns: List[str]) -> Dict:
    """
    Runs the `safety check` command to identify vulnerabilities.

    Args:
        requirements_file: Path to the requirements.txt file.
        ignore_vulns: List of vulnerability IDs to ignore

    Returns:
        A dictionary containing the parsed JSON output from `safety check`.  Returns an empty dictionary on failure.
    """
    try:
        # Construct the safety check command
        command = ["safety", "check", "--file", requirements_file, "--json"]

        #Add ignore option
        if ignore_vulns:
            for vuln_id in ignore_vulns:
                command.extend(["--ignore", vuln_id])


        result = subprocess.run(command, capture_output=True, text=True, check=False)
        # safety reports found vulnerabilities with a non zero exit code, so
        # stdout is parsed whenever it is present, whatever the exit code.
        if result.stdout and result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError as e:
                logging.error(f"Safety check failed: output could not be decoded: {e}")
                sys.exit(1)
        logging.error("Safety check failed: no usable output from safety.")
        sys.exit(1)
    except FileNotFoundError:
        logging.error("Safety is not installed. Install safety and make sure it is in your PATH.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred while running safety check: {e}")
        return {}


def calculate_risk_score(vulnerability: Dict) -> int:
    """
    Calculates a risk score based on the vulnerability information.
    This is a very basic implementation and can be customized.

    Args:
        vulnerability: A dictionary containing vulnerability information from the `safety check` output.

    Returns:
        An integer representing the risk score.
    """
    severity = vulnerability.get("severity", "LOW").upper()

    if severity == "CRITICAL":
        return 90
    elif severity == "HIGH":
        return 70
    elif severity == "MEDIUM":
        return 50
    elif severity == "LOW":
        return 30
    else:
        return 10


def generate_report(vulnerabilities) -> List[Dict]:
    """
    Generates a report containing information about vulnerable dependencies and their risk scores.

    Args:
        vulnerabilities: A list of vulnerability dictionaries, or an object
            holding a vulnerabilities list.

    Returns:
        A list of dictionaries, where each dictionary represents a vulnerable dependency and its risk score.
    """
    if isinstance(vulnerabilities, dict):
        vulnerabilities = vulnerabilities.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        logging.error("Safety output has an unexpected shape. Expected a list or an object with a vulnerabilities list.")
        return []
    report = []
    skipped = 0
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict) or not vulnerability.get("package_name") or not vulnerability.get("vulnerability_id"):
            skipped += 1
            continue
        risk_score = calculate_risk_score(vulnerability)
        report_entry = {
            "dependency": vulnerability.get("package_name"),
            "version": vulnerability.get("analyzed_version", "unknown"),
            "vulnerability_id": vulnerability.get("vulnerability_id"),
            "severity": vulnerability.get("severity", "LOW"),
            "risk_score": risk_score,
            "advisory": vulnerability.get("advisory", ""),
            "more_info_url": vulnerability.get("more_info_url", "")
        }
        report.append(report_entry)
    if skipped:
        logging.warning(f"Skipped {skipped} entries with missing fields.")
    return report


def save_report(report: List[Dict], output_file: str):
    """
    Saves the report to a JSON file.

    Args:
        report: A list of dictionaries representing the vulnerability report.
        output_file: Path to the output file.
    """
    try:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=4)
        logging.info(f"Report saved to: {output_file}")
    except Exception as e:
        logging.error(f"Error saving report to file: {e}")


def main():
    """
    Main function to orchestrate the dependency risk analysis.
    """
    args = setup_argparse()

    # Validate input
    if not isinstance(args.requirements, str):
        logging.error("Requirements file path must be a string.")
        sys.exit(1)

    if not isinstance(args.output, str):
        logging.error("Output file path must be a string.")
        sys.exit(1)

    import os as _os
    if _os.path.realpath(args.output) == _os.path.realpath(args.requirements):
        logging.error("Output path must not equal the requirements file path.")
        sys.exit(1)

    ignore_vulns = [vuln_id.strip() for vuln_id in args.ignore.split(',') if vuln_id.strip()]  # Split and strip the ignore list


    dependencies = get_dependencies(args.requirements)

    if not dependencies:
        logging.warning("No dependencies found or an error occurred while reading the requirements file. Exiting.")
        sys.exit(1)

    vulnerabilities = run_safety_check(args.requirements, ignore_vulns)


    if vulnerabilities:
        report = generate_report(vulnerabilities)
        save_report(report, args.output)
    else:
        logging.info("No vulnerabilities found or an error occurred during the safety check.")


if __name__ == "__main__":
    # Example usage:
    # python main.py -r requirements.txt -o report.json --ignore CVE-2020-0001,CVE-2021-0002
    main()