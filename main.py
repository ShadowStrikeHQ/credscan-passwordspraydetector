import argparse
import re
import logging
import sys
import tldextract  # Ensure this is installed: pip install tldextract

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse():
    """Sets up the argument parser for the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Detects password spraying attacks and credential leaks."
    )

    # Subparsers for different functionalities
    subparsers = parser.add_subparsers(
        title="Commands", dest="command", help="Available commands"
    )

    # Password spraying detection subparser
    spray_parser = subparsers.add_parser(
        "spray", help="Detect password spraying attacks from log files."
    )
    spray_parser.add_argument(
        "log_file", type=str, help="Path to the authentication log file."
    )
    spray_parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Threshold for failed login attempts from the same IP to flag as suspicious.",
    )

    # Credential leak detection subparser
    leak_parser = subparsers.add_parser(
        "leak", help="Scan files for potential credential leaks."
    )
    leak_parser.add_argument(
        "file_path", type=str, help="Path to the file to scan for leaks."
    )
    leak_parser.add_argument(
        "--domains",
        type=str,
        nargs="*",
        help="List of domains to flag in URLs (e.g., example.com).",
    )

    return parser


def detect_password_spraying(log_file, threshold):
    """
    Detects password spraying attacks by analyzing failed login attempts.

    Args:
        log_file (str): Path to the authentication log file.
        threshold (int): Number of failed attempts from an IP before flagging.
    """
    try:
        ip_failed_attempts = {}
        with open(log_file, "r") as f:
            for line in f:
                #  Match failed login attempts. Adjust regex based on your log format.
                match = re.search(
                    r"(?:Failed login|Authentication failure) for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                    line,
                )
                if match:
                    ip = match.group(1)
                    ip_failed_attempts[ip] = ip_failed_attempts.get(ip, 0) + 1

        # Identify suspicious IPs
        suspicious_ips = [
            ip for ip, count in ip_failed_attempts.items() if count >= threshold
        ]

        if suspicious_ips:
            logging.warning(
                f"Potential password spraying attack detected.  The following IPs have exceeded the threshold ({threshold}):"
            )
            for ip in suspicious_ips:
                logging.warning(
                    f"IP: {ip} - Failed attempts: {ip_failed_attempts[ip]}"
                )
        else:
            logging.info("No password spraying attacks detected based on the threshold.")

    except FileNotFoundError:
        logging.error(f"Log file not found: {log_file}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")


def detect_credential_leaks(file_path, domains=None):
    """
    Scans a file for potential credential leaks using regex and domain parsing.

    Args:
        file_path (str): Path to the file to scan.
        domains (list, optional): List of domains to flag. Defaults to None.
    """
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()

        # Regex patterns for common credentials and sensitive information. Customize and expand as needed.
        patterns = {
            "API Key": r"[A-Za-z0-9_-]{32,45}",  # Example: long alphanumeric string
            "Password": r"(password|pwd)\s*[:=]\s*[\"']?[\w\d!@#$%^&*()_+=\-`~\[\]\{\}\|;':\",\.\/<>\?]+[\"']?", #Basic password detection
            "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Secret Key": r"[sS][ecret]*\_?[Kk][eys]*\s*[:=]\s*[\"']?[\w\d!@#$%^&*()_+=\-`~\[\]\{\}\|;':\",\.\/<>\?]+[\"']?"
        }

        # Iterate and search for leaks
        for key, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                logging.warning(f"Potential {key} leak(s) found:")
                for match in matches:
                    logging.warning(f"  - {match}")

        # Domain parsing for suspicious URLs
        if domains:
            url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
            urls = re.findall(url_pattern, content)
            for url in urls:
                ext = tldextract.extract(url)
                domain = ext.domain + "." + ext.suffix
                if domain in domains:
                    logging.warning(f"Suspicious URL found with domain {domain}: {url}")

    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")


def main():
    """
    Main function to parse arguments and call the appropriate functions.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "spray":
        detect_password_spraying(args.log_file, args.threshold)
    elif args.command == "leak":
        detect_credential_leaks(args.file_path, args.domains)


if __name__ == "__main__":
    main()

# Usage Examples:

# Password Spraying Detection:
#   python credscan.py spray auth.log --threshold 10

# Credential Leak Detection:
#   python credscan.py leak config.ini
#   python credscan.py leak code.py --domains example.com internal.corp