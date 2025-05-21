# credscan-PasswordSprayDetector
Analyzes authentication logs to detect password spraying attacks. It identifies patterns of failed login attempts across multiple accounts originating from the same source IP, indicating potential brute-force credential attacks. - Focused on Scans code repositories, log files, and other text-based artifacts for inadvertently exposed credentials, API keys, or other sensitive information. Uses regular expressions and heuristics to identify potential leaks. Includes domain parsing to flag suspicious URLs.

## Install
`git clone https://github.com/ShadowStrikeHQ/credscan-passwordspraydetector`

## Usage
`./credscan-passwordspraydetector [params]`

## Parameters
- `-h`: Show help message and exit
- `--threshold`: Threshold for failed login attempts from the same IP to flag as suspicious.
- `--domains`: No description provided

## License
Copyright (c) ShadowStrikeHQ
