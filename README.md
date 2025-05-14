# Cross-Platform Vulnerability Scanner

A comprehensive vulnerability scanner that detects OS-level, software, and configuration vulnerabilities on both Windows and Linux systems.

## Features

- **Cross-Platform Support**: Works on both Windows and Linux environments
- **Comprehensive Scanning**:
  - Operating System vulnerabilities
  - Installed package vulnerabilities
  - Network and port scanning
  - User and permission issues
  - Configuration vulnerabilities
- **Structured Output**: Results are saved in JSON format
- **Multithreaded Scanning**: Parallel scanning for improved performance
- **Detailed Reporting**: Severity ratings, descriptions, and fix recommendations

## Requirements

- Python 3.6 or higher
- Administrative/root privileges (for some scans)

### Optional Dependencies

- For Linux distribution detection: `pip install distro`
- For HTML report generation: Standard Python libraries
- For CSV report generation: Standard Python libraries

## Installation

1. Clone this repository:

   ```
   git clone https://github.com/yourusername/vuln-scanner.git
   cd vuln-scanner
   ```

2. Install optional dependencies:

   ```
   pip install distro
   ```

3. (Optional) Set environment variables for API keys:

   ```
   # Windows
   set VULNERS_API_KEY=your_api_key_here

   # Linux
   export VULNERS_API_KEY=your_api_key_here
   ```

## Usage

### Basic Usage

Run the scanner with default settings:

```
python scanner.py
```

This will:

- Scan the local system for vulnerabilities
- Save results to `vulnerability_report.json`
- Generate HTML report at `vulnerability_report.html`
- Generate CSV report at `vulnerability_report.csv`
- Create a log file at `scanner.log`

### Command-Line Options

```
python scanner.py [-h] [-o OUTPUT] [-l LOG] [-t THREADS] [-v] [--no-html] [--no-csv]

options:
  -h, --help            Show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file path (default: vulnerability_report.json)
  -l LOG, --log LOG     Log file path (default: scanner.log)
  -t THREADS, --threads THREADS
                        Number of threads to use (default: 4)
  -v, --verbose         Enable verbose output
  --no-html             Disable HTML report generation
  --no-csv              Disable CSV report generation
```

### Examples

Scan with verbose output and custom output file:

```
python scanner.py -v -o my_scan_results.json
```

This will also generate `my_scan_results.html` and `my_scan_results.csv`.

Scan with more threads for faster performance:

```
python scanner.py -t 8
```

Scan and only generate JSON output (no HTML or CSV):

```
python scanner.py --no-html --no-csv
```

## Output Format

The scanner produces a JSON file with the following structure:

```json
{
  "metadata": {
    "scan_time": "2023-07-15T14:30:45.123456",
    "scanner_version": "1.0.0",
    "os": "Windows 10 10.0.19044",
    "hostname": "DESKTOP-ABC123"
  },
  "summary": {
    "total_vulnerabilities": 12,
    "severity_counts": {
      "Critical": 1,
      "High": 3,
      "Medium": 5,
      "Low": 3,
      "Info": 0
    },
    "average_cvss": 6.2
  },
  "vulnerabilities": [
    {
      "id": "CVE-2023-XXXXX",
      "description": "Remote code execution in XYZ",
      "severity": "High",
      "component": "OpenSSL",
      "fix_available": true,
      "fix": "Update OpenSSL to version 1.1.1t or later"
    },
    ...
  ]
}
```

## Report Formats

The scanner automatically generates reports in three formats:

1. **JSON** - Detailed structured data (default: vulnerability_report.json)
2. **HTML** - Human-readable report with formatting and styling (default: vulnerability_report.html)
3. **CSV** - Spreadsheet-compatible format for data analysis (default: vulnerability_report.csv)

You can disable HTML or CSV report generation using the `--no-html` or `--no-csv` command-line options:

```
# Generate only JSON and CSV reports
python scanner.py --no-html

# Generate only JSON report
python scanner.py --no-html --no-csv
```

## Security Considerations

- The scanner requires administrative/root privileges for some checks
- No data is transmitted externally unless required for CVE lookup
- API keys should be kept secure and not hardcoded
- The scanner is designed to be non-intrusive and safe to run

## Limitations

- Some scans may produce false positives
- The scanner cannot detect all possible vulnerabilities
- Performance may vary depending on system resources
- Some checks require internet connectivity for CVE lookups

## Acknowledgments

- This scanner uses various open-source tools and libraries
- Vulnerability information is sourced from public CVE databases
- Inspired by security best practices from NIST, CIS, and OWASP
