# PowerShell Graylog Log Parser
**Automated Log Parser and GELF Forwarder to Graylog (PowerShell)**
This PowerShell script scans error log files in a specified folder, extracts relevant data (IP address, timestamp, severity level, exception, message, URL), and sends structured JSON logs to a Graylog server via the GELF HTTP input. It includes advanced parsing error handling, deduplication using SHA1 hashing, and log archiving.

---

## Features
- Parses `.log` files and automatic log block splitting using regex (based on timestamp and IP).
- Extracts key information: IP address, timestamp, level, exception, message, URL.
- Filters duplicate logs using SHA1 hashing.
- Formats logs in [GELF 1.1](https://go2docs.graylog.org/current/getting_in_log_data/gelf_inputs.html) JSON.
- Sends entries to Graylog via HTTP POST.
- Saves unprocessed or malformed blocks with reasons.
- Automatically archives files once processed.
- Summary of processed, skipped, and failed logs.

---

## Folder Structure
```
graylog/
├── example_logs/
│   └── error.log.sample       # Sample log for testing
└── logs/                      # Runtime output directory (excluded from git)
    ├── error.log              # Input log file (user provided)
    ├── error.log.done.txt     # Archived version after processing
    ├── error.log_hashing.txt  # SHA1 hashes of processed log blocks
    ├── error.log_parsing.txt  # Skipped/malformed blocks with reasons
    └── logs_failed.txt        # Global file read/rename errors
├── .gitignore                 # Ignore rules
├── LICENSE                    # MIT license
├── main.ps1                   # Main PowerShell script
└── README.md                  # Project documentation
```

---

## File System Overview
- __error.log.*__: Raw log files to parse
- __*.done.txt__: Renamed (archived) logs after processing
- **logs_failed.txt**: Logs with unreadable or malformed blocks
- __*hashing.txt__: Stores SHA1 hashes of already processed blocks
- __*parsing.txt__:Logs blocks that failed parsing with reasons

---

## Main Configuration Parameters

| Variable         | Description                                        |
|------------------|----------------------------------------------------|
| `$server`        | Graylog server IP or hostname                      |
| `$logFolder`     | Folder path containing log files                   |
| `$uri`           | GELF HTTP input URL (e.g., `http://localhost:12201/gelf`) |
| `$archiveSuffix` | Suffix added to processed files (e.g., `.done.txt`) |
| `$errorLogFile`  | Global error log for file-level issues             |

---

## Functions Explained
### `Get-Hash($text)`
Returns a SHA1 hash of the input text. Used to uniquely identify and skip duplicate log blocks.

### `logParsingError(...)`
Logs unprocessable or ignored log blocks with details into a specified file for future debugging.

### `logParsedBlock(...)`
Displays the parsed content from a block in the console (disabled in production but useful for debugging).

---

## Expected Raw Log Format
Example of a well-structured input block:
```
192.168.13.23 2025-05-27 22:44:04 Error: [MissingControllerException] Controller class Wp-includesController could not be found.
Request URL: /wp-includes/css/
```
---

## JSON Format Sent to Graylog (GELF 1.1)
```json
{
  "version": "1.1",
  "host": "127.0.0.1",
  "short_message": "MissingControllerException: Controller class ...",
  "full_message": "192.168.13.23 2025-05-27 22:44:04 Error: ...",
  "timestamp": 1716830644.000,
  "level": 3,
  "_ip": "192.168.13.23",
  "_url": "/wp-includes/css/",
  "_exception_class": "MissingControllerException",
  "_datetime": "2025-05-27 22:44:04",
  "_log_id": "abc123..."
}
```

## Requirements
- PowerShell 5.1 (Windows) or PowerShell Core (7.x) on Linux.
- A Graylog server with an active GELF HTTP input.
- Log files must contain IP + timestamp + level in identifiable format.

## Sample Output
Processing complete.
- Logs sent    : 45
- Logs ignored : 12
- Errors in    : logs_failed.txt

## Contributions
Pull requests and feedback are welcome! Please open issues for bugs or feature suggestions.
