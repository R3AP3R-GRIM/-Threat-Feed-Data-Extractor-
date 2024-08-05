# Palo Alto Unit 42 Threat Feed Fetcher

This script fetches JSON data from various URLs provided in a configuration file, saves the data to a file, and performs checksum verification. It is designed to be part of a larger Threat Intelligence Platform (TIP) repository.

## Features

- Fetches JSON data from multiple URLs.
- Saves the fetched data to a file in a structured format.
- Calculates and verifies the checksum of the saved file to ensure data integrity.
- Logs errors and information to a log file for easy troubleshooting.

## Requirements

- Python 3.x
- `requests` library

You can install the required library using:
```bash
pip install requests
```

## Configuration

The script uses an INI file named `palo_alto_unit42_threat_feed.ini` for configuration. This file should be placed in the same directory as the script.

Example `palo_alto_unit42_threat_feed.ini`:
```ini
[DEFAULT]
MAX_RETRIES = 3
REQUEST_TIMEOUT = 10

[logging]
LOGGING_LEVEL = 30

[URLs]
# Add more URLs if needed
```

## Usage

1. Ensure the configuration file `palo_alto_unit42_threat_feed.ini` is correctly set up in the script's directory.
2. Run the script:
```bash
python script_name.py
```

The script will fetch the JSON data from the URLs listed in the configuration file and save it to `palo_alto_unit42_threat_feed.json`. It will also calculate and save the checksum to `palo_alto_unit42_threat_feed_checksum.txt`.

## Logging

The script logs errors and informational messages to `palo_alto.log`. The logging level can be adjusted in the configuration file under the `[logging]` section.

## Error Handling

If the configuration file is missing or empty, the script will log an error message and exit. All other errors during the fetch and save operations are logged to the log file.

## Example

Here is a brief example of how the script works:

1. The script reads the configuration file for URLs and settings.
2. It attempts to fetch JSON data from each URL, retrying up to `MAX_RETRIES` times in case of failure.
3. The fetched data is saved to `palo_alto_unit42_threat_feed.json`.
4. The script calculates the checksum of the saved file and compares it with any existing checksum to ensure data integrity.
5. All operations and errors are logged to `palo_alto.log`.

## Contributing

Contributions are welcome! Please ensure your code follows the project's style guidelines and includes appropriate tests.

