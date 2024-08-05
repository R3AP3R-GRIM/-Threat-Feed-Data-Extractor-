# Threat Intelligence Platform (TIP) Data Fetcher

This script fetches the data from various URLs provided in a configuration file which have been taken from https://threatfeeds.io/ where only the then live websites were taken into account and now there may be some increments, which then saves the data to a file in json format, and performs checksum verification. It is designed to be part of a larger Threat Intelligence Platform (TIP) repository.

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

The script uses an INI file named `threat_feeds_config.ini` for configuration. This file should be placed in the same directory as the script.

Example `threat_feeds_config.ini`:
```ini
[paths]
BASE_DIR = /path/to/base/directory
LOG_FILE_PATH = /path/to/logfile.log

[logging]
LOGGING_LEVEL = 20  # INFO

[URLs]
feed1 = https://example.com/feed1.json
feed2 = https://example.com/feed2.json

[feed1]
threat_feed_url = https://example.com/feed1.json
threat_feed_name = Feed 1
reference_url = https://example.com
description = Description of Feed 1
type = IP
tags = tag1, tag2

[feed2]
threat_feed_url = https://example.com/feed2.json
threat_feed_name = Feed 2
reference_url = https://example.com
description = Description of Feed 2
type = URL
tags = tag1, tag2
```

## Usage

1. Ensure the configuration file `threat_feeds_config.ini` is correctly set up in the script's directory.
2. Run the script:
```bash
python threats.py
```

The script will fetch the JSON data from the URLs listed in the configuration file and save it to the respective directories. It will also calculate and save the checksum to `*_checksum.txt` files.

## Logging

The script logs errors and informational messages to the file specified in the `LOG_FILE_PATH` configuration setting. The logging level can be adjusted in the configuration file under the `[logging]` section.

## Error Handling

If the configuration file is missing or empty, the script will log an error message and exit. All other errors during the fetch and save operations are logged to the log file.

## Example

Here is a brief example of how the script works:

1. The script reads the configuration file for URLs and settings.
2. It attempts to fetch JSON data from each URL.
3. The fetched data is saved to files in the specified directories.
4. The script calculates the checksum of the saved files and compares them with any existing checksum to ensure data integrity.
5. All operations and errors are logged to the log file specified in the configuration.

## Contributing

Contributions are welcome! Please ensure your code follows the project's style guidelines and includes appropriate tests.