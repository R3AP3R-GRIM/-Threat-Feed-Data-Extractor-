# Threat-Feed-Data-Extractor

The Threat-Feed-Data-Extractor repository contains three main components that work together to enhance cybersecurity through threat intelligence data retrieval, processing, and analysis. This repository is designed to help organizations collect, analyze, and manage threat intelligence data effectively.

## Components

1. **Threat Feed Data Retrieval from threatfeeds.io**
2. **Threat Feed Data Retrieval from Palo Alto Unit42**
3. **Threat Intelligence Platform (TIP) API**

### Threat Feed Data Retrieval from threatfeeds.io

This component focuses on retrieving threat feed data from various sources and saving it in a structured format. It includes a Python script that fetches JSON data from multiple URLs, verifies the integrity of the data using checksums, and saves it to files for further analysis.

**Features:**
- Fetches threat data from specified URLs
- Verifies data integrity using checksums
- Saves data to files for analysis

### Threat Feed Data Retrieval from Palo Alto Unit42

This script fetches JSON data from various URLs provided in a configuration file, saves the data to a file, and performs checksum verification. It is designed to be part of a larger Threat Intelligence Platform (TIP) repository.

**Features:**
- Fetches JSON data from multiple URLs.
- Saves the fetched data to a file in a structured format.
- Calculates and verifies the checksum of the saved file to ensure data integrity.
- Logs errors and information to a log file for easy troubleshooting.

### Threat Intelligence Platform (TIP) API

The TIP API component provides a set of RESTful endpoints to manage and query threat intelligence data stored in Elasticsearch. It supports operations like searching for indicators, adding new indicators, and fetching relationships between indicators.

**Features:**
- Provides RESTful API endpoints for managing threat intelligence data
- Supports searching, adding, and fetching relationships of threat indicators
- Utilizes Elasticsearch for data storage and retrieval

**Endpoints:**
- `/api/v1/search_indicator`: Searches for an existing indicator in Elasticsearch.
- `/api/v1/add_indicator`: Adds a new indicator to Elasticsearch.
- `/api/v1/fetch_relationships`: Fetches relationships of an indicator from Elasticsearch.
- `/api/v1/process_indicators`: Processes a batch of indicators and adds them to Elasticsearch.

## Installation

To install and set up the repository, follow the instructions in the respective README files located in each component's folder:

- [Threat Feed Data Retrieval from threatfeeds.io README](Threat_Feeds/README.md)
- [Threat Feed Data Retrieval from Palo Alto Unit42 README](Palo_Alto/README.md)
- [Threat Intelligence Platform (TIP) API README](stix_generation/README.md)

## Usage

Each component's README file contains detailed usage instructions. Ensure you follow the steps provided in each README to set up and use the components effectively.

## Contributing

Contributions are welcome! If you have any ideas, suggestions, or improvements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the CC BY-NC-SA 4.0 License. See the [LICENSE](LICENSE) file for details.
