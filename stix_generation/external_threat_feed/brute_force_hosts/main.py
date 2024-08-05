import re
import os
import json
import requests
import logging
import configparser
import uuid
from datetime import datetime, timedelta

ipv4_pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"

# Set up logging
logger = logging.getLogger(__name__)

# Function to convert IOC to STIX format
def convert_to_stix(ioc, feed_name, feed_source, url, ioc_type):
    now = datetime.utcnow()
    valid_from = now.isoformat() + "Z"
    valid_until = (now + timedelta(days=30)).isoformat() + "Z"
    stix_object = {
        "type": "indicator",
        "id": f"indicator--{uuid.uuid4()}",
        "created": valid_from,
        "modified": valid_from,
        "name": ioc,
        "description": f"This indicator indicates a {ioc_type}.",
        "pattern": f"[{ioc_type}:value = '{ioc}']",
        "valid_from": valid_from,
        "valid_until": valid_until,
        "x_decay_timeperiod": 30,
        "confidence": "",
        "x_indicator_source": feed_source,
        "labels": ["malicious", feed_name],
        "x_threat_feed_list": [feed_name],
        "x_ioc_value": ioc,
        "x_ioc_type": ioc_type,
        "external_references": [
            {
                "source_name": feed_name,
                "url": url
            }
        ]
    }
    return stix_object

# Function to send data to the API
def send_to_api(ioc_list, api_url, headers):
    try:
        response = requests.post(api_url, json=ioc_list, headers=headers)
        if response.status_code == 200:
            logger.info("Successfully sent data to API.")
        else:
            logger.error(f"Failed to send data to API. Status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
    except requests.RequestException as e:
        logger.error(f"An error occurred while sending data to API: {e}")

# Function to fetch data from a URL and process IOCs
def fetch_and_process_data(url, feed_name, config, section, api):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            logger.info(f"Successfully fetched data from {url}. Status code: {response.status_code}")
            feed_source = "external_threat_feed" if feed_name != "cdacsiem" else "cdacsiem"
            ioc_list = []

            for line in response.content.decode("utf-8").splitlines():
                parts = line.split(",")
                if parts and re.match(ipv4_pattern, parts[0].strip()):
                    ioc = parts[0].strip()
                    ioc_list.append(convert_to_stix(ioc, feed_name, feed_source, url, "ipv4-addr"))

            # Log the payload
            logger.debug(f"Payload: {json.dumps(ioc_list, indent=4)}")

            # Send the IOCs to the FastAPI endpoint
            headers = {"api-key": api}  # Replace with your actual API key
            send_to_api(ioc_list, api_url, headers)
        else:
            logger.error(f"Failed to fetch data from {url}. Status code: {response.status_code}")
    except requests.RequestException as e:
        logger.error(f"An error occurred while fetching data from {url}: {e}")

def main():
    global logging_level
    global api_url
    # Path to the configuration file
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_file_path = os.path.join(script_dir, 'config.ini')

    # Check if the configuration file exists
    if os.path.exists(config_file_path):
        # Read the configuration file
        config = configparser.ConfigParser()
        config.read(config_file_path)

        # Configure logging
        log_file_path = config['paths']['LOG_FILE_PATH']
        logging_level = int(config['logging']['LOGGING_LEVEL'])
        api_url = config['API']['api_url']
        logging_format = '%(asctime)s - %(levellevelname)s - %(message)s'
        logging.basicConfig(filename=log_file_path, level=logging_level, format=logging_format)

        # Fetch and process data from the specified URL
        url = config['URL']['brute_force_hosts']
        feed_name = 'brute_force_hosts'
        api = config['API']['api_key']
        logging_level = config['logging']['LOGGING_LEVEL']
        fetch_and_process_data(url, feed_name, config, 'URL', api)
    else:
        logging.error(f"Configuration file '{config_file_path}' not found.")

if __name__ == "__main__":
    main()
