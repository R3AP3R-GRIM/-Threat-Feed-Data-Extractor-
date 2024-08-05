import re
import os
import json
import requests
import logging
import hashlib
import configparser
import uuid
from datetime import datetime, timedelta

ipv4_pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
ipv6_pattern = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
md5_pattern = r"\b[a-fA-F0-9]{32}\b"
sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
sha256_pattern = r"\b[a-fA-F0-9]{64}\b"
sha512_pattern = r"\b[a-fA-F0-9]{128}\b"
url_pattern = r"https?://[^\s]+"

# Set up logging
logger = logging.getLogger(__name__)

# Function to convert IOC to STIX format
def convert_to_stix(ioc, feed_name, feed_source, url, ioc_type):
    now = datetime.utcnow()
    valid_from = now.isoformat() + "Z"
    valid_until = (now + timedelta(days=30)).isoformat() + "Z"
    if ioc_type == "ipv4-addr":
        type_ioc = "ipv4"
    elif ioc_type == "ipv6-addr":
        type_ioc = "ipv6"
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
        "x_ioc_type": type_ioc,
        "external_references": [
            {
                "source_name": feed_name,
                "url": url
            }
        ]
    }
    return stix_object

# Function to send data to the API
def send_to_api(stix_data, api_url):
    try:
        response = requests.post(api_url, json=stix_data)
        if response.status_code == 200:
            logger.info("Successfully sent data to API.")
        else:
            logger.error(f"Failed to send data to API. Status code: {response.status_code}")
    except requests.RequestException as e:
        logger.error(f"An error occurred while sending data to API: {e}")

# Function to fetch data from a URL and process IOCs
def fetch_and_process_data(url, feed_name, config, section):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            logger.info(f"Successfully fetched data from {url}. Status code: {response.status_code}")
            feed_source = "external_threat_feed" if feed_name != "cdacsiem" else "cdacsiem"
            ioc_list = []

            for line in response.content.decode("utf-8").splitlines():
                line = line.strip()
                if re.match(ipv4_pattern, line):
                    ioc = line.split()[0]
                    ioc_list.append(convert_to_stix(ioc, feed_name, feed_source, url, "ipv4-addr"))
                elif re.match(ipv6_pattern, line):
                    ioc = line.split()[0]
                    ioc_list.append(convert_to_stix(ioc, feed_name, feed_source, url, "ipv6-addr"))
                elif re.match(md5_pattern, line):
                    ioc = line.split()[0]
                    ioc_list.append(convert_to_stix(ioc, feed_name, feed_source, url, "file:hashes.MD5"))
                elif re.match(sha1_pattern, line):
                    ioc = line.split()[0]
                    ioc_list.append(convert_to_stix(ioc, feed_name, feed_source, url, "file:hashes.SHA-1"))
                elif re.match(sha256_pattern, line):
                    ioc = line.split()[0]
                    ioc_list.append(convert_to_stix(ioc, feed_name, feed_source, url, "file:hashes.SHA-256"))
                elif re.match(sha512_pattern, line):
                    ioc = line.split()[0]
                    ioc_list.append(convert_to_stix(ioc, feed_name, feed_source, url, "file:hashes.SHA-512"))
                elif re.match(url_pattern, line):
                    ioc = line.split()[0]
                    ioc_list.append(convert_to_stix(ioc, feed_name, feed_source, url, "url"))

            # api_url = config['api']['endpoint']
            # send_to_api(ioc_list, api_url)
            with open("C:\\Users\\laksh\\Downloads\\Python\\stix_generation\\scripts\\external_threat_feed\\ipsum_level5\\lol.json", 'w') as main_data_json_file:
                json.dump(ioc_list, main_data_json_file, indent=4)
        else:
            logger.error(f"Failed to fetch data from {url}. Status code: {response.status_code}")
    except requests.RequestException as e:
        logger.error(f"An error occurred while fetching data from {url}: {e}")

def main():
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
        logging_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(filename=log_file_path, level=logging_level, format=logging_format)

        # Fetch and process data from the specified URL
        url = config['URL']['ipsum_level5']
        feed_name = 'ipsum_level5'
        fetch_and_process_data(url, feed_name, config, 'URL')
    else:
        logging.error(f"Configuration file '{config_file_path}' not found.")

if __name__ == "__main__":
    main()