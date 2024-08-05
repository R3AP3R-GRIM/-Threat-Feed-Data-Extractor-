import logging
import requests
import json
import time
import configparser
import hashlib
import os
import datetime

# Retrieving the directory path of the current script
script_dir = os.path.dirname(os.path.realpath(__file__))

# Checking if the configuration file exists and is not empty
config_file_path = os.path.join(script_dir, 'palo_alto_unit42_threat_feed.ini')
if not os.path.exists(config_file_path) or os.path.getsize(config_file_path) == 0:
    # Log error message if the configuration file is missing or empty and exit the script
    error_message = f'Error ({datetime.datetime.now()}): Configuration file "palo_alto_unit42_threat_feed.ini" not found or empty.'
    with open(os.path.join(script_dir, 'error.txt'), 'w') as error_file:
        error_file.write(error_message)
    exit()

# Reading configuration settings from the configuration file
config = configparser.ConfigParser()
config.read(config_file_path)
MAX_RETRIES = int(config['DEFAULT']['MAX_RETRIES'])
REQUEST_TIMEOUT = int(config['DEFAULT']['REQUEST_TIMEOUT'])
LOGGING_LEVEL = config['logging']['LOGGING_LEVEL']

# Adjust logging level
logging.basicConfig(filename=os.path.join(script_dir, 'palo_alto.log'), level=int(LOGGING_LEVEL),
                    format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_json(url):
    # Fetch JSON data from a URL with retries
    for _ in range(MAX_RETRIES):
        try:
            # Send GET request to the URL
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            # Return the JSON data if the request is successful
            return response.json()
        except requests.exceptions.RequestException as e:
            # Log an error if the request fails
            logging.error(f"Failed to fetch JSON from {url}: {e}")
            time.sleep(1)
        except json.JSONDecodeError as e:
            # Log an error if JSON decoding fails
            logging.error(f"Failed to decode JSON from {url}: {e}")
            break
    # Log an error if maximum retries are exceeded
    logging.error(f"Maximum retries exceeded for {url}")
    return None

def fetch_all_json(urls):
    # Fetch JSON data from a list of URLs
    fetched_data = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            continue
        data = fetch_json(url)
        if data:
            fetched_data.append(data)
        else:
            # Log an error if fetching JSON fails
            logging.error(f"Failed to fetch JSON from {url}")
    return fetched_data

def retrieve_existing_checksum(checksum_file_path):
    # Retrieve the existing checksum from the checksum file
    if os.path.exists(checksum_file_path):
        with open(checksum_file_path, 'r') as checksum_file:
            return checksum_file.read().strip()
    return None

def calculate_checksum(file_path, checksum_file_path):
    try:
        # Calculate the checksum of the file
        with open(file_path, 'rb') as f:
            bytes = f.read()
            calculated_checksum = hashlib.sha512(bytes).hexdigest()

        existing_checksum = retrieve_existing_checksum(checksum_file_path)
        if existing_checksum == calculated_checksum:
            # Log a message if the checksum is already calculated
            logging.info(f"Checksum already calculated for file: {file_path}. Retrieved checksum: {existing_checksum}")
        else:
            # Update the checksum file with the new checksum
            with open(checksum_file_path, 'w') as checksum_file:
                checksum_file.write(calculated_checksum)
            logging.info(f"Checksum updated for file: {file_path}. Previous checksum: {existing_checksum}. New checksum: {calculated_checksum}")

        return calculated_checksum

    except Exception as e:
        # Log an error if checksum calculation fails
        logging.error(f"Error calculating checksum for file: {file_path}. Error: {e}")
        return ""

def main():
    # Get the list of URLs from the configuration file
    urls = config['URLs'].values()
    final_json_data = fetch_all_json(urls)

    if final_json_data:
        # Save the fetched JSON data to a file
        formatted_json = {"palo_alto_unit42_threat_feed": final_json_data}
        filename = "palo_alto_unit42_threat_feed.json"
        file_path = os.path.join(script_dir, filename)
        checksum_file_path = os.path.join(script_dir, 'palo_alto_unit42_threat_feed_checksum.txt')

        with open(file_path, "w") as json_file:
            json.dump(formatted_json, json_file, indent=2)
            logging.info(f"Palo Alto Unit 42 threat feed data successfully saved to {filename}.")

        # Calculate and update the checksum of the saved file
        calculated_checksum = calculate_checksum(file_path, checksum_file_path)
        if calculated_checksum:
            with open(checksum_file_path, "w") as f:
                f.write(calculated_checksum)
        else:
            print("Failed to calculate checksum for the file.")
    else:
        # Log an error if fetching all JSON files fails
        logging.error("Failed to fetch all required JSON files.")

if __name__ == "__main__":
    main()
