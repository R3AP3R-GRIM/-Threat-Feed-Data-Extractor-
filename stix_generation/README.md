# Threat Intelligence Platform (TIP) API

The Threat Intelligence Platform (TIP) API provides a set of RESTful endpoints to manage and query threat intelligence data stored in Elasticsearch. This API allows users to search for indicators, add new indicators, fetch relationships, and process a batch of indicators efficiently.

## Features

- Provides RESTful API endpoints for managing threat intelligence data
- Supports searching, adding, and fetching relationships of threat indicators
- Utilizes Elasticsearch for data storage and retrieval

## Endpoints

- **/api/v1/search_indicator**
  - Searches for an existing indicator in Elasticsearch.
  - **Method**: POST
  - **Request Body**:
    ```json
    {
      "indicator_value": "example_indicator_value",
      "indicator_type": "example_indicator_type",
      "graph": false
    }
    ```
  - **Response**: Indicator details or STIX bundle if `graph` is true.

- **/api/v1/add_indicator**
  - Adds a new indicator to Elasticsearch.
  - **Method**: POST
  - **Request Body**:
    ```json
    {
      "indicator_value": "example_indicator_value",
      "indicator_type": "example_indicator_type",
      "indicator_source": "example_source",
      "valid_from": "2024-01-01T00:00:00Z"
    }
    ```
  - **Response**: Newly added indicator details.

- **/api/v1/fetch_relationships**
  - Fetches relationships of an indicator from Elasticsearch.
  - **Method**: POST
  - **Request Body**:
    ```json
    {
      "indicator_id": "example_indicator_id"
    }
    ```
  - **Response**: List of related objects.

- **/api/v1/process_indicators**
  - Processes a batch of indicators and adds them to Elasticsearch.
  - **Method**: POST
  - **Request Body**: JSON array of indicator objects.
  - **Response**: Status of the operation, including the count of new indicators added.

## Setup

1. Clone the repository:

   ```sh
   git clone https://github.com/yourusername/Threat-Feed-Data-Extractor.git
   cd Threat-Feed-Data-Extractor/tip-api
   ```

2. Install the required dependencies:

   ```sh
   pip install -r requirements.txt
   ```

3. Configure the application by editing the `main.ini` file to include your Elasticsearch URL and credentials.

4. Run the FastAPI application:

   ```sh
   uvicorn main:app --reload
   ```

