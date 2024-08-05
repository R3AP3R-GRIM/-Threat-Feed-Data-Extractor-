import logging
import os
import uuid
import warnings
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import configparser
from elasticsearch import Elasticsearch, NotFoundError, RequestError
from fastapi import FastAPI, HTTPException, Header, Request, APIRouter
from pydantic import BaseModel
from stix2 import parse, Bundle
import traceback
import json

# Ignore warnings to prevent them from cluttering the output
warnings.filterwarnings('ignore')

# Read configuration from the main.ini file
script_dir = os.path.dirname(os.path.realpath(__file__))
config_file_path = os.path.join(script_dir, 'main.ini')

config = configparser.ConfigParser()
if os.path.exists(config_file_path):
    config.read(config_file_path)
    
    log_file_path = config['paths']['LOG_FILE_PATH']
    logging_level = int(config['logging']['LOGGING_LEVEL'])
    ELASTICSEARCH_URL = config['Elasticsearch']['URL']
    ELASTICSEARCH_USERNAME = config['Elasticsearch']['Username']
    ELASTICSEARCH_PASSWORD = config['Elasticsearch']['Password']

# Set up logging using the configuration settings
logging.basicConfig(filename=log_file_path, level=logging_level, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging_level)

# Initialize FastAPI application
app = FastAPI()

# Initialize Elasticsearch client with basic authentication
es = Elasticsearch(
    [ELASTICSEARCH_URL], 
    basic_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD), 
    verify_certs=False
)

logger.info("Starting FastAPI application")
 
class IndicatorQuery(BaseModel):
    indicator_value: str
    indicator_type: str
    graph: Optional[bool] = False

class NewIndicator(BaseModel):
    indicator_value: str
    indicator_type: str
    indicator_source: str
    valid_from: Optional[str] = None

class IndicatorIDQuery(BaseModel):
    indicator_id: str

class STIXBundle(BaseModel):
    type: str
    id: str
    objects: List[Dict[str, Any]]

FIELDS_TO_KEEP = [
    "type", "id", "created", "modified", "name", "description", "pattern", 
    "valid_from", "valid_until", "x_decay_timeperiod", "confidence", 
    "x_indicator_source", "labels", "x_threat_feed_list", "x_ioc_value",
    "x_ioc_type", "external_references"
]

def filter_fields(indicator):
    return {k: v for k, v in indicator.items() if k in FIELDS_TO_KEEP}

# Create Elasticsearch query to search for existing indicators by name
def search_existing_indicator(name: str) -> Optional[Dict[str, Any]]:
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"name": name}},
                    {"match": {"type": "indicator"}}
                ]
            }
        }
    }
    try:
        response = es.search(index="indicators", body=query)
        if response['hits']['total']['value'] > 0:
            return response['hits']['hits'][0]['_source']
        return None
    except Exception as e:
        logger.error(f"Failed to search existing indicator: {e}")
        logger.error(traceback.format_exc())
        return None

@app.post("/api/v1/search_indicator")
async def search_indicator(indicator_query: IndicatorQuery, api_key: str = Header(..., alias="api-key")):
    if api_key != "UD78zb11QJzWodDIQhy0tdxuGgCkskGCG1Jh8xInBSfClPmKHlxk2516LB":
        raise HTTPException(status_code=403, detail="Invalid API key")

    try:
        # Search for existing indicator in Elasticsearch
        existing_indicator = search_existing_indicator(indicator_query.indicator_value)

        if existing_indicator:
            filtered_indicator = filter_fields(existing_indicator)

            if indicator_query.graph:
                related_objects = []
                if 'x_stix_sdo_sro_id_list' in existing_indicator:
                    related_ids = existing_indicator['x_stix_sdo_sro_id_list']
                    related_objects.extend(fetch_additional_objects(related_ids))

                all_objects = [filtered_indicator] + related_objects
                stix_bundle = Bundle(objects=all_objects, allow_custom=True)
                stix_bundle = json.loads(stix_bundle.serialize())
                return {"status": "success", "bundle": stix_bundle}
            else:
                return filtered_indicator

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"name": indicator_query.indicator_value}},
                        {"match": {"type": indicator_query.indicator_type}}
                    ]
                }
            }
        }

        response = es.search(index="indicators", body=query)

        if response['hits']['total']['value'] > 0:
            filtered_indicator = filter_fields(response['hits']['hits'][0]['_source'])

            if indicator_query.graph:
                indicator_id = response['hits']['hits'][0]['_id']
                related_objects = fetch_related_objects_by_attributes(indicator_id, indicator_query.indicator_value, indicator_query.indicator_type)
                all_objects = [filtered_indicator] + related_objects

                stix_bundle = Bundle(objects=all_objects)
                return {"status": "success", "bundle": stix_bundle.serialize()}
            else:
                return filtered_indicator
        else:
            raise HTTPException(status_code=404, detail="Indicator not found")
    except Exception as e:
        logger.error(f"Failed to search Elasticsearch: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail="Failed to search Elasticsearch")

def fetch_additional_objects(related_ids):
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "terms": {
                            "id.keyword": list(related_ids)
                        }
                    }
                ]
            }
        },
        "size": 6500
    }
    try:
        response = es.search(index="indicators", body=query)
        return [hit['_source'] for hit in response['hits']['hits']]
    except Exception as e:
        logger.error(f"Failed to fetch additional objects: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch additional objects")

def fetch_related_objects_by_attributes(indicator_id: str, indicator_value: str, indicator_type: str) -> List[Dict[str, Any]]:
    query = {
        "query": {
            "bool": {
                "should": [
                    {"match": {"source_ref": indicator_id}},
                    {"match": {"target_ref": indicator_id}}
                ]
            }
        }
    }
    try:
        response = es.search(index="indicators", body=query)
        related_objects = [hit['_source'] for hit in response['hits']['hits']]
        return related_objects
    except Exception as e:
        logger.error(f"Failed to fetch related objects: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail="Failed to fetch related objects")

@app.post("/api/v1/add_indicator")
async def add_indicator(new_indicator: NewIndicator, api_key: str = Header(..., alias="api-key")):
    if api_key != "UD78zb11QJzWodDIQhy0tdxuGgCkskGCG1Jh8xInBSfClPmKHlxk2516LB":
        raise HTTPException(status_code=403, detail="Invalid API key")

    try:
        if search_existing_indicator(new_indicator.indicator_value):
            logger.info(f"Indicator with this value already exists: {new_indicator.indicator_value}")
        else:
            # Generate timestamps and unique ID for the new indicator
            now = datetime.utcnow().isoformat() + "Z"
            valid_from = new_indicator.valid_from if new_indicator.valid_from else now
            valid_until = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"
            indicator_id = f"indicator--{uuid.uuid4()}"

            indicator = {
                "type": "indicator",
                "id": indicator_id,
                "created": now,
                "modified": now,
                "name": new_indicator.indicator_value,
                "description": f"This indicator indicates a {new_indicator.indicator_type}.",
                "pattern": f"[{new_indicator.indicator_type}:value = '{new_indicator.indicator_value}']",
                "valid_from": valid_from,
                "valid_until": valid_until,
                "x_decay_timeperiod": 30,
                "confidence": "",
                "x_indicator_source": new_indicator.indicator_source,
                "labels": ["malicious", new_indicator.indicator_source],
                "x_threat_feed_list": [new_indicator.indicator_source],
                "x_ioc_value": new_indicator.indicator_value,
                "x_ioc_type": new_indicator.indicator_type,
                "x_stix_sdo_sro_id_list": []
            }

            es.index(index="indicators", document=indicator)
            return indicator
    except Exception as e:
        logger.error(f"Failed to index document to Elasticsearch: {e}")
        raise HTTPException(status_code=500, detail="Failed to index document to Elasticsearch")

@app.post("/api/v1/fetch_relationships")
async def fetch_relationships(indicator_id_query: IndicatorIDQuery, api_key: str = Header(..., alias="api-key")):
    if api_key != "UD78zb11QJzWodDIQhy0tdxuGgCkskGCG1Jh8xInBSfClPmKHlxk2516LB":
        raise HTTPException(status_code=403, detail="Invalid API key")

    try:
        relationships = fetch_related_objects(indicator_id_query.indicator_id)
        return relationships
    except Exception as e:
        logger.error(f"Failed to fetch relationships from Elasticsearch: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail="Failed to fetch relationships from Elasticsearch")

def fetch_related_objects(indicator_id):
    query = {
        "query": {
            "bool": {
                "should": [
                    {"match": {"source_ref": indicator_id}},
                    {"match": {"target_ref": indicator_id}}
                ]
            }
        }
    }
    try:
        response = es.search(index="indicators", body=query)
        related_objects = [hit['_source'] for hit in response['hits']['hits']]
        return related_objects
    except Exception as e:
        logger.error(f"Failed to fetch related objects: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail="Failed to fetch related objects")

@app.post("/api/v1/process_indicators")
async def process_indicators(request: Request, api_key: str = Header(..., alias="api-key")):
    if api_key != "UD78zb11QJzWodDIQhy0tdxuGgCkskGCG1Jh8xInBSfClPmKHlxk2516LB":
        raise HTTPException(status_code=403, detail="Invalid API key")

    try:
        # Parse incoming JSON request containing indicators
        indicators = await request.json()
        logger.info(f"Received payload: {indicators}")

        new_indicators_count = 0
        for indicator in indicators:
            try:
                indicator_value = indicator["name"]
                if not search_existing_indicator(indicator_value):
                    filtered_indicator = filter_fields(indicator)
                    es.index(index="indicators", document=filtered_indicator)
                    new_indicators_count += 1
            except KeyError as ke:
                logger.error(f"Missing key in indicator: {ke}")
                raise HTTPException(status_code=400, detail=f"Missing key in indicator: {ke}")
            except NotFoundError as nfe:
                logger.error(f"Document not found: {nfe}")
                raise HTTPException(status_code=404, detail="Document not found")
            except RequestError as re:
                logger.error(f"Request error: {re}")
                raise HTTPException(status_code=400, detail="Bad request to Elasticsearch")
            except ConnectionError as ce:
                logger.error(f"Connection error: {ce}")
                raise HTTPException(status_code=500, detail="Elasticsearch connection error")
            except Exception as e:
                logger.error(f"Unexpected error while processing indicator: {e}")
                raise HTTPException(status_code=500, detail="Internal Server Error")

        if new_indicators_count > 0:
            return {"status": "success", "new_indicators_count": new_indicators_count}
        else:
            return {"status": "no new indicators"}
    except Exception as e:
        logger.error(f"Failed to process indicators: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

app.include_router(APIRouter())
