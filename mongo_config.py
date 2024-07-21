from pymongo import MongoClient
import os
from dotenv import load_dotenv

def get_mongo_client():
    load_dotenv()
    mongo_host = os.getenv("MONGO_HOST", "localhost")
    mongo_port = int(os.getenv("MONGO_PORT", 27017))
    client = MongoClient(mongo_host, mongo_port)
    return client

def get_database(db_name="services"):
    client = get_mongo_client()
    return client[db_name]