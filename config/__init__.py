from motor.motor_asyncio import AsyncIOMotorClient
import os
from config.basic_config import settings
from urllib.parse import quote_plus

if settings.MONGO_USER and settings.MONGO_PASSWORD:
    username = quote_plus(settings.MONGO_USER)
    password = quote_plus(settings.MONGO_PASSWORD)
    uri = f"mongodb://{username}:{password}@{settings.MONGO_HOST}:{settings.MONGO_PORT}/{settings.MONGO_DATABASE}"
    print('db compass url dev-----------------------',uri)

else:
    uri = f"mongodb://{settings.MONGO_HOST}:{settings.MONGO_PORT}"
    print('db compass url local-----------------------',uri)


DB_NAME = os.getenv("DB_NAME", "boilerplate_db")  # <-- put your db name here


client = AsyncIOMotorClient(
    uri,
    maxPoolSize=20,
    minPoolSize=5,
    maxIdleTimeMS=30000,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=10000,
    socketTimeoutMS=30000,  # Increased to 30s for safety
    retryWrites=True,
    retryReads=True,
    compressors="zlib",
    waitQueueTimeoutMS=5000,
    maxConnecting=10
)

db = client["DB_NAME"]

user_collection = db["users"]
token_collection = db["tokens"]

