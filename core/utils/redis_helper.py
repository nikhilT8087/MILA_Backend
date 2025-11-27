import redis.asyncio as redis
from config.basic_config import settings
import asyncio
from typing import Optional

# Create Redis connection pool for better performance
redis_pool = redis.ConnectionPool(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    decode_responses=True,
    max_connections=20,  # Maximum connections in pool
    retry_on_timeout=True,
    socket_connect_timeout=5,
    socket_timeout=10,
    health_check_interval=30
)

# Create async Redis client with connection pool
redis_client = redis.Redis(connection_pool=redis_pool)

async def store_in_redis(key: str, value: str, ttl: int):
    """Store value in Redis with TTL asynchronously"""
    try:
        await redis_client.setex(key, ttl, value)
    except Exception as e:
        print(f"Redis store error: {e}")
        # Fallback to sync operation if async fails
        sync_redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True
        )
        sync_redis.setex(key, ttl, value)
        sync_redis.close()

async def get_from_redis(key: str) -> Optional[str]:
    """Get value from Redis asynchronously"""
    try:
        value = await redis_client.get(key)
        return value
    except Exception as e:
        print(f"Redis get error: {e}")
        # Fallback to sync operation if async fails
        sync_redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True
        )
        value = sync_redis.get(key)
        sync_redis.close()
        return value

async def delete_from_redis(key: str):
    """Delete key from Redis asynchronously"""
    try:
        await redis_client.delete(key)
    except Exception as e:
        print(f"Redis delete error: {e}")
        # Fallback to sync operation if async fails
        sync_redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True
        )
        sync_redis.delete(key)
        sync_redis.close()

async def close_redis_connections():
    """Close Redis connections properly"""
    try:
        await redis_client.close()
        await redis_pool.disconnect()
    except Exception as e:
        print(f"Error closing Redis connections: {e}")

# Backward compatibility functions (sync versions)
def store_in_redis_sync(key: str, value: str, ttl: int):
    """Synchronous version for backward compatibility"""
    sync_redis = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        decode_responses=True
    )
    sync_redis.setex(key, ttl, value)
    sync_redis.close()

def get_from_redis_sync(key: str) -> Optional[str]:
    """Synchronous version for backward compatibility"""
    sync_redis = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        decode_responses=True
    )
    value = sync_redis.get(key)
    sync_redis.close()
    return value

def delete_from_redis_sync(key: str):
    """Synchronous version for backward compatibility"""
    sync_redis = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        decode_responses=True
    )
    sync_redis.delete(key)
    sync_redis.close()