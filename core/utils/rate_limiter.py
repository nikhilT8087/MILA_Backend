import time
from redis import Redis
from fastapi import HTTPException
from config.basic_config import settings

redis_client = Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    decode_responses=True
)

def rate_limit_check(user_id: str, max_requests: int = settings.RATE_LIMIT_MAX, period: int = settings.RATE_LIMIT_PERIOD):
    key = f"rate_limit:{user_id}"
    current_time = time.time()
    request_times = redis_client.lrange(key, 0, -1)

    # Remove outdated requests
    request_times = [float(t) for t in request_times if current_time - float(t) <= period]
    if len(request_times) >= max_requests:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")

    # Update Redis
    redis_client.rpush(key, current_time)
    redis_client.expire(key, period)
