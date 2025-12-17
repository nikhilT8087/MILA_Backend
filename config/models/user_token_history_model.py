from config.db_config import user_token_history_collection
from core.utils.pagination import StandardResultsSetPagination
from schemas.user_token_history_schema import TokenHistoryResponse
from services.translation import translate_message
async def get_user_token_history(user_id:str,lang:str, pagination:StandardResultsSetPagination):
    history = ((user_token_history_collection
                .find({"user_id":user_id})).sort("created_at", -1).skip(pagination.skip).limit(pagination.limit))

    return [
        TokenHistoryResponse(
            delta=doc["delta"],
            type=doc["type"],
            reason=translate_message(doc["reason"], lang),
            balance_before=int(doc["balance_before"]),
            balance_after=int(doc["balance_after"]),
            created_at=doc["created_at"],
        )
        for doc in history
    ]