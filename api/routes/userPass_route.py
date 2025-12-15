from fastapi import APIRouter ,Depends
from api.controller.userPass_controller import (
    get_user_details , 
    add_to_fav ,
    like_user ,
    pass_user ,
    get_my_favorites , 
    get_users_who_liked_me,
    total_token)
from core.auth import get_current_user
from config.models.userPass_model import AddFavoriteRequest , LikeUserRequest , PassUserRequest

router = APIRouter()

supported_langs = ["en" , "fr"]

# Route to get the users details.
@router.get("/user/details/{user_id}",response_model =dict)
async def get_usersDetails(user_id:str , current_user: dict = Depends(get_current_user)):
    response = await get_user_details(user_id)
    return response

# Route to handle user like flow
@router.post("/user/like", response_model=dict)
async def like_user_route(
    request: LikeUserRequest,
    current_user: dict = Depends(get_current_user),
    lang: str = "en"
):
    user_id = str(current_user["_id"])

    return await like_user(
        user_id=user_id,
        liked_user_id=request.liked_user_id,
        lang=lang
    )

# Route to add users in fav list 
@router.post("/user/add-fav", response_model=dict)
async def add_favorite_user(
    request: AddFavoriteRequest,
    current_user: dict = Depends(get_current_user)
):
    logged_in_user_id = str(current_user["_id"])

    response = await add_to_fav(
        user_id=logged_in_user_id,
        favorite_user_id=request.favorite_user_id
    )

    return response

# API to return the passed user.
@router.post("/user/pass", response_model=dict)
async def pass_user_route(
    request: PassUserRequest,
    current_user: dict = Depends(get_current_user),
    lang: str = "en"
):
    user_id = str(current_user["_id"])

    return await pass_user(
        user_id=user_id,
        passed_user_id=request.passed_user_id,
        lang=lang
    )

# Route to get list of the users from favorites collection
@router.get("/user/favorites", response_model=dict)
async def get_favorite_users(
    current_user: dict = Depends(get_current_user),
    lang: str = "en"
):
    user_id = str(current_user["_id"])
    return await get_my_favorites(user_id, lang)

# Rotue to get user who liked my profile
@router.get("/user/liked-me", response_model=dict)
async def get_liked_me_users(
    current_user: dict = Depends(get_current_user),
    lang: str = "en"
):
    user_id = str(current_user["_id"])
    return await get_users_who_liked_me(user_id, lang)

# API to get the count of the token
@router.get("/user/tokens",response_model=dict)
async def get_total_tokens(
    current_user:dict = Depends(get_current_user),
    lang : str = "en"
):
    user_id = str(current_user["_id"])
    print("the id of the users is",user_id)
    return await total_token(user_id  , lang)

