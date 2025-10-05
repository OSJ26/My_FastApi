from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from .dependencies import (
    Token,
    User,
    UserCreate,
    get_auth_service, # <-- Correct dependency function
    get_current_active_user,
    Role
)
from .auth_service import AuthService # <-- Import the class itself
from .error_messages import USER_ALREADY_REGISTERED, INCORRECT_CREDENTIALS 
from .dependencies import get_current_admin_user # <-- The admin dependency

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ... (Rest of the router logic using injected dependencies) ...

# Ensure the register route is correct:
@router.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate, 
    service: Annotated[AuthService, Depends(get_auth_service)],
    current_admin: Annotated[User, Depends(get_current_admin_user)] # Requires Admin token
):
    try:
        new_user_db = service.register_new_user(
            user_data.email, 
            user_data.full_name, 
            user_data.password,
            user_data.role # Pass the role from the request body
        )
    except ValueError as e:
        if str(e) == USER_ALREADY_REGISTERED:
            raise HTTPException(status_code=400, detail=USER_ALREADY_REGISTERED)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    
    return User.model_validate(new_user_db)

# ... (Login route logic) ...
