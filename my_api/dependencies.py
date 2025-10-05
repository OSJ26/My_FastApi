from datetime import datetime, timedelta
from typing import Annotated, Dict, Any
from enum import Enum

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from jose import JWTError, jwt

# --- CONFIGURATION CONSTANTS (JWT Settings) ---
# NOTE: In a real app, these should come from environment variables (.env file)
SECRET_KEY = "your-secret-key-super-secure" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- DATABASE SIMULATION ---
# In a real application, this would be a connection to a PostgreSQL, MongoDB, etc.
fake_users_db: Dict[str, Dict[str, Any]] = {}


# --- MODELS (Pydantic Schemas) ---

class Role(str, Enum):
    """Defines the possible user roles in the system."""
    ADMIN = "admin"
    DOCTOR = "doctor"
    NORMAL = "normal_user"

class Token(BaseModel):
    """Model for the JWT token returned on successful login."""
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """Model for data stored inside the JWT payload."""
    email: EmailStr | None = None
    
class UserBase(BaseModel):
    """Base fields for user creation."""
    email: EmailStr
    full_name: str | None = None

class UserCreate(UserBase):
    """Model used for registering a new user (includes password and role)."""
    password: str
    role: Role = Role.NORMAL # Required for Admin registration endpoint

class User(UserBase):
    """Model for public user data returned by the API."""
    disabled: bool | None = None
    role: Role = Role.NORMAL

class UserInDB(User):
    """Model for user data as stored in the database (includes hash)."""
    hashed_password: str


# --- UTILITY FUNCTIONS ---

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")
credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Creates a signed JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- CORE DEPENDENCIES ---

# We import AuthService class in functions, not globally, to break import loops.
# The actual AuthService instance (auth_service) is provided via main.get_auth_service

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)],
                     auth_service_dep: Any = Depends(lambda: None)) -> User:
    """Dependency that decodes the JWT and retrieves the user object."""
    # NOTE: The dependency injection for AuthService is tricky due to package structure.
    # We rely on main.py providing the service via `get_auth_service` 
    # which must be injected into the routers/dependecies manually if we can't import it here.
    
    # 1. Decode token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    # 2. Get the Service Instance (Simulated/Placeholder for cross-module dependency)
    # In a real setup, we would import main.get_auth_service here, but that causes 
    # the circular dependency error. Since we cannot rely on global import here:
    
    # We must retrieve the service dynamically. Since that's complicated, we define
    # the concrete user retrieval dependency here, which needs the service:
    
    # To fix this, we will temporarily rely on the AuthService being callable 
    # in the router where this dependency is used, 
    # but for a self-contained dependency file, we rely on the caller 
    # (the router) to pass the service dependency correctly, which it does. 

    # Since this dependency is NOT used by main.py, we must import AuthService 
    # (and the main.get_auth_service) only inside the function:

    # 3. Retrieve user (Importing here breaks the circular dependency)
    try:
        from .main import get_auth_service
        service = get_auth_service()
        user_db = service.get_user(token_data.email)
    except Exception as e:
        # If the service cannot be imported/found, raise a 500
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Dependency injection error: {e}"
        )


    if user_db is None:
        raise credentials_exception
        
    # Convert UserInDB (with hash) to public User model
    return User(
        email=user_db.email, 
        full_name=user_db.full_name, 
        disabled=user_db.disabled, 
        role=user_db.role
    )


def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    """Dependency that ensures the user is not disabled."""
    if current_user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user

def get_current_admin_user(current_user: Annotated[User, Depends(get_current_active_user)]) -> User:
    """Dependency that ensures the authenticated user has the 'admin' role."""
    if current_user.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to perform this action (Admin access required)."
        )
    return current_user
