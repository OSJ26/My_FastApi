from fastapi import FastAPI, Depends
from typing import Annotated
from .auth_router import router as auth_router
from .dependencies import User, get_current_active_user, fake_users_db
from .auth_service import AuthService

# --- SERVICE LAYER INSTANCE ---
# The AuthService is instantiated with the fake database
auth_service = AuthService(user_db=fake_users_db)

# NEW: The actual Dependency Provider Function for the service
def get_auth_service():
    """Provides the singleton instance of the AuthService to the routers."""
    return auth_service

# --- APPLICATION LIFECYCLE EVENT ---
app = FastAPI(
    title="Modular FastAPI Auth Demo",
    description="A multi-user authentication API with RBAC."
)

@app.on_event("startup")
async def startup_event():
    """
    BUSINESS LOGIC: This function runs once when the application starts.
    It checks for and creates the initial admin user if they don't exist.
    """
    print("Application starting up... Creating initial admin user.")
    # The initial admin credentials
    admin_email = "admin@example.com"
    admin_password = "adminpassword123" # WARNING: Change for production!
    admin_name = "System Admin"
    
    # Use the AuthService to create the admin user
    auth_service.create_initial_admin(admin_email, admin_name, admin_password)

# Include the authentication routes
app.include_router(auth_router)

# ... (rest of the endpoints) ...