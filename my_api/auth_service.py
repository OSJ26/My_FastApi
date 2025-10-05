# ... (rest of imports)
from .dependencies import UserInDB, Role # Import the Role enum

class AuthService:
    # ... (rest of the class) ...

    def create_initial_admin(self, email: str, full_name: str, password: str) -> UserInDB:
        """
        BUSINESS LOGIC: Creates the very first admin user.
        This method is designed to be called only once at application startup.
        """
        if self.get_user(email):
            print(f"Admin user {email} already exists. Skipping creation.")
            return None
        
        hashed_password = self._get_password_hash(password)
        
        admin_user_db = UserInDB(
            email=email,
            full_name=full_name,
            hashed_password=hashed_password,
            disabled=False,
            role=Role.ADMIN # Assign the 'admin' role
        )
        self.db[email] = admin_user_db.model_dump()
        print(f"Admin user {email} created successfully.")
        return admin_user_db

    def register_new_user(self, email: str, full_name: str | None, plain_password: str, role: Role = Role.NORMAL) -> UserInDB:
        """
        BUSINESS LOGIC: Handles new user registration for Doctor or Normal User roles.
        Admin users are created via a separate process.
        """
        if self.get_user(email):
            raise ValueError(USER_ALREADY_REGISTERED) 

        hashed_password = self._get_password_hash(plain_password)
        
        new_user_db = UserInDB(
            email=email,
            full_name=full_name,
            hashed_password=hashed_password,
            disabled=False,
            role=role # Use the provided role
        )
        self.db[email] = new_user_db.model_dump()
        return new_user_db