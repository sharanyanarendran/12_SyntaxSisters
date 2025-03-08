from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import secrets
import models
from database import SessionLocal, engine

# Create the database tables (only needed once)
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

SECRET_KEY = "your_secret_key_here"  # Change this to a secure random key!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login/")

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Hashing functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Password reset token handling
def create_reset_token(user_id: int, db: Session):
    """Generates a password reset token and stores it in the database."""
    token = secrets.token_hex(32)  # Generate a random 32-byte token
    expires_at = datetime.utcnow() + timedelta(minutes=15)  # Token valid for 15 mins

    # Check if an existing token exists for the user
    existing_token = db.query(models.PasswordResetToken).filter(models.PasswordResetToken.user_id == user_id).first()

    if existing_token:
        # Update existing token
        existing_token.token = token
        existing_token.expires_at = expires_at
    else:
        # Create a new token entry
        reset_token = models.PasswordResetToken(user_id=user_id, token=token, expires_at=expires_at)
        db.add(reset_token)

    db.commit()
    return token

def verify_reset_token(token: str, db: Session):
    """Verifies the password reset token and returns user_id if valid."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))  # Extract user ID from token

        # Ensure user exists
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            return None

        return user_id  # Return the user ID if valid
    except JWTError:
        return None  # Invalid token

# Routes for user registration, login, and password reset

# User Registration
@app.post("/register/")
def register_user(username: str, email: str, password: str, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email is already registered")

    hashed_password = hash_password(password)
    new_user = models.User(username=username, email=email, password=hashed_password)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully", "user_id": new_user.id}

# User Login
@app.post("/login/")
def login_user(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == username).first()

    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    return {"access_token": access_token, "token_type": "bearer"}

# Forgot Password (Generate Reset Token)
@app.post("/forgot-password/")
def forgot_password(email: str, db: Session = Depends(get_db)):
    """Handles password reset requests and generates a reset token."""
    user = db.query(models.User).filter(models.User.email == email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    reset_token = create_reset_token(user.id, db)  # Generate a token

    # Ideally, send the reset token via email here
    # For now, we're just returning it
    return {"message": "Password reset token generated", "reset_token": reset_token}

# Reset Password (Validate Token and Update Password)
@app.post("/reset-password/")
def reset_password(reset_token: str, new_password: str, db: Session = Depends(get_db)):
    """Resets the user's password using a valid reset token."""
    user_id = verify_reset_token(reset_token, db)  # Verify token

    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user = db.query(models.User).filter(models.User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Hash the new password
    hashed_password = hash_password(new_password)
    user.password = hashed_password  # Update password in DB
    db.commit()

    return {"message": "Password reset successfully"}
#logut
@app.post("/logout/")
async def logout(authorization: str = Header(...)):
    """This route logs the user out by invalidating the token on the client side."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header is missing.")
    
    try:
        token = authorization.split(" ")[1]  # Extract token from "Bearer <token>"
        
        # If there's no token after the "Bearer", raise an error
        if not token:
            raise HTTPException(status_code=401, detail="Token missing from Authorization header.")
        
        # Decoding the token (no need to do anything further since JWT is stateless)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Invalidation of the token happens at the client-side; nothing needs to be done here for JWT
        return {"message": "Logged out successfully. Please discard your token."}
    
    except IndexError:
        raise HTTPException(status_code=401, detail="Token missing from Authorization header.")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Protected Route Example
@app.get("/protected/")
def protected_route(token: str = Header(..., description="Access Token")):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_data = payload  # Token decoded
        return {"message": f"Welcome, {user_data['sub']}! You accessed a protected route."}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
