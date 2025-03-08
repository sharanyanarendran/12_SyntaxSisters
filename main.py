# from fastapi import FastAPI, Depends, HTTPException
# from sqlalchemy.orm import Session
# from database import SessionLocal, engine
# import models
# import utils

# # Create the database tables (only needed once)
# models.Base.metadata.create_all(bind=engine)

# app = FastAPI()

# # Dependency to get database session
# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# @app.post("/register/")
# def register_user(username: str, email: str, password: str, db: Session = Depends(get_db)):
#     # Check if the email already exists
#     existing_user = db.query(models.User).filter(models.User.email == email).first()
#     if existing_user:
#         raise HTTPException(status_code=400, detail="Email is already registered")

#     # Hash password and create a new user
#     hashed_password = utils.hash_password(password)
#     new_user = models.User(username=username, email=email, password=hashed_password)
#     db.add(new_user)
    
#     db.commit()  # ✅ Correct usage
#     db.refresh(new_user)  # ✅ Ensure data is updated in the session

#     return {"message": "User registered successfully", "user_id": new_user.id}


# @app.post("/login/")
# def login_user(username: str, password: str, db: Session = Depends(get_db)):
#     # Find user by username instead of email
#     user = db.query(models.User).filter(models.User.username == username).first()

#     if not user or not utils.verify_password(password, user.password):
#         raise HTTPException(status_code=401, detail="Invalid username or password")

#     # Generate JWT token
#     access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    
#     return {"access_token": access_token, "token_type": "bearer"}

# from fastapi.security import OAuth2PasswordRequestForm
# from jose import JWTError, jwt
# from datetime import datetime, timedelta
# from passlib.context import CryptContext

# # Secret key for JWT
# SECRET_KEY = "your_secret_key_here"  # 🔹 Change this to a secure random key!
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)

# def create_access_token(data: dict, expires_delta: timedelta | None = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# @app.post("/login/")
# def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
#     # Get user by email
#     user = db.query(models.User).filter(models.User.email == form_data.username).first()

#     if not user or not verify_password(form_data.password, user.password):
#         raise HTTPException(status_code=401, detail="Invalid email or password")

#     # Generate JWT token
#     access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    
#     return {"access_token": access_token, "token_type": "bearer"}




 

# from fastapi import FastAPI, Depends, HTTPException
# from sqlalchemy.orm import Session
# from database import SessionLocal, engine
# import models
# import utils
# from datetime import datetime, timedelta
# from jose import jwt
# from passlib.context import CryptContext
# from jose import JWTError, jwt
# from datetime import datetime, timedelta
# from passlib.context import CryptContext

# # ✅ Keep register exactly as before
# models.Base.metadata.create_all(bind=engine)

# app = FastAPI()

# SECRET_KEY = "your_secret_key_here"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# def create_access_token(data: dict, expires_delta: timedelta | None = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# def create_access_token(data: dict, expires_delta: timedelta | None = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)

# @app.post("/register/")
# def register_user(username: str, email: str, password: str, db: Session = Depends(get_db)):
#     existing_user = db.query(models.User).filter(models.User.email == email).first()
#     if existing_user:
#         raise HTTPException(status_code=400, detail="Email is already registered")

#     hashed_password = utils.hash_password(password)
#     new_user = models.User(username=username, email=email, password=hashed_password)
    
#     db.add(new_user)
#     db.commit()
#     db.refresh(new_user)

#     return {"message": "User registered successfully", "user_id": new_user.id}

# @app.post("/login/")
# def login_user(username: str, password: str, db: Session = Depends(get_db)):
#     user = db.query(models.User).filter(models.User.username == username).first()

#     if not user or not verify_password(password, user.password):
#         raise HTTPException(status_code=401, detail="Invalid username or password")

#     access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

#     return {"access_token": access_token, "token_type": "bearer"}


# from fastapi import FastAPI, Depends, HTTPException, status, security
# from sqlalchemy.orm import Session
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from jose import jwt, JWTError
# from datetime import datetime, timedelta
# from passlib.context import CryptContext

# import models
# import utils
# from database import SessionLocal, engine

# # Create the database tables (only needed once)
# models.Base.metadata.create_all(bind=engine)

# app = FastAPI()

# # Secret key for JWT (keep this secure)
# SECRET_KEY = "your_secret_key_here"  # 🔹 Change this to a secure random key!
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# # Password hashing setup
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# # OAuth2 scheme for authentication
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login/")

# # Dependency to get database session
# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# # ✅ Hashing functions
# def hash_password(password: str) -> str:
#     return pwd_context.hash(password)

# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)

# def create_access_token(data: dict, expires_delta: timedelta | None = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
# def get_current_user(token: str = Depends(oauth2_scheme)):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise HTTPException(status_code=401, detail="Invalid token")
#         return {"username": username}
#     except JWTError:
#         raise HTTPException(status_code=401, detail="Invalid token")
# # ✅ User Registration
# @app.post("/register/")
# def register_user(username: str, email: str, password: str, db: Session = Depends(get_db)):
#     # Check if the email already exists
#     existing_user = db.query(models.User).filter(models.User.email == email).first()
#     if existing_user:
#         raise HTTPException(status_code=400, detail="Email is already registered")

#     # Hash password and create a new user
#     hashed_password = hash_password(password)
#     new_user = models.User(username=username, email=email, password=hashed_password)
#     db.add(new_user)
    
#     db.commit()
#     db.refresh(new_user)

#     return {"message": "User registered successfully", "user_id": new_user.id}

# # ✅ User Login & Token Generation
# @app.post("/login/")
# def login_user(username: str, password: str, db: Session = Depends(get_db)):
#     # Find user by username
#     user = db.query(models.User).filter(models.User.username == username).first()

#     if not user or not verify_password(password, user.password):
#         raise HTTPException(status_code=401, detail="Invalid username or password")

#     # Generate JWT token
#     access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    
#     return {"access_token": access_token, "token_type": "bearer"}


# # ✅ Token Verification for Protected Routes
# def verify_token(token: str):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         return payload  # If successful, return decoded token data
#     except JWTError:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid token",
#             headers={"WWW-Authenticate": "Bearer"},
#         )

# # ✅ Protected Route (Requires Authentication)
# @app.get("/protected/")
# def protected_route(token: str = Depends(oauth2_scheme)):
#     user_data = verify_token(token)
#     return {"message": f"Welcome, {user_data['sub']}! You accessed a protected route."}





from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

import models
import utils
from database import SessionLocal, engine

# ✅ Create the database tables (only needed once)
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# ✅ Secret key for JWT (Keep this secure)
SECRET_KEY = "your_secret_key_here"  # 🔹 Change this to a secure random key!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ✅ Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ✅ OAuth2 scheme for authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login/")  # ✅ Fixed token URL

# ✅ Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ✅ Hashing functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_reset_token(user_id: int):
    """Generates a temporary password reset token."""
    expire = datetime.utcnow() + timedelta(minutes=15)  # Token expires in 15 minutes
    payload = {"sub": str(user_id), "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

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






def create_reset_token(user_id: int, expires_delta: timedelta | None = None):
    """Generates a JWT token for password reset."""
    to_encode = {"sub": str(user_id)}
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)









# ✅ User Registration
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

# ✅ User Login & Token Generation
@app.post("/login/")
def login_user(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == username).first()

    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/request-password-reset/")
def request_password_reset(email: str, db: Session = Depends(get_db)):
    """Generates a password reset token for a user if the email exists."""
    user = db.query(models.User).filter(models.User.email == email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User with this email not found")

    reset_token = create_reset_token(user.id)  # Generate reset token

    # 🚀 In a real app, send this token via email
    return {"message": "Password reset token generated", "reset_token": reset_token}






# ✅ Token Verification for Protected Routes
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # If successful, return decoded token data
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ✅ Protected Route (Now Shows Parameters)
@app.get("/protected/")
def protected_route(token: str = Header(..., description="Access Token")):
    user_data = verify_token(token)
    return {"message": f"Welcome, {user_data['sub']}! You accessed a protected route."}

import secrets
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import models

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

@app.post("/forgot-password/")
def forgot_password(email: str, db: Session = Depends(get_db)):
    """Handles password reset requests and generates a reset token."""
    user = db.query(models.User).filter(models.User.email == email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    reset_token = create_reset_token(user.id, db)  # Generate a token

    # Ideally, you should send this token via email, but for now, we return it
    return {"message": "Password reset token generated", "reset_token": reset_token}

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
