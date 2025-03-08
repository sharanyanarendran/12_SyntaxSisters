from database import Base, engine

# This creates the database tables
Base.metadata.create_all(bind=engine)

print("Database tables created successfully!")
