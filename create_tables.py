from database import Base, engine
from model import User


Base.metadata.create_all(bind=engine)

print("Tables created successfully!")