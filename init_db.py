import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User, ServiceType
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.path.join("instance", "home_services.sqlite")
DB_URI = f"sqlite:///{DB_PATH}"

engine = create_engine(DB_URI, echo=False, future=True)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine, future=True)

def bootstrap():
    s = Session()
    services = [
        ServiceType(name="Plumbing", description="Repair leaks, install fittings."),
        ServiceType(name="Electrical", description="Fix wiring, install switches."),
        ServiceType(name="Cleaning", description="Home cleaning service."),
    ]
    s.add_all(services)
    if not s.query(User).filter_by(username="admin").first():
        admin = User(
            username="admin",
            email_hash=None,
            password_hash=generate_password_hash("adminpass"),
            role="admin",
            email_verified=True
        )
        s.add(admin)
    s.commit()
    s.close()
    print("DB initialized, admin user created (username: admin, password: adminpass)")

if __name__ == "__main__":
    os.makedirs("instance", exist_ok=True)
    bootstrap()
