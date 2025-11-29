import os


def test_app_file_exists():
    assert os.path.isfile("app.py"), "app.py should exist in the project root"


def test_models_file_exists():
    assert os.path.isfile("models.py"), "models.py should exist in the project root"


def test_database_file_exists():
    db_path = os.path.join("instance", "home_services.sqlite")
    assert os.path.isfile(db_path), f"Database file not found at {db_path}"
