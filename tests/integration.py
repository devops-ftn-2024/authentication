import requests

BASE_URL = "http://localhost:3001"


def test_health():
    response = requests.get(f"{BASE_URL}/auth/health")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello, World!"}
