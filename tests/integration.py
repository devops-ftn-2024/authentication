import requests
import json
import random

BASE_URL = "http://localhost:3001"

random_number = random.randint(1000, 9999)
username = "username" + str(random_number)

def test_health():
    response = requests.get(BASE_URL + "/auth/health")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello, World!"}
    print("Health check passed.")

def test_login_unauthorized():
    url = BASE_URL + "/auth/login"
    payload = json.dumps({
        "username": username,
        "password": "cascaded"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.post(url, headers=headers, data=payload)
    assert response.json() == {"message": "Unauthorized"}
    print("User unauthorized login test passed.")

def test_register():
    url = BASE_URL + "/auth/register"
    payload = json.dumps({
        "username": username,
        "password": "cascaded",
        "role": "user",
        "firstName": "Sandra",
        "lastName": "Smith",
        "address": "123 Cascade St"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.post(url, headers=headers, data=payload)
    assert response.status_code == 201
    assert response.json() == {"message": "User registered successfully"}
    print("User registration passed.")

def test_login():
    url = BASE_URL + "/auth/login"
    payload = json.dumps({
        "username": username,
        "password": "cascaded"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.post(url, headers=headers, data=payload)
    assert response.status_code == 200
    user = response.json().get("user")
    assert user is not None
    print("User login passed.")

test_health()
test_login_unauthorized()
test_register()
test_login()
