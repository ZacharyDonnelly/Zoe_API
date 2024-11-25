import requests

# Register User
url = "http://127.0.0.1:8000/register"
payload = {"username": "test@test.com", "password": "1234234"}
headers = {"Content-Type": "application/json"}

response = requests.post(url, json=payload, headers=headers)
print(response.json())

# Token Authentication
url = "http://127.0.0.1:8000/token"
payload = {"username": "test@test.com", "password": "1234234"}
headers = {"Content-Type": "application/json"}

response = requests.post(url, json=payload, headers=headers)
print(response.json())
