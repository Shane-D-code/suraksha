import requests

# Login
login_resp = requests.post(
    'http://localhost:8000/api/v1/auth/login',
    data={'username': 'admin', 'password': 'admin123'},
    headers={'Content-Type': 'application/x-www-form-urlencoded'}
)
token = login_resp.json()['access_token']

# Get overrides
overrides_resp = requests.get(
    'http://localhost:8000/api/v1/admin/overrides',
    headers={'Authorization': f'Bearer {token}'}
)
print("Admin Overrides:")
print(overrides_resp.json())
