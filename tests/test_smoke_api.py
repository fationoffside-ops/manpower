import requests

BASE_URL = "http://localhost:5000"

def test_signin():
    # Replace with a valid test user from your registrations.json
    payload = {
        "email": "mutalvita@gmail.com",
        "password": "testpassword"  # Use the correct password for your test user
    }
    r = requests.post(f"{BASE_URL}/api/signin", json=payload)
    assert r.status_code == 200 or r.status_code == 403, f"Unexpected status: {r.status_code}"
    print("Signin response:", r.json())

def test_profile():
    # First, sign in to get the session cookie
    payload = {
        "email": "mutalvita@gmail.com",
        "password": "testpassword"  # Use the correct password for your test user
    }
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/signin", json=payload)
    assert r.status_code == 200 or r.status_code == 403, f"Unexpected status: {r.status_code}"
    # Now, access profile
    r2 = s.get(f"{BASE_URL}/api/profile")
    assert r2.status_code == 200, f"Profile status: {r2.status_code}"
    print("Profile response:", r2.json())

if __name__ == "__main__":
    test_signin()
    test_profile()
