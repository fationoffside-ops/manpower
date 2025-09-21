import sys
import os
import json

# Ensure project root is on sys.path so imports like 'import app' work
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app import app

client = app.test_client()

# 1) Test GET /api/contracts
r = client.get('/api/contracts')
print('GET /api/contracts', r.status_code, 'json=', r.is_json)
try:
    print('Body:', r.get_json())
except Exception as e:
    print('Body not json:', r.data[:200])

# 2) Test signup contractor with company-only payload
import time

unique = str(int(time.time()))
payload = {
    'company': 'TestCo',
    'email': f'testco+{unique}@example.com',
    'phone': '+1234567890',
    'industry': 'technology',
    'city': 'Testville',
    'password': 'Longenough1!',
    'confirmPassword': 'Longenough1!',
    'signupRole': 'contractors'
}

r = client.post('/api/signup', data=json.dumps(payload), content_type='application/json')
print('POST /api/signup', r.status_code)
try:
    print('Body:', r.get_json())
except Exception as e:
    print('Body not json:', r.data[:200])

# If signup succeeded, try signing in to test authenticated GET /api/contracts
if r.status_code == 200 or (r.is_json and r.get_json().get('success')):
    # Attempt to auto-verify the user by reading the verification_tokens file and calling /verify
    tokens_path = os.path.join(ROOT, 'verification_tokens.json')
    verified = False
    if os.path.exists(tokens_path):
        try:
            with open(tokens_path, 'r', encoding='utf-8') as f:
                tokens = json.load(f)
            # Find token for our email
            for t, info in tokens.items():
                if info.get('email') == payload['email']:
                    print('Found verification token, calling /verify')
                    resp = client.get('/verify?token=' + t)
                    print('GET /verify', resp.status_code)
                    verified = True
                    break
        except Exception as e:
            print('Failed to read verification tokens:', e)

    if not verified:
        # Fallback: mark email_verified directly in registrations file
        try:
            regs_path = os.path.join(ROOT, 'data', 'registrations.json')
            if os.path.exists(regs_path):
                with open(regs_path, 'r', encoding='utf-8') as f:
                    regs = json.load(f)
                for rrec in regs:
                    p = rrec.get('payload') if isinstance(rrec, dict) else rrec
                    if p and p.get('email') == payload['email']:
                        p['email_verified'] = True
                        break
                with open(regs_path, 'w', encoding='utf-8') as f:
                    json.dump(regs, f, indent=2)
                verified = True
                print('Marked user as verified in registrations.json')
        except Exception as e:
            print('Failed to mark verified in registrations.json:', e)

    signin_payload = {'email': payload['email'], 'password': payload['password']}
    r2 = client.post('/api/signin', data=json.dumps(signin_payload), content_type='application/json')
    print('POST /api/signin', r2.status_code)
    try:
        print('Signin body:', r2.get_json())
    except Exception:
        print('Signin body not json:', r2.data[:200])

    # Now GET contracts authenticated
    r3 = client.get('/api/contracts')
    print('GET /api/contracts (auth) ->', r3.status_code, 'json=', r3.is_json)
    try:
        print('Body:', r3.get_json())
    except Exception:
        print('Body not json:', r3.data[:200])
