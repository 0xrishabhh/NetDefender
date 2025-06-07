import hashlib
import requests

def is_password_pwned(password):
    """
    Check if a password has been pwned using the HIBP Pwned Passwords API.
    Returns a tuple: (is_pwned: bool, count: int)
    """
    # Hash the password using SHA-1
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    
    # Query the HIBP API with the prefix
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    # Check if the suffix exists in the response
    hashes = response.text.splitlines()
    for h in hashes:
        if h.startswith(suffix):
            count = int(h.split(':')[1])
            return True, count
    return False, 0