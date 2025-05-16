import hmac
import hashlib

SECRET_KEY = b'supersecretkey'  # Unknown to attacker

def generate_mac(message: bytes) -> str:
    """Generate a MAC for the message using secure HMAC-MD5."""
    try:
        return hmac.new(SECRET_KEY, message, hashlib.md5).hexdigest()
    except Exception as e:
        print(f"Error generating MAC: {e}")
        return ""

def verify_mac(message: bytes, mac: str) -> bool:
    """Verify if the provided MAC is valid for the message."""
    try:
        expected_mac = generate_mac(message)
        return hmac.compare_digest(mac.lower(), expected_mac.lower())
    except Exception as e:
        print(f"Error verifying MAC: {e}")
        return False
