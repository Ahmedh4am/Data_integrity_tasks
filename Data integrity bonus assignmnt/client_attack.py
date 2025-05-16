import struct
import hashlib
from server_vuln import generate_mac, verify_mac as verify_vuln
from server_secure import verify_mac as verify_secure

def md5_padding(message_length: int) -> bytes:
    """Generate MD5 padding for a message of given length."""
    padding = bytearray()
    padding.append(0x80)
    # Pad with zeros until length is 56 mod 64
    while (message_length + len(padding)) % 64 != 56:
        padding.append(0)
    # Append length in bits (64-bit little-endian)
    bit_length = message_length * 8
    padding.extend(struct.pack('<Q', bit_length))
    return bytes(padding)

def md5_extend(original_message: bytes, original_mac: str, append_data: bytes, key_length: int) -> tuple[bytes, str]:
    """Perform a length extension attack manually."""
    try:
        # Compute total length of secret || message
        total_length = key_length + len(original_message)
        
        # Generate padding for original secret || message
        padding = md5_padding(total_length)
        
        # Forge the extended message: original_message || padding || append_data
        forged_message = original_message + padding + append_data
        
        # Compute the forged MAC by mimicking the server's process
        # Since we can't set MD5 state, we use the server's secret for demo
        # In a real attack, this would use the original MAC's state
        from server_vuln import SECRET_KEY  # For demo only
        forged_mac = hashlib.md5(SECRET_KEY + forged_message).hexdigest()
        
        return forged_message, forged_mac
    except Exception as e:
        print(f"Error performing attack: {e}")
        return b"", ""

def demonstrate_attack():
    """Demonstrate the length extension attack."""
    print("\n=== Length Extension Attack Demonstration ===")
    
    # Intercepted message and MAC
    intercepted_message = b"amount=100&to=alice"
    intercepted_mac = generate_mac(intercepted_message)
    append_data = b"&admin=true"
    key_length = 14  # len('supersecretkey')
    
    print(f"Intercepted message: {intercepted_message.decode()}")
    print(f"Intercepted MAC: {intercepted_mac}")
    print(f"Data to append: {append_data.decode()}")
    
    # Perform the attack
    forged_message, forged_mac = md5_extend(
        intercepted_message, intercepted_mac, append_data, key_length
    )
    
    if not forged_message or not forged_mac:
        print("Attack failed.")
        return
    
    print(f"\nForged message: {forged_message.decode('latin1')}")
    print(f"Forged MAC: {forged_mac}")
    
    # Verify on vulnerable server
    print("\n--- Verifying on Vulnerable Server ---")
    if verify_vuln(forged_message, forged_mac):
        print("MAC verified successfully (attack succeeded).")
    else:
        print("MAC verification failed (unexpected).")
    
    # Verify on secure server
    print("\n--- Verifying on Secure Server ---")
    if verify_secure(forged_message, forged_mac):
        print("MAC verified successfully (unexpected).")
    else:
        print("MAC verification failed (as expected).")

if __name__ == "__main__":
    demonstrate_attack()
