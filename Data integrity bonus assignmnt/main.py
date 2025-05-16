import sys

try:
    from server_vuln import generate_mac as generate_mac_vuln, verify_mac as verify_mac_vuln
    from server_secure import generate_mac as generate_mac_secure, verify_mac as verify_mac_secure
    from client_attack import demonstrate_attack
except ImportError as e:
    print(f"Error: Failed to import required modules: {e}")
    print("Ensure server_vuln.py, server_secure.py, and client_attack.py are in the same directory.")
    sys.exit(1)

def print_menu():
    """Display the interactive menu."""
    print("\n=== MAC Demonstration System ===")
    print("1. Generate MAC (Vulnerable Server)")
    print("2. Verify MAC (Vulnerable Server)")
    print("3. Generate MAC (Secure Server)")
    print("4. Verify MAC (Secure Server)")
    print("5. Demonstrate Length Extension Attack")
    print("6. Exit")

def get_user_input(prompt: str) -> str:
    """Get user input with error handling."""
    try:
        return input(prompt).strip()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error reading input: {e}")
        return ""

def main():
    while True:
        print_menu()
        choice = get_user_input("Enter your choice (1-6): ")
        
        if choice == "1":
            # Generate MAC on vulnerable server
            message = get_user_input("Enter message: ")
            try:
                message_bytes = message.encode('utf-8')
                mac = generate_mac_vuln(message_bytes)
                print(f"Generated MAC: {mac}")
            except Exception as e:
                print(f"Error generating MAC: {e}")
        
        elif choice == "2":
            # Verify MAC on vulnerable server
            message = get_user_input("Enter message: ")
            mac = get_user_input("Enter MAC: ")
            try:
                message_bytes = message.encode('utf-8')
                if verify_mac_vuln(message_bytes, mac):
                    print("MAC verified successfully.")
                else:
                    print("MAC verification failed.")
            except Exception as e:
                print(f"Error verifying MAC: {e}")
        
        elif choice == "3":
            # Generate MAC on secure server
            message = get_user_input("Enter message: ")
            try:
                message_bytes = message.encode('utf-8')
                mac = generate_mac_secure(message_bytes)
                print(f"Generated MAC: {mac}")
            except Exception as e:
                print(f"Error generating MAC: {e}")
        
        elif choice == "4":
            # Verify MAC on secure server
            message = get_user_input("Enter message: ")
            mac = get_user_input("Enter MAC: ")
            try:
                message_bytes = message.encode('utf-8')
                if verify_mac_secure(message_bytes, mac):
                    print("MAC verified successfully.")
                else:
                    print("MAC verification failed.")
            except Exception as e:
                print(f"Error verifying MAC: {e}")
        
        elif choice == "5":
            # Demonstrate length extension attack
            try:
                demonstrate_attack()
            except Exception as e:
                print(f"Error running attack demonstration: {e}")
        
        elif choice == "6":
            print("Exiting...")
            sys.exit(0)
        
        else:
            print("Invalid choice. Please select 1-6.")

if __name__ == "__main__":
    main()
