# auth.py
import bcrypt
import os
import re
import secrets
import time

USER_DATA_FILE = "users.txt"

# ------------------------
# Password hashing helpers
# ------------------------
def hash_password(plain_text_password: str) -> str:
    """
    Hashes a password using bcrypt with automatic salt generation.
    Returns the hashed password as a UTF-8 string.
    """
    if not isinstance(plain_text_password, str):
        raise TypeError("Password must be a string")
    password_bytes = plain_text_password.encode("utf-8")
    salt = bcrypt.gensalt()  # default cost is fine for learning
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_text_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against a stored bcrypt hash.
    Returns True if the password matches, False otherwise.
    """
    if not plain_text_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(plain_text_password.encode("utf-8"),
                              hashed_password.encode("utf-8"))
    except Exception:
        return False


# ------------------------
# File / user helpers
# ------------------------
def user_exists(username: str) -> bool:
    """
    Checks if a username already exists in the user database.
    """
    if not os.path.exists(USER_DATA_FILE):
        return False
    with open(USER_DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",", 1)
            if len(parts) >= 1 and parts[0] == username:
                return True
    return False


def register_user(username: str, password: str) -> bool:
    """
    Registers a new user by hashing their password and storing credentials.
    Returns True if registration successful, False if username already exists.
    """
    if user_exists(username):
        print(f"Error: Username '{username}' already exists.")
        return False

    hashed = hash_password(password)
    # Append username and hashed password to file
    with open(USER_DATA_FILE, "a", encoding="utf-8") as f:
        f.write(f"{username},{hashed}\n")
    print(f"Success: User '{username}' registered successfully!")
    return True


def login_user(username: str, password: str) -> bool:
    """
    Authenticates a user by verifying their username and password.
    Returns True if authentication successful, False otherwise.
    """
    if not os.path.exists(USER_DATA_FILE):
        print("Error: No users are registered yet.")
        return False

    with open(USER_DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",", 1)
            if len(parts) != 2:
                continue
            stored_username, stored_hash = parts
            if stored_username == username:
                if verify_password(password, stored_hash):
                    print(f"Success: Welcome, {username}!")
                    return True
                else:
                    print("Error: Invalid password.")
                    return False

    print("Error: Username not found.")
    return False


# ------------------------
# Validation helpers
# ------------------------
def validate_username(username: str):
    """
    Validates username format: 3-20 characters, alphanumeric and underscores allowed.
    Returns (True, "") if valid else (False, error_message)
    """
    if not username:
        return False, "Username cannot be empty."
    if len(username) < 3 or len(username) > 20:
        return False, "Username must be between 3 and 20 characters."
    if not re.match(r"^[A-Za-z0-9_]+$", username):
        return False, "Username may contain letters, digits and underscores only."
    return True, ""


def validate_password(password: str):
    """
    Validates password strength.
    Returns (True, "") if valid else (False, error_message)
    Criteria (example):
      - at least 6 characters
      - at most 50 characters
      - contains at least one lowercase, one uppercase and one digit
    """
    if not password:
        return False, "Password cannot be empty."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    if len(password) > 50:
        return False, "Password must be at most 50 characters."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    # optional: encourage special characters
    return True, ""


# ------------------------
# Optional: simple sessions
# ------------------------
_sessions = {}  # in-memory: username -> token (only for runtime demo)


def create_session(username: str) -> str:
    token = secrets.token_hex(16)
    _sessions[username] = {"token": token, "time": time.time()}
    return token


# ------------------------
# CLI Interface
# ------------------------
def display_menu():
    """Displays the main menu options."""
    print("\n" + "=" * 50)
    print("  MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print("  Secure Authentication System")
    print("=" * 50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-" * 50)


def main():
    """Main program loop."""
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == "1":
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password = input("Enter a password: ").strip()
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            register_user(username, password)

        elif choice == "2":
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            if login_user(username, password):
                # create a session token (demo)
                token = create_session(username)
                print("(Session token created; demo only.)")
                input("\nPress Enter to return to main menu...")

        elif choice == "3":
            # Exit
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()