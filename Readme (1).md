\# Secure Authentication System



A command-line authentication system built with Python that provides secure user registration and login functionality using bcrypt password hashing.



\## Features



\- 🔐 \*\*Secure Password Hashing\*\*: Uses bcrypt with automatic salt generation

\- 👤 \*\*User Registration\*\*: Create new accounts with username/password validation

\- 🔑 \*\*User Authentication\*\*: Secure login with password verification

\- ✅ \*\*Input Validation\*\*: Comprehensive username and password validation

\- 💾 \*\*File-based Storage\*\*: Simple text file database for user credentials

\- 🎯 \*\*CLI Interface\*\*: Easy-to-use command-line menu system

\- 🔄 \*\*Session Management\*\*: Basic in-memory session tokens (demo)



\## Requirements



\- Python 3.6+

\- bcrypt library



\## Installation



1\. \*\*Clone or download the project files\*\*



2\. \*\*Install the required dependency\*\*:

&nbsp;  ```bash

&nbsp;  pip install bcrypt

&nbsp;  ```



\## Usage



\### Running the Application



```bash

python auth.py

```



\### Menu Options



1\. \*\*Register a new user\*\*

&nbsp;  - Create a new account with username and password

&nbsp;  - Username requirements: 3-20 characters, alphanumeric and underscores only

&nbsp;  - Password requirements: 

&nbsp;    - At least 6 characters, maximum 50

&nbsp;    - At least one lowercase letter

&nbsp;    - At least one uppercase letter  

&nbsp;    - At least one digit



2\. \*\*Login\*\*

&nbsp;  - Authenticate with existing credentials

&nbsp;  - Successful login creates a demo session token



3\. \*\*Exit\*\*

&nbsp;  - Close the application



\## Security Features



\- \*\*Bcrypt Hashing\*\*: Passwords are hashed using industry-standard bcrypt algorithm

\- \*\*Salt Generation\*\*: Automatic salt generation for each password

\- \*\*Secure Verification\*\*: Constant-time password verification

\- \*\*Input Sanitization\*\*: Comprehensive input validation and error handling

\- \*\*No Plain Text Storage\*\*: Passwords are never stored in plain text



\## File Structure



```

auth.py          # Main application file

users.txt        # User database (created automatically)

```



\## Data Storage



User credentials are stored in `users.txt` with the following format:

```

username,hashed\_password

```



Example:

```

john\_doe,$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdCvSrIPl6dmV7G

```



\## API Reference



\### Core Functions



\- `hash\_password(password)` - Hashes a plain text password

\- `verify\_password(password, hashed)` - Verifies a password against its hash

\- `register\_user(username, password)` - Registers a new user

\- `login\_user(username, password)` - Authenticates a user

\- `user\_exists(username)` - Checks if username exists

\- `validate\_username(username)` - Validates username format

\- `validate\_password(password)` - Validates password strength



\## Example Usage Flow



```

=== MULTI-DOMAIN INTELLIGENCE PLATFORM ===

&nbsp; Secure Authentication System

==================================================



\[1] Register a new user

\[2] Login  

\[3] Exit

--------------------------------------------------



Please select an option (1-3): 1



--- USER REGISTRATION ---

Enter a username: alice123

Enter a password: SecurePass123

Confirm password: SecurePass123

Success: User 'alice123' registered successfully!

```



\## Limitations \& Notes



\- \*\*In-memory sessions\*\*: Session data is lost when the program exits

\- \*\*Single-file storage\*\*: User data stored in plain text file (encrypted passwords only)

\- \*\*No concurrent access\*\*: Not designed for multiple simultaneous users

\- \*\*Educational purpose\*\*: Designed for learning authentication concepts



\## Security Considerations



For production use, consider:

\- Using a proper database instead of text files

\- Implementing proper session persistence

\- Adding rate limiting for login attempts

\- Using environment variables for configuration

\- Implementing proper logging and monitoring



\## Troubleshooting



\- Ensure `bcrypt` is installed: `pip install bcrypt`

\- Check file permissions for `users.txt`

\- Verify Python version (3.6+ required)



\## License



Educational project - feel free to use and modify for learning purposes.



---



\*\*Note\*\*: This is a demonstration system for educational purposes. For production applications, consider using established authentication frameworks and security best practices.

