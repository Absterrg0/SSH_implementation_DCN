# SSH Protocol Implementation

This project implements a simplified version of the SSH (Secure Shell) protocol in Python. It provides both a server and client implementation that addresses the following challenges:

1. **Encrypted connections** - Using standard cryptographic libraries
2. **Low-latency performance** - Optimized for quick response times
3. **Session persistence** - Management of active connections
4. **Secure authentication** - Both password and public key auth

## Features

- Secure encrypted communications using RSA for key exchange and AES for session encryption
- Password and public key authentication methods
- Session management with timeout handling
- Command execution interface
- User management utilities

## Project Structure

- **ssh_implementation.py** - Core SSH protocol implementation with encryption and authentication
- **ssh_server.py** - Server application to accept and handle client connections
- **ssh_client.py** - Client application to connect to SSH servers
- **ssh_user_manager.py** - Utility for managing SSH users and keys

## Requirements

- Python 3.7+
- cryptography library (`pip install cryptography`)

## Setup

1. Install dependencies:
   ```
   pip install cryptography
   ```

2. Make the scripts executable (Linux/macOS):
   ```
   chmod +x ssh_server.py ssh_client.py ssh_user_manager.py
   ```

## Usage

### Server

Start the SSH server:

```bash
python ssh_server.py [--host HOST] [--port PORT] [--debug]
```

Options:
- `--host HOST` - Host address to bind to (default: 0.0.0.0)
- `--port PORT` - Port number to listen on (default: 2222)
- `--debug` - Enable debug logging

### User Management

Before connecting clients, you'll need to add users:

```bash
# Add a new user with password authentication
python ssh_user_manager.py add-user username [--password PASSWORD]

# Add a public key for a user (either provide existing key or generate new one)
python ssh_user_manager.py add-key username --key-file PATH_TO_KEY
python ssh_user_manager.py add-key username --generate

# List all users
python ssh_user_manager.py list-users

# Remove a user
python ssh_user_manager.py remove-user username
```

### Client

Connect to the SSH server:

```bash
python ssh_client.py [--host HOST] [--port PORT] [--user USERNAME] [--password PASSWORD | --key KEY_PATH] [--debug]
```

Options:
- `--host HOST` - Server hostname or IP address (default: localhost)
- `--port PORT` - Server port number (default: 2222)
- `--user USERNAME` - Username for authentication (default: admin)
- `--password PASSWORD` - Password for authentication
- `--key KEY_PATH` - Path to private key file for authentication
- `--debug` - Enable debug logging

If neither `--password` nor `--key` is specified, you'll be prompted for a password.

## Security Considerations

This implementation is for educational and demonstration purposes and has several limitations:

1. The SSH protocol implementation is simplified and not fully compliant with RFC 4251-4254
2. Password authentication stores passwords in plaintext (in a real implementation, use salted hashing)
3. Limited command execution environment (doesn't execute actual system commands)
4. No support for terminal features like window size, control sequences, etc.
5. Missing security features like strict host key checking

In a production environment, consider using established SSH libraries like Paramiko or OpenSSH.

## How It Works

### Key Exchange Process

1. Client connects to server
2. Server and client exchange SSH banners
3. Server sends its public key to client
4. Client sends its public key to server
5. Server generates a random session key and encrypts it with client's public key
6. Server sends encrypted session key to client
7. Client decrypts session key with its private key
8. Both sides verify the connection with a ping-pong exchange
9. All subsequent communication is encrypted with the session key using AES-GCM

### Authentication Methods

#### Password Authentication
1. Client sends username and password (encrypted with session key)
2. Server verifies username and password against stored credentials
3. Server sends authentication result

#### Public Key Authentication
1. Client sends username and request for public key authentication
2. Server sends a random challenge
3. Client signs the challenge with its private key
4. Server verifies signature using client's public key from authorized_keys
5. Server sends authentication result

### Session Management

The server maintains active sessions with:
- Session timeout handling
- Unique session identifiers
- Command history tracking
- Activity timestamp updates

## License

This project is provided for educational purposes only.