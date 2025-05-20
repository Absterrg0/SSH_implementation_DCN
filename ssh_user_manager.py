#!/usr/bin/env python3
"""
SSH User Manager

This script provides utilities for managing SSH users, including:
- Creating new users with password authentication
- Adding public keys for key-based authentication
- Listing users
- Removing users

Usage:
  python ssh_user_manager.py [command] [options]

Commands:
  add-user       Add a new user with password authentication
  add-key        Add a public key for a user
  list-users     List all users
  remove-user    Remove a user
  help           Show this help message

Options depend on the command. Use -h with any command for help.
"""

import argparse
import getpass
import json
import logging
import os
import sys
from pathlib import Path
from ssh_implementation import SSHProtocol

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ssh_user_manager')

# Constants
USER_DIR = "ssh_users"
CREDENTIALS_FILE = "credentials.json"
AUTHORIZED_KEYS_DIR = "authorized_keys"

def setup_directories():
    """Create necessary directories if they don't exist."""
    os.makedirs(USER_DIR, exist_ok=True)
    os.makedirs(os.path.join(USER_DIR, AUTHORIZED_KEYS_DIR), exist_ok=True)
    
    # Create empty credentials file if it doesn't exist
    credentials_path = os.path.join(USER_DIR, CREDENTIALS_FILE)
    if not os.path.exists(credentials_path):
        with open(credentials_path, 'w') as f:
            json.dump({}, f)

def load_credentials():
    """Load user credentials from the credentials file."""
    credentials_path = os.path.join(USER_DIR, CREDENTIALS_FILE)
    try:
        with open(credentials_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        logger.warning("Credentials file not found or corrupted, creating new one")
        with open(credentials_path, 'w') as f:
            json.dump({}, f)
        return {}

def save_credentials(credentials):
    """Save user credentials to the credentials file."""
    credentials_path = os.path.join(USER_DIR, CREDENTIALS_FILE)
    with open(credentials_path, 'w') as f:
        json.dump(credentials, f, indent=2)

def load_authorized_keys(username):
    """Load authorized keys for a user."""
    key_path = os.path.join(USER_DIR, AUTHORIZED_KEYS_DIR, f"{username}.pub")
    keys = []
    
    if os.path.exists(key_path):
        with open(key_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    keys.append(line)
    
    return keys

def save_authorized_key(username, key_data):
    """Save an authorized key for a user."""
    key_path = os.path.join(USER_DIR, AUTHORIZED_KEYS_DIR, f"{username}.pub")
    
    # Append key to file
    with open(key_path, 'a') as f:
        f.write(key_data.strip() + "\n")

def add_user(args):
    """Add a new user with password authentication."""
    username = args.username
    
    # Load existing credentials
    credentials = load_credentials()
    
    # Check if user already exists
    if username in credentials:
        logger.error(f"User '{username}' already exists")
        return False
    
    # Get password
    if args.password:
        password = args.password
    else:
        password = getpass.getpass(f"Enter password for {username}: ")
        confirm = getpass.getpass("Confirm password: ")
        
        if password != confirm:
            logger.error("Passwords do not match")
            return False
    
    # Add user to credentials
    credentials[username] = password
    save_credentials(credentials)
    
    logger.info(f"User '{username}' added successfully")
    return True

def add_key(args):
    """Add a public key for a user."""
    username = args.username
    
    # Load existing credentials
    credentials = load_credentials()
    
    # Check if user exists
    if username not in credentials:
        logger.error(f"User '{username}' does not exist")
        return False
    
    # Get public key
    if args.key_file:
        try:
            with open(args.key_file, 'r') as f:
                key_data = f.read().strip()
        except FileNotFoundError:
            logger.error(f"Key file not found: {args.key_file}")
            return False
    elif args.generate:
        # Generate a new key pair
        private_key, public_key = SSHProtocol.generate_keys()
        
        # Save private key
        private_key_path = f"{username}_id_rsa"
        with open(private_key_path, 'wb') as f:
            f.write(SSHProtocol.serialize_private_key(private_key))
            
        # Get public key data
        key_data = SSHProtocol.serialize_public_key(public_key).decode('utf-8')
        
        logger.info(f"Generated new key pair for {username}")
        logger.info(f"Private key saved to {private_key_path}")
    else:
        logger.error("Either --key-file or --generate must be specified")
        return False
    
    # Save authorized key
    save_authorized_key(username, key_data)
    
    logger.info(f"Public key added for user '{username}'")
    return True

def list_users(args):
    """List all users."""
    credentials = load_credentials()
    
    if not credentials:
        print("No users found")
        return
    
    print("Users:")
    for username in credentials.keys():
        # Check if user has authorized keys
        keys = load_authorized_keys(username)
        key_status = f"{len(keys)} authorized key(s)" if keys else "No authorized keys"
        
        print(f"- {username} ({key_status})")

def remove_user(args):
    """Remove a user."""
    username = args.username
    
    # Load existing credentials
    credentials = load_credentials()
    
    # Check if user exists
    if username not in credentials:
        logger.error(f"User '{username}' does not exist")
        return False
    
    # Remove user from credentials
    del credentials[username]
    save_credentials(credentials)
    
    # Remove authorized keys file if it exists
    key_path = os.path.join(USER_DIR, AUTHORIZED_KEYS_DIR, f"{username}.pub")
    if os.path.exists(key_path):
        os.remove(key_path)
    
    logger.info(f"User '{username}' removed successfully")
    return True

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='SSH User Manager')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Add user command
    add_user_parser = subparsers.add_parser('add-user', help='Add a new user')
    add_user_parser.add_argument('username', help='Username to add')
    add_user_parser.add_argument('--password', help='Password for the user')
    
    # Add key command
    add_key_parser = subparsers.add_parser('add-key', help='Add a public key for a user')
    add_key_parser.add_argument('username', help='Username to add key for')
    key_group = add_key_parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument('--key-file', help='Path to public key file')
    key_group.add_argument('--generate', action='store_true', help='Generate a new key pair')
    
    # List users command
    subparsers.add_parser('list-users', help='List all users')
    
    # Remove user command
    remove_user_parser = subparsers.add_parser('remove-user', help='Remove a user')
    remove_user_parser.add_argument('username', help='Username to remove')
    
    return parser.parse_args()

def main():
    """Main function to run the SSH user manager."""
    args = parse_arguments()
    
    # Setup directories
    setup_directories()
    
    # Execute command
    if args.command == 'add-user':
        add_user(args)
    elif args.command == 'add-key':
        add_key(args)
    elif args.command == 'list-users':
        list_users(args)
    elif args.command == 'remove-user':
        remove_user(args)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()