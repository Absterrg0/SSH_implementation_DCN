#!/usr/bin/env python3
"""
SSH Client Implementation

This script provides a command-line SSH client to connect to the SSH server.
It supports both password and public key authentication.

Usage:
  python ssh_client.py [--host HOST] [--port PORT] [--user USERNAME] 
                       [--password PASSWORD | --key KEY_PATH]

Options:
  --host HOST        Server hostname or IP address [default: localhost]
  --port PORT        Server port number [default: 2222]
  --user USERNAME    Username for authentication [default: admin]
  --password PASSWORD Username's password for authentication
  --key KEY_PATH     Path to private key file for authentication
  --debug            Enable debug logging
"""

import argparse
import getpass
import logging
import os
import sys
import time
from ssh_implementation import SSHClient, DEFAULT_PORT

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ssh_client')

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='SSH Client Implementation')
    parser.add_argument('--host', default='localhost', help='Server hostname or IP address')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Server port number')
    parser.add_argument('--user', default='admin', help='Username for authentication')
    
    # Password or key authentication options
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument('--password', help='Password for authentication')
    auth_group.add_argument('--key', help='Path to private key file for authentication')
    
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    return parser.parse_args()

def interactive_shell(client):
    """Run an interactive shell with the SSH server."""
    print(f"Connected to SSH server at {client.host}:{client.port}")
    print("Type 'exit' to disconnect.")
    
    try:
        # Display welcome message
        welcome = client.receive_data()
        if welcome:
            print(welcome.decode())
        
        while True:
            # Get prompt from server
            prompt_data = client.receive_data()
            if not prompt_data:
                print("Connection closed by server.")
                break
                
            prompt = prompt_data.decode()
            print(prompt, end='', flush=True)
            
            # Get user input
            try:
                command = input()
            except EOFError:
                print("\nConnection closed.")
                break
                
            # Send command to server
            client.send_data(command.encode())
            
            # Handle exit command
            if command.strip() == 'exit':
                # Get goodbye message
                goodbye = client.receive_data()
                if goodbye:
                    print(goodbye.decode())
                break
                
            # Get command output
            output = client.receive_data()
            if output:
                print(output.decode(), end='')
            else:
                print("Connection closed by server.")
                break
    
    except KeyboardInterrupt:
        print("\nConnection interrupted by user.")
    except Exception as e:
        logger.error(f"Shell error: {e}")

def main():
    """Main function to run the SSH client."""
    args = parse_arguments()
    
    # Set debug logging if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create SSH client
    client = SSHClient(host=args.host, port=args.port)
    
    try:
        # Connect to server
        logger.info(f"Connecting to SSH server at {args.host}:{args.port}")
        if not client.connect():
            logger.error("Failed to connect to server")
            sys.exit(1)
            
        # Perform key exchange
        logger.info("Performing key exchange")
        if not client.key_exchange():
            logger.error("Key exchange failed")
            sys.exit(1)
            
        # Authenticate
        if args.key:
            # Public key authentication
            logger.info(f"Authenticating as {args.user} using public key")
            if not os.path.exists(args.key):
                logger.error(f"Private key file not found: {args.key}")
                sys.exit(1)
                
            if not client.authenticate_publickey(args.user, args.key):
                logger.error("Authentication failed")
                sys.exit(1)
        else:
            # Password authentication
            password = args.password
            if not password:
                password = getpass.getpass(f"Password for {args.user}: ")
                
            logger.info(f"Authenticating as {args.user} using password")
            if not client.authenticate_password(args.user, password):
                logger.error("Authentication failed")
                sys.exit(1)
                
        # Start interactive shell
        interactive_shell(client)
        
    except Exception as e:
        logger.error(f"Client error: {e}")
        sys.exit(1)
    finally:
        # Close connection
        client.close()

if __name__ == "__main__":
    main()