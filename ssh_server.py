#!/usr/bin/env python3
"""
SSH Server Implementation

This script runs the SSH server component that handles client connections,
authentication, session management, and command execution.

Usage:
  python ssh_server.py [--host HOST] [--port PORT]

Options:
  --host HOST    Host address to bind to [default: 0.0.0.0]
  --port PORT    Port number to listen on [default: 2222]
"""

import argparse
import logging
import signal
import sys
import os
from ssh_implementation import SSHServer, DEFAULT_PORT

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ssh_server')

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='SSH Server Implementation')
    parser.add_argument('--host', default='0.0.0.0', help='Host address to bind to')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port number to listen on')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    return parser.parse_args()

def setup_signal_handlers(server):
    """Set up signal handlers for graceful shutdown."""
    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, shutting down...")
        server.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def main():
    """Main function to run the SSH server."""
    args = parse_arguments()
    
    # Set debug logging if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create user directory if it doesn't exist
    os.makedirs("ssh_users", exist_ok=True)
    
    # Create and start the server
    server = SSHServer(host=args.host, port=args.port)
    
    # Set up signal handlers
    setup_signal_handlers(server)
    
    try:
        logger.info(f"Starting SSH server on {args.host}:{args.port}")
        server.start()
    except Exception as e:
        logger.error(f"Server error: {e}")
        server.stop()
        sys.exit(1)

if __name__ == "__main__":
    main()