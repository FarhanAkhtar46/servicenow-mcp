"""
ServiceNow MCP Server CLI

This module provides the command-line interface for the ServiceNow MCP server.
"""

import argparse
import os
import sys
import asyncio
from dotenv import load_dotenv
import json

from mcp_server_servicenow.server import ServiceNowMCP, create_basic_auth

async def interactive_mode(server: ServiceNowMCP):
    """Run the server in interactive mode, accepting natural language queries"""
    print("ServiceNow MCP Server - Interactive Mode")
    print("Type your queries or 'quit' to exit")
    print("-" * 50)
    
    while True:
        try:
            user_input = input("Enter your command: ").strip()
            if user_input.lower() == "quit":
                print("Exiting interactive mode.")
                break
            
            # Format input as JSON-RPC request
            jsonrpc_request = {
                "jsonrpc": "2.0",
                "method": "natural_language_update",
                "params": {"command": user_input},
                "id": 1
            }
            
            # Send the JSON-RPC request
            result = await server.natural_language_update(**jsonrpc_request["params"])
            
            # Print the result
            print("Response:", json.dumps(result, indent=2))
        
        except Exception as e:
            print(f"Error: {e}")
            continue
    
    await server.close()

def main():
    """Run the ServiceNow MCP server from the command line"""
    # Load environment variables from .env file if it exists
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="ServiceNow MCP Server")
    parser.add_argument("--url", help="ServiceNow instance URL", default=os.environ.get("SERVICENOW_INSTANCE_URL"))
    parser.add_argument("--transport", help="Transport protocol (stdio, sse, or interactive)", default="stdio", choices=["stdio", "sse", "interactive"])
    
    # Authentication options
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("--username", help="ServiceNow username", default=os.environ.get("SERVICENOW_USERNAME"))
    auth_group.add_argument("--password", help="ServiceNow password", default=os.environ.get("SERVICENOW_PASSWORD"))
    auth_group.add_argument("--token", help="ServiceNow token", default=os.environ.get("SERVICENOW_TOKEN"))
    auth_group.add_argument("--client-id", help="OAuth client ID", default=os.environ.get("SERVICENOW_CLIENT_ID"))
    auth_group.add_argument("--client-secret", help="OAuth client secret", default=os.environ.get("SERVICENOW_CLIENT_SECRET"))
    
    args = parser.parse_args()
    
    # Check required parameters
    if not args.url:
        print("Error: ServiceNow instance URL is required")
        print("Set SERVICENOW_INSTANCE_URL environment variable or use --url")
        sys.exit(1)
    
    # Determine authentication method
    auth = None
    if args.token:
        from mcp_server_servicenow.server import create_token_auth
        auth = create_token_auth(args.token)
    elif args.client_id and args.client_secret and args.username and args.password:
        from mcp_server_servicenow.server import create_oauth_auth
        auth = create_oauth_auth(args.client_id, args.client_secret, args.username, args.password, args.url)
    elif args.username and args.password:
        auth = create_basic_auth(args.username, args.password)
    else:
        print("Error: Authentication credentials required")
        print("Either provide username/password, token, or OAuth credentials")
        sys.exit(1)
    
    # Create the server
    server = ServiceNowMCP(instance_url=args.url, auth=auth)
    
    # Run in interactive mode or server mode
    if args.transport == "interactive":
        asyncio.run(interactive_mode(server))
    else:
        server.run(transport=args.transport)

if __name__ == "__main__":
    main()