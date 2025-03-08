#!/usr/bin/env python3
import requests
import time
import json
import random
import argparse

# Parse command line arguments
parser = argparse.ArgumentParser(description='Test the OpenStack Honeypot with stateful interactions')
parser.add_argument('--host', default='localhost', help='Host where the API gateway is running')
parser.add_argument('--port', default=8080, type=int, help='Port where the API gateway is running')
parser.add_argument('--mode', choices=['random', 'sequential', 'targeted'], default='sequential', 
                    help='Test mode: random requests, sequential progression, or targeted attack')
parser.add_argument('--requests', type=int, default=10, help='Number of requests to send')
parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds')
parser.add_argument('--agent', default='TestAgent/1.0', help='User agent to use')
parser.add_argument('--show-response', action='store_true', help='Show response content')
args = parser.parse_args()

# Base URL for the API gateway
base_url = f"http://{args.host}:{args.port}"

# User agent and headers
headers = {
    'User-Agent': args.agent,
    'Content-Type': 'application/json'
}

# Track our auth token if we get one
auth_token = None

# Define endpoints for different test modes
endpoints = {
    'random': [
        '/v2/auth/tokens',
        '/v2/servers',
        '/v2/servers/details',
        '/v2/images',
        '/v2/volumes',
        '/v2/admin/config',
        '/v3/auth/tokens',
        '/v3/servers',
        '/v3/images',
        '/v3/volumes',
        '/v3/admin/config'
    ],
    'sequential': [
        # Start with basic discovery
        '/v2/auth/tokens',  # Try to get a token
        '/v2/servers',      # List servers
        '/v2/servers/server-1',  # Get details of a specific server
        '/v2/images',       # List available images
        '/v2/volumes',      # List volumes
        '/v2/volumes/volume-3',  # Try to access an admin volume
        '/v2/admin/config'  # Try to access admin config
    ],
    'targeted': [
        # This simulates an attacker who knows what they're looking for
        '/v2/auth/tokens',  # Get a token first 
        '/v2/servers',      # Quick scan of servers
        '/v2/admin/config', # Directly try admin access
        '/v2/volumes/volume-3'  # Directly try to access sensitive volume
    ]
}

def send_request(endpoint, method='GET', data=None):
    """Send a request to the specified endpoint"""
    global auth_token  # Move the global declaration to the beginning of the function
    
    url = f"{base_url}{endpoint}"
    current_headers = headers.copy()
    
    # Add auth token if we have one
    if auth_token:
        current_headers['X-Auth-Token'] = auth_token
    
    print(f"\n{method} {url}")
    
    if method == 'GET':
        response = requests.get(url, headers=current_headers)
    elif method == 'POST':
        response = requests.post(url, headers=current_headers, json=data)
    elif method == 'PUT':
        response = requests.put(url, headers=current_headers, json=data)
    else:
        response = requests.delete(url, headers=current_headers)
    
    print(f"Status: {response.status_code}")
    
    if args.show_response:
        try:
            print("Response:")
            print(json.dumps(response.json(), indent=2))
        except:
            print("Non-JSON response")
            print(response.text)
    
    # Check if we got a token in the response
    try:
        resp_json = response.json()
        if 'token' in resp_json and 'id' in resp_json['token']:
            auth_token = resp_json['token']['id']  # No need for global here since we declared it at the top
            print(f"Received token: {auth_token}")
    except:
        pass
    
    return response

def run_test():
    """Run the test based on specified mode"""
    if args.mode == 'random':
        # Random requests
        for i in range(args.requests):
            endpoint = random.choice(endpoints['random'])
            method = random.choice(['GET', 'POST', 'PUT', 'DELETE'])
            
            # For auth endpoints, use POST with credentials
            if 'auth/tokens' in endpoint:
                method = 'POST'
                data = {
                    "auth": {
                        "identity": {
                            "methods": ["password"],
                            "password": {
                                "user": {
                                    "name": "testuser",
                                    "password": "testpassword"
                                }
                            }
                        }
                    }
                }
                send_request(endpoint, method, data)
            else:
                send_request(endpoint, method)
            
            time.sleep(args.delay)
    
    elif args.mode == 'sequential':
        # Sequential progression through endpoints
        for endpoint in endpoints['sequential']:
            if 'auth/tokens' in endpoint:
                # Auth requires POST
                data = {
                    "auth": {
                        "identity": {
                            "methods": ["password"],
                            "password": {
                                "user": {
                                    "name": "testuser",
                                    "password": "testpassword"
                                }
                            }
                        }
                    }
                }
                send_request(endpoint, 'POST', data)
            else:
                send_request(endpoint)
            
            time.sleep(args.delay)
    
    elif args.mode == 'targeted':
        # Targeted attack pattern
        for endpoint in endpoints['targeted']:
            if 'auth/tokens' in endpoint:
                # Auth requires POST
                data = {
                    "auth": {
                        "identity": {
                            "methods": ["password"],
                            "password": {
                                "user": {
                                    "name": "admin",  # Try admin credentials
                                    "password": "admin"
                                }
                            }
                        }
                    }
                }
                send_request(endpoint, 'POST', data)
            else:
                send_request(endpoint)
            
            time.sleep(args.delay)

    # Finally, check what the honeypot recorded about our session
    print("\nChecking honeypot sessions...")
    response = requests.get(f"{base_url}/sessions", headers=headers)
    if args.show_response:
        try:
            print(json.dumps(response.json(), indent=2))
        except:
            print("Error retrieving sessions")

if __name__ == '__main__':
    print(f"Starting honeypot test in {args.mode} mode")
    print(f"Sending {args.requests} requests with {args.delay}s delay")
    run_test()
    print("Test completed")