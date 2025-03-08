from flask import Flask, request, jsonify
import time
import json
import uuid
import datetime
from collections import defaultdict, deque

app = Flask(__name__)

# Track suspicious requests
suspicious_requests = []

# Session tracking - store information about each visitor
# Structure: {
#   "session_id": {
#     "ip": "client_ip",
#     "user_agent": "user agent string",
#     "first_seen": timestamp,
#     "last_seen": timestamp,
#     "requests": deque of last N requests (path, method, timestamp),
#     "endpoints_accessed": set of unique endpoints accessed,
#     "interaction_level": 0-5 scale of how deep they've gone,
#     "fake_token": token if they've "authenticated"
#   }
# }
sessions = {}

# Maximum number of requests to keep in history per session
MAX_REQUEST_HISTORY = 20

# Fake authentication tokens
active_tokens = {}

def get_session_id(request):
    """Generate a unique session identifier based on IP and user agent"""
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Basic session identification - in production you might want something more sophisticated
    return f"{ip}:{user_agent}"

def update_session(session_id, request_path, request_method):
    """Update session information based on the current request"""
    current_time = time.time()
    
    if session_id not in sessions:
        # Create new session
        sessions[session_id] = {
            "ip": request.remote_addr,
            "user_agent": request.headers.get('User-Agent', 'Unknown'),
            "first_seen": current_time,
            "last_seen": current_time,
            "requests": deque(maxlen=MAX_REQUEST_HISTORY),
            "endpoints_accessed": set(),
            "interaction_level": 0,
            "fake_token": None
        }
    else:
        # Update existing session
        sessions[session_id]["last_seen"] = current_time
    
    # Record this request
    sessions[session_id]["requests"].append({
        "path": request_path,
        "method": request_method,
        "timestamp": current_time
    })
    
    # Add to unique endpoints
    sessions[session_id]["endpoints_accessed"].add(f"{request_method}:{request_path}")
    
    # Update interaction level based on endpoints accessed
    update_interaction_level(session_id, request_path)
    
    return sessions[session_id]

def update_interaction_level(session_id, path):
    """Update the interaction level based on the path accessed"""
    session = sessions[session_id]
    current_level = session["interaction_level"]
    
    # Define paths that increase interaction level
    # This is where you can customize the "depth" of interaction
    if path.startswith("/v2/auth") or path.startswith("/v3/auth"):
        if current_level < 1:
            session["interaction_level"] = 1
    
    elif path.startswith("/v2/servers") or path.startswith("/v3/servers"):
        if current_level < 2:
            session["interaction_level"] = 2
    
    elif path.startswith("/v2/images") or path.startswith("/v3/images"):
        if current_level < 3:
            session["interaction_level"] = 3
    
    elif path.startswith("/v2/volumes") or path.startswith("/v3/volumes"):
        if current_level < 4:
            session["interaction_level"] = 4
    
    # Level 5 requires token authentication
    elif path.startswith("/v2/admin") or path.startswith("/v3/admin"):
        if session["fake_token"] and current_level < 5:
            session["interaction_level"] = 5

def get_custom_response(session, path, method):
    """Generate a custom response based on the session's interaction history"""
    interaction_level = session["interaction_level"]
    
    # Default response
    response = {
        "service": "openstack",  # Don't reveal this is a honeypot
        "status": "success",
        "message": "Request processed successfully",
        "request_id": "req-" + str(int(time.time())),
    }
    
    # Authentication endpoints
    if path.startswith("/v2/auth/tokens") or path.startswith("/v3/auth/tokens"):
        if method == "POST":
            # Generate a fake token
            token = str(uuid.uuid4())
            session["fake_token"] = token
            active_tokens[token] = session
            response = {
                "token": {
                    "issued_at": datetime.datetime.utcnow().isoformat(),
                    "expires_at": (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).isoformat(),
                    "id": token,
                    "tenant": {
                        "description": "Default tenant",
                        "enabled": True,
                        "id": "default-tenant-id",
                        "name": "default"
                    }
                }
            }
    
    # Server endpoints - provide more detail based on interaction level
    elif path.startswith("/v2/servers") or path.startswith("/v3/servers"):
        if interaction_level >= 1:
            # Basic server listing
            response = {
                "servers": [
                    {
                        "id": "server-1",
                        "name": "web-server-01",
                        "status": "ACTIVE"
                    },
                    {
                        "id": "server-2",
                        "name": "db-server-01",
                        "status": "ACTIVE"
                    }
                ]
            }
            
            # If they're deeper in, show more details
            if interaction_level >= 3:
                response["servers"].append({
                    "id": "server-3",
                    "name": "admin-server",
                    "status": "ACTIVE",
                    "description": "Main admin server with privileged access"
                })
    
    # Images endpoint
    elif path.startswith("/v2/images") or path.startswith("/v3/images"):
        response = {
            "images": [
                {
                    "id": "image-1",
                    "name": "Ubuntu 20.04",
                    "status": "ACTIVE"
                },
                {
                    "id": "image-2",
                    "name": "CentOS 8",
                    "status": "ACTIVE"
                }
            ]
        }
    
    # Volumes endpoint
    elif path.startswith("/v2/volumes") or path.startswith("/v3/volumes"):
        response = {
            "volumes": [
                {
                    "id": "volume-1",
                    "name": "web-storage",
                    "size": 100,
                    "status": "available",
                    "attachments": [{"server_id": "server-1"}]
                },
                {
                    "id": "volume-2",
                    "name": "db-storage",
                    "size": 500,
                    "status": "available",
                    "attachments": [{"server_id": "server-2"}]
                }
            ]
        }
        
        # Reveal "sensitive" volume for higher interaction levels
        if interaction_level >= 4:
            response["volumes"].append({
                "id": "volume-3",
                "name": "admin-backup",
                "size": 1000,
                "status": "available",
                "attachments": [{"server_id": "server-3"}],
                "description": "Weekly backups of admin configurations and data"
            })
    
    # Admin endpoints - only accessible with token and high interaction level
    elif (path.startswith("/v2/admin") or path.startswith("/v3/admin")) and interaction_level >= 5:
        response = {
            "status": "success",
            "admin_access": "granted",
            "sensitive_info": "This endpoint contains sensitive admin configuration data",
            "config_files": ["/etc/openstack/admin.conf", "/etc/openstack/credentials.yml"]
        }
    
    return response

@app.route('/v2/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def mock_v2_api(path):
    """Mock honeypot endpoint that looks like OpenStack but collects potential attack data"""
    session_id = get_session_id(request)
    session = update_session(session_id, f"/v2/{path}", request.method)
    
    # Log the request
    request_info = {
        "timestamp": time.time(),
        "path": f"/v2/{path}",
        "method": request.method,
        "headers": dict(request.headers),
        "remote_addr": request.remote_addr,
        "data": request.get_json(silent=True),
        "session_id": session_id,
        "interaction_level": session["interaction_level"]
    }
    suspicious_requests.append(request_info)
    
    print(f"HONEYPOT: Received potential malicious request to /v2/{path} [Session: {session_id}, Level: {session['interaction_level']}]")
    
    # Get a custom response based on the session's interaction history
    response_data = get_custom_response(session, f"/v2/{path}", request.method)
    
    return jsonify(response_data)

@app.route('/v3/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def mock_v3_api(path):
    """Mock honeypot endpoint for v3 API calls"""
    return mock_v2_api(path)  # Reuse honeypot logic

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return "Service is healthy", 200

@app.route('/honeypot-logs', methods=['GET'])
def get_logs():
    """Admin endpoint to view collected attack data"""
    return jsonify(suspicious_requests)

@app.route('/sessions', methods=['GET'])
def get_sessions():
    """Admin endpoint to view active sessions"""
    # Convert sessions to a JSON-serializable format
    serializable_sessions = {}
    for session_id, session_data in sessions.items():
        serializable_session = session_data.copy()
        serializable_session["requests"] = list(session_data["requests"])
        serializable_session["endpoints_accessed"] = list(session_data["endpoints_accessed"])
        serializable_sessions[session_id] = serializable_session
    
    return jsonify(serializable_sessions)

@app.route('/sessions/<session_id>', methods=['GET'])
def get_session_detail(session_id):
    """Admin endpoint to view details of a specific session"""
    if session_id in sessions:
        session_data = sessions[session_id].copy()
        session_data["requests"] = list(session_data["requests"])
        session_data["endpoints_accessed"] = list(session_data["endpoints_accessed"])
        return jsonify(session_data)
    else:
        return jsonify({"error": "Session not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8774, debug=True)