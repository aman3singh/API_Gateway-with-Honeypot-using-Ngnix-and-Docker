from flask import Flask, request, jsonify
import time

app = Flask(__name__)

# Track requests for logging/debugging
request_log = []

@app.route('/v2/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def mock_v2_api(path):
    """Mock endpoint for v2 API calls"""
    request_info = {
        "timestamp": time.time(),
        "path": f"/v2/{path}",
        "method": request.method,
        "headers": dict(request.headers),
        "remote_addr": request.remote_addr,
        "data": request.get_json(silent=True)
    }
    request_log.append(request_info)
    
    print(f"OPENSTACK SERVICE: Received {request.method} request to /v2/{path}")
    
    return jsonify({
        "service": "openstack-mock",
        "status": "success",
        "message": f"OpenStack mock received request to /v2/{path}",
        "method": request.method,
        "request_id": len(request_log)
    })

@app.route('/v3/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def mock_v3_api(path):
    """Mock endpoint for v3 API calls"""
    return mock_v2_api(path)  # Reuse logic for now

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return "Mock OpenStack service is healthy", 200

@app.route('/logs', methods=['GET'])
def get_logs():
    """Return the request logs"""
    return jsonify(request_log)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8774, debug=True)
