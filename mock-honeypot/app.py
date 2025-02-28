from flask import Flask, request, jsonify
import time
import json

app = Flask(__name__)

# Track suspicious requests
suspicious_requests = []

@app.route('/v2/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def mock_v2_api(path):
    """Mock honeypot endpoint that looks like OpenStack but collects potential attack data"""
    request_info = {
        "timestamp": time.time(),
        "path": f"/v2/{path}",
        "method": request.method,
        "headers": dict(request.headers),
        "remote_addr": request.remote_addr,
        "data": request.get_json(silent=True)
    }
    suspicious_requests.append(request_info)
    
    print(f"HONEYPOT: Received potential malicious request to /v2/{path}")
    
    # Return a response that mimics OpenStack but does nothing harmful
    return jsonify({
        "service": "openstack", # Don't reveal this is a honeypot
        "status": "success",
        "message": "Request processed successfully",
        "request_id": "req-" + str(int(time.time())),
    })

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8774, debug=True)
