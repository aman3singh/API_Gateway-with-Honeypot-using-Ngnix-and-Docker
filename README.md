# API Gateway with Honeypot Integration

This project implements a flexible API gateway system with an integrated honeypot that can be adapted for any API service. While it currently mimics OpenStack APIs, the framework can be easily modified to protect and monitor any API infrastructure. The system includes comprehensive logging and monitoring capabilities through Grafana and Loki, allowing for real-time detection of potential attackers and detailed behavioral analysis.

## Project Overview

This API Gateway with Honeypot Integration consists of several services:

1. **Nginx Gateway** - Serves as a reverse proxy, intelligently routing requests to either the real API service or the honeypot based on configurable rules. This is the core component that enables the honeypot integration without affecting legitimate traffic.
2. **Mock OpenStack** - A simplified mock of a real API service (using OpenStack as an example) that responds to legitimate requests. This can be replaced with any API service.
3. **Mock Honeypot** - An advanced honeypot service that not only responds like the real API but also builds comprehensive profiles of potential attackers. It tracks their behavior patterns, techniques, interaction depth, and preferred targets while recording all attack vectors for later analysis.
4. **Loki** - Log aggregation system for collecting and querying logs.
5. **Promtail** - Log collection agent that ships logs to Loki.
6. **Grafana** - Visualization and monitoring dashboard for real-time attack monitoring and analysis.

## System Architecture

```
                                 ┌─────────────────┐
                                 │                 │
                       ┌─────────►  Mock OpenStack │
                       │         │                 │
                       │         └─────────────────┘
┌──────────────┐       │
│              │       │
│ Nginx Gateway├───────┤
│              │       │         ┌─────────────────┐
└──────────────┘       │         │                 │
                       └─────────►  Mock Honeypot  │
                                 │                 │
                                 └─────────────────┘
┌──────────────┐       ┌─────────────────┐       ┌─────────────────┐
│              │       │                 │       │                 │
│   Promtail   ├───────►      Loki       ├───────►     Grafana     │
│              │       │                 │       │                 │
└──────────────┘       └─────────────────┘       └─────────────────┘
```

## Prerequisites

- Docker and Docker Compose installed on your system
- Git (for cloning the repository)

## Getting Started

### Clone the Repository

```bash
git clone https://github.com/yourusername/openstack-honeypot.git
cd openstack-honeypot
```

### Directory Structure

```
api-gateway-project/
├── README.md
├── docker-compose.yml
├── grafana/
│   └── provisioning/
│       ├── dashboards/
│       │   ├── api_gateway.yaml
│       │   └── api_gateway_dashboard.json
│       └── datasources/
│           └── loki.yaml
├── loki/
│   ├── boltdb-shipper-active
│   ├── boltdb-shipper-cache
│   ├── chunks
│   ├── config.yaml
│   └── data/
│       ├── cache
│       ├── chunks
│       ├── index
│       └── uploader/
│           └── name
├── mock-honeypot/
│   ├── Dockerfile
│   ├── app.py
│   └── requirements.txt
├── mock-openstack/
│   ├── Dockerfile
│   ├── app.py
│   └── requirements.txt
├── nginx/
│   ├── Dockerfile
│   └── nginx.conf
└── promtail/
    └── config.yaml
```

### Running the System

To start the entire system, run:

```bash
docker-compose up -d
```

This will:
1. Build all necessary Docker images
2. Create and start containers for each service
3. Set up networking between containers
4. Mount volumes for persistent data

To stop the system:

```bash
docker-compose down
```

If you want to remove the volumes as well:

```bash
docker-compose down -v
```

## Accessing the Services

Once the system is running, you can access the following services:

- **Mock OpenStack API**: http://localhost:8080/v2/ or http://localhost:8080/v3/
- **Grafana Dashboard**: http://localhost:3000 (default login: admin/admin)
- **Loki API**: http://localhost:3100

## Viewing Logs

### Terminal Logs

To view logs for a specific service in the terminal:

```bash
# View logs for all services
docker-compose logs

# View logs for a specific service
docker-compose logs nginx-gateway
docker-compose logs mock-openstack
docker-compose logs mock-honeypot

# Follow logs (stream in real time)
docker-compose logs -f

# Show last N lines
docker-compose logs --tail=100 mock-honeypot
```

### Grafana Logs

1. Open Grafana at http://localhost:3000
2. Log in with username `admin` and password `admin`
3. Navigate to the "Explore" section
4. Select "Loki" as the data source
5. Use LogQL queries to filter logs, for example:
   - `{container_name="openstack-honeypot_mock-honeypot_1"}`
   - `{container_name=~".*nginx.*"} |= "error"`

## Configuration Files

### docker-compose.yml

The main configuration file that defines all services and their relationships. Key configurations include:
- Ports mapping for each service
- Volume mounts for persistent data
- Network configuration
- Dependencies between services

### nginx/nginx.conf

The Nginx configuration file that sets up the reverse proxy. This determines which requests get routed to the mock OpenStack service and which go to the honeypot.

### promtail/config.yaml

Configures how Promtail collects logs from the services and sends them to Loki.

### grafana/provisioning/

Contains configuration files for Grafana, including dashboard definitions and data source configurations.

## Honeypot Features and Attacker Profiling

The honeypot service implements advanced attacker profiling:

### Comprehensive Session Tracking
- Creates unique session profiles for each potential attacker
- Tracks client IP, user agent, timestamps, and interaction patterns
- Maintains a chronological history of all requests within each session
- Maps the complete attack path from initial probe to targeted exploitation attempts

### Behavioral Analysis
- Assigns dynamic "interaction levels" (0-5) based on how deeply attackers probe the system
- Catalogs which endpoints are targeted and in what sequence
- Identifies sophisticated attackers by analyzing their methodical exploration patterns
- Detects automated tools vs. manual exploration through timing and request patterns

### Strategic Response System
- Provides increasingly interesting fake data to entice attackers to reveal more techniques
- Simulates authentication systems and tracks session tokens
- Presents different vulnerability surfaces based on perceived attacker sophistication
- Creates breadcrumb trails that appear to lead to valuable resources

### Intelligence Gathering
- Captures and logs all requests, headers, and payloads for later analysis
- Enables attribution through pattern matching across multiple attack attempts
- Provides valuable data for security research and improving defensive postures
- Allows for the development of attacker signatures and detection rules

## Mock OpenStack Features

The mock OpenStack service:
- Provides simplified responses that mimic real OpenStack API responses
- Logs all requests for monitoring and debugging
- Includes basic health check endpoints

## Customization and Integration

This framework is designed to be highly adaptable and can be integrated with any API ecosystem:

### Adapting to Different API Services

The system can be easily modified to work with any API service, not just OpenStack:
- Replace the mock API service with your own API implementation
- Customize the honeypot responses to match your API's expected format
- Update routing rules in the Nginx gateway to match your API's endpoints

### Modifying the Honeypot Behavior and Profiling Logic

Edit `mock-honeypot/app.py` to:
- Customize how the honeypot responds to different types of requests
- Adjust the interaction level logic to match your threat model
- Add additional profiling metrics specific to your application
- Implement more sophisticated behavioral analysis algorithms

### Changing Nginx Gateway Routing Logic

Edit `nginx/nginx.conf` to:
- Modify how requests are routed between the real service and the honeypot
- Implement more complex routing rules based on headers, IPs, or request patterns
- Add rate limiting or other protective measures
- Configure custom error responses

### Enhancing Monitoring and Analysis

- Add custom Grafana dashboards by adding JSON definitions to `grafana/provisioning/dashboards/`
- Create specialized visualizations for attacker profiling data
- Set up alerts for specific attack patterns
- Develop custom reports for security operations teams

## Security Considerations

- This system is designed for research and monitoring purposes
- In production environments, consider adding authentication to admin endpoints
- Regularly review logs to identify potential threats
- Consider isolating the honeypot network from production systems

## Troubleshooting

### Common Issues

1. **Services not starting properly**:
   - Check logs with `docker-compose logs <service-name>`
   - Ensure all ports are available and not in use by other applications

2. **Nginx not routing properly**:
   - Verify nginx.conf configuration
   - Check Nginx logs with `docker-compose logs nginx-gateway`

3. **Loki/Grafana integration issues**:
   - Verify Loki is healthy with `curl http://localhost:3100/ready`
   - Check Grafana datasource configuration
