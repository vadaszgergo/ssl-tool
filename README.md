# SSL Certificate Tools - Docker Setup

This directory contains the Flask application for the SSL Certificate Tools.

## Docker Build and Run

### Using Docker Compose (Recommended)

```bash
# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

### Using Docker directly

```bash
# Build the image
docker build -t ssl-tool-app .

# Run the container
docker run -d -p 8000:8000 --name ssl-tool-app ssl-tool-app

# View logs
docker logs -f ssl-tool-app

# Stop the container
docker stop ssl-tool-app
docker rm ssl-tool-app
```

## Access the Application

Once running, access the application at:
- http://localhost:8000

## Development

For local development without Docker:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## Security Note

This application processes private keys in memory only. Private keys are NEVER stored, logged, or persisted. For production use, consider running this in your own Docker environment.

