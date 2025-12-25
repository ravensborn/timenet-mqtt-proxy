FROM python:3.12-slim

LABEL maintainer="MQTT Proxy"
LABEL description="MQTT proxy that forwards plain 1883 connections to TLS 8883"

WORKDIR /app

# Create non-root user for security
RUN useradd -r -s /bin/false mqttproxy

COPY proxy.py .

# Make script executable
RUN chmod +x proxy.py

# Switch to non-root user
USER mqttproxy

# Default environment variables
ENV LISTEN_HOST=0.0.0.0
ENV LISTEN_PORT=1883
ENV TARGET_HOST=mqtt.example.com
ENV TARGET_PORT=8883
ENV VERIFY_SSL=true
ENV CA_CERT_PATH=

EXPOSE 1883

CMD ["python", "-u", "proxy.py"]
