# MQTT Proxy (1883 → 8883)

A lightweight proxy service that accepts plain MQTT connections on port 1883 and forwards them to a TLS-secured MQTT broker on port 8883.

## Use Case

When you have:
- An IoT device that only supports unencrypted MQTT (port 1883)
- A cloud MQTT broker that only accepts TLS connections (port 8883)

This proxy sits in between, handling the TLS termination.

```
┌─────────────┐         ┌────────────────┐         ┌─────────────────┐
│   Device    │  1883   │   MQTT Proxy   │  8883   │  MQTT Broker    │
│ (plain MQTT)│ ──────► │ (TLS terminator)│ ──────► │ (TLS required)  │
└─────────────┘  plain  └────────────────┘   TLS   └─────────────────┘
```

## Quick Start

1. **Configure the proxy**

   Edit `docker-compose.yml` and set your target broker:
   ```yaml
   environment:
     - TARGET_HOST=your-mqtt-broker.example.com
     - TARGET_PORT=8883
     - VERIFY_SSL=true
   ```

2. **Start the proxy**
   ```bash
   docker compose up -d
   ```

3. **Point your device to the proxy**
   
   Configure your device to connect to the proxy's IP/hostname on port 1883.

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `LISTEN_HOST` | `0.0.0.0` | Interface to listen on |
| `LISTEN_PORT` | `1883` | Port for incoming plain MQTT |
| `TARGET_HOST` | `mqtt.example.com` | Upstream MQTT broker hostname |
| `TARGET_PORT` | `8883` | Upstream TLS port |
| `VERIFY_SSL` | `true` | Verify broker's SSL certificate |
| `CA_CERT_PATH` | *(empty)* | Path to CA cert inside container |

## Using Custom CA Certificates

If your broker uses a self-signed certificate or private CA:

1. Create a `certs` directory:
   ```bash
   mkdir certs
   cp /path/to/your/ca.crt certs/
   ```

2. The `docker-compose.yml` already mounts this directory. Just set:
   ```yaml
   - CA_CERT_PATH=/certs/ca.crt
   ```

3. For self-signed certs where you don't have the CA:
   ```yaml
   - VERIFY_SSL=false
   ```
   ⚠️ Only use this in trusted networks!

## Running Without Docker

```bash
# Set environment variables
export TARGET_HOST=mqtt.example.com
export TARGET_PORT=8883

# Run directly
python3 proxy.py
```

## Logs

View logs:
```bash
docker compose logs -f mqtt-proxy
```

## Security Considerations

- **Network Security**: The connection between your device and this proxy is unencrypted. Run the proxy on the same network as your device, or use a VPN.
- **Authentication**: MQTT credentials pass through the proxy unchanged. The upstream broker handles authentication.
- **Firewall**: Only expose port 1883 to trusted devices/networks.

## Troubleshooting

**Connection refused to upstream**
- Check that `TARGET_HOST` and `TARGET_PORT` are correct
- Verify the broker is reachable: `openssl s_client -connect TARGET_HOST:8883`

**SSL certificate errors**
- If using a private CA, mount and specify `CA_CERT_PATH`
- For self-signed certs, set `VERIFY_SSL=false` (not recommended for production)

**Device can't connect**
- Ensure port 1883 is exposed and not blocked by firewall
- Check proxy logs for connection details
