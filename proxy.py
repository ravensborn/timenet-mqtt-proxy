#!/usr/bin/env python3
"""
MQTT Proxy Service
Accepts plain MQTT connections on port 1883 and forwards them to a TLS-secured broker on port 8883.
"""

import asyncio
import ssl
import os
import logging
import signal

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration from environment variables
LISTEN_HOST = os.getenv('LISTEN_HOST', '0.0.0.0')
LISTEN_PORT = int(os.getenv('LISTEN_PORT', '1883'))
TARGET_HOST = os.getenv('TARGET_HOST', 'mqtt.example.com')
TARGET_PORT = int(os.getenv('TARGET_PORT', '8883'))
VERIFY_SSL = os.getenv('VERIFY_SSL', 'true').lower() == 'true'
CA_CERT_PATH = os.getenv('CA_CERT_PATH', '')


class MQTTProxy:
    def __init__(self):
        self.connections = set()
        self.server = None
        
    def create_ssl_context(self):
        """Create SSL context for upstream connection."""
        ssl_context = ssl.create_default_context()
        
        if CA_CERT_PATH and os.path.exists(CA_CERT_PATH):
            ssl_context.load_verify_locations(CA_CERT_PATH)
            logger.info(f"Loaded CA certificate from {CA_CERT_PATH}")
        
        if not VERIFY_SSL:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            logger.warning("SSL verification is disabled")
        
        return ssl_context
    
    async def pipe(self, reader, writer, direction):
        """Pipe data from reader to writer."""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                logger.debug(f"{direction}: {len(data)} bytes")
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            logger.error(f"Pipe error ({direction}): {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    
    async def handle_client(self, client_reader, client_writer):
        """Handle incoming client connection."""
        client_addr = client_writer.get_extra_info('peername')
        logger.info(f"New connection from {client_addr}")
        
        upstream_reader = None
        upstream_writer = None
        
        try:
            ssl_context = self.create_ssl_context()
            upstream_reader, upstream_writer = await asyncio.open_connection(
                TARGET_HOST,
                TARGET_PORT,
                ssl=ssl_context
            )
            logger.info(f"Connected to upstream {TARGET_HOST}:{TARGET_PORT}")
            
            connection_info = (client_writer, upstream_writer)
            self.connections.add(connection_info)
            
            # Create bidirectional pipes
            client_to_upstream = asyncio.create_task(
                self.pipe(client_reader, upstream_writer, "client->upstream")
            )
            upstream_to_client = asyncio.create_task(
                self.pipe(upstream_reader, client_writer, "upstream->client")
            )
            
            # Wait for either direction to complete
            done, pending = await asyncio.wait(
                [client_to_upstream, upstream_to_client],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # Cancel pending tasks
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                    
        except ConnectionRefusedError:
            logger.error(f"Connection refused by upstream {TARGET_HOST}:{TARGET_PORT}")
        except ssl.SSLError as e:
            logger.error(f"SSL error connecting to upstream: {e}")
        except Exception as e:
            logger.error(f"Error handling client {client_addr}: {e}")
        finally:
            # Cleanup
            for writer in [client_writer, upstream_writer]:
                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
            
            if 'connection_info' in locals():
                self.connections.discard(connection_info)
            
            logger.info(f"Connection from {client_addr} closed")
    
    async def start(self):
        """Start the proxy server."""
        self.server = await asyncio.start_server(
            self.handle_client,
            LISTEN_HOST,
            LISTEN_PORT
        )
        
        addr = self.server.sockets[0].getsockname()
        logger.info(f"MQTT Proxy listening on {addr[0]}:{addr[1]}")
        logger.info(f"Forwarding to {TARGET_HOST}:{TARGET_PORT} (TLS)")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self):
        """Stop the proxy server."""
        logger.info("Shutting down proxy...")
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        # Close all active connections
        for client_writer, upstream_writer in list(self.connections):
            for writer in [client_writer, upstream_writer]:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        
        logger.info("Proxy shutdown complete")


async def main():
    proxy = MQTTProxy()
    
    loop = asyncio.get_running_loop()
    
    # Handle shutdown signals
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(proxy)))
    
    try:
        await proxy.start()
    except asyncio.CancelledError:
        pass


async def shutdown(proxy):
    await proxy.stop()
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()


if __name__ == '__main__':
    asyncio.run(main())
