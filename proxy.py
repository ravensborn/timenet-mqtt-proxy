#!/usr/bin/env python3
"""
MQTT Proxy Service
Accepts plain MQTT connections on port 1883 and forwards them to a TLS-secured broker on port 8883.
Includes MQTT packet parsing for debugging.
"""

import asyncio
import ssl
import os
import logging
import signal
import struct

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

# MQTT Packet Types
MQTT_PACKET_TYPES = {
    1: 'CONNECT',
    2: 'CONNACK',
    3: 'PUBLISH',
    4: 'PUBACK',
    5: 'PUBREC',
    6: 'PUBREL',
    7: 'PUBCOMP',
    8: 'SUBSCRIBE',
    9: 'SUBACK',
    10: 'UNSUBSCRIBE',
    11: 'UNSUBACK',
    12: 'PINGREQ',
    13: 'PINGRESP',
    14: 'DISCONNECT',
}

# CONNACK Return Codes
CONNACK_CODES = {
    0: 'Connection Accepted',
    1: 'Unacceptable Protocol Version',
    2: 'Identifier Rejected',
    3: 'Server Unavailable',
    4: 'Bad Username or Password',
    5: 'Not Authorized',
}


def decode_remaining_length(data, offset):
    """Decode MQTT remaining length field."""
    multiplier = 1
    value = 0
    idx = offset
    while idx < len(data):
        byte = data[idx]
        value += (byte & 127) * multiplier
        multiplier *= 128
        idx += 1
        if (byte & 128) == 0:
            break
    return value, idx


def decode_string(data, offset):
    """Decode MQTT UTF-8 string."""
    if offset + 2 > len(data):
        return None, offset
    length = struct.unpack('!H', data[offset:offset+2])[0]
    offset += 2
    if offset + length > len(data):
        return None, offset
    string = data[offset:offset+length].decode('utf-8', errors='replace')
    return string, offset + length


def parse_connect_packet(data):
    """Parse MQTT CONNECT packet and extract details."""
    info = {}
    try:
        offset = 0
        
        # Fixed header
        packet_type = (data[0] & 0xF0) >> 4
        if packet_type != 1:
            return None
        
        # Remaining length
        remaining_length, offset = decode_remaining_length(data, 1)
        
        # Protocol name
        protocol_name, offset = decode_string(data, offset)
        info['protocol'] = protocol_name
        
        # Protocol level
        protocol_level = data[offset]
        info['protocol_version'] = protocol_level
        offset += 1
        
        # Connect flags
        connect_flags = data[offset]
        offset += 1
        
        has_username = bool(connect_flags & 0x80)
        has_password = bool(connect_flags & 0x40)
        will_retain = bool(connect_flags & 0x20)
        will_qos = (connect_flags & 0x18) >> 3
        has_will = bool(connect_flags & 0x04)
        clean_session = bool(connect_flags & 0x02)
        
        info['clean_session'] = clean_session
        info['has_will'] = has_will
        
        # Keep alive
        keep_alive = struct.unpack('!H', data[offset:offset+2])[0]
        info['keep_alive'] = keep_alive
        offset += 2
        
        # Client ID
        client_id, offset = decode_string(data, offset)
        info['client_id'] = client_id
        
        # Will topic and message
        if has_will:
            will_topic, offset = decode_string(data, offset)
            will_message, offset = decode_string(data, offset)
            info['will_topic'] = will_topic
        
        # Username
        if has_username:
            username, offset = decode_string(data, offset)
            info['username'] = username
        
        # Password
        if has_password:
            password, offset = decode_string(data, offset)
            info['password'] = '***' if password else '(empty)'
            info['password_length'] = len(password) if password else 0
        
        return info
    except Exception as e:
        logger.debug(f"Error parsing CONNECT: {e}")
        return None


def parse_publish_packet(data):
    """Parse MQTT PUBLISH packet and extract details."""
    info = {}
    try:
        offset = 0
        
        # Fixed header
        packet_type = (data[0] & 0xF0) >> 4
        if packet_type != 3:
            return None
        
        flags = data[0] & 0x0F
        info['dup'] = bool(flags & 0x08)
        info['qos'] = (flags & 0x06) >> 1
        info['retain'] = bool(flags & 0x01)
        
        # Remaining length
        remaining_length, offset = decode_remaining_length(data, 1)
        
        # Topic
        topic, offset = decode_string(data, offset)
        info['topic'] = topic
        
        # Packet ID (only for QoS > 0)
        if info['qos'] > 0:
            packet_id = struct.unpack('!H', data[offset:offset+2])[0]
            info['packet_id'] = packet_id
            offset += 2
        
        # Payload
        payload_start = offset
        payload = data[payload_start:]
        
        # Try to decode as UTF-8, otherwise show hex preview
        try:
            payload_str = payload.decode('utf-8')
            if len(payload_str) > 100:
                info['payload'] = payload_str[:100] + '...'
            else:
                info['payload'] = payload_str
        except:
            info['payload'] = f'(binary, {len(payload)} bytes)'
        
        info['payload_size'] = len(payload)
        
        return info
    except Exception as e:
        logger.debug(f"Error parsing PUBLISH: {e}")
        return None


def parse_subscribe_packet(data):
    """Parse MQTT SUBSCRIBE packet and extract topics."""
    info = {'topics': []}
    try:
        offset = 0
        
        # Fixed header
        packet_type = (data[0] & 0xF0) >> 4
        if packet_type != 8:
            return None
        
        # Remaining length
        remaining_length, offset = decode_remaining_length(data, 1)
        end_offset = offset + remaining_length
        
        # Packet ID
        packet_id = struct.unpack('!H', data[offset:offset+2])[0]
        info['packet_id'] = packet_id
        offset += 2
        
        # Topic filters
        while offset < end_offset:
            topic, offset = decode_string(data, offset)
            qos = data[offset]
            offset += 1
            info['topics'].append({'topic': topic, 'qos': qos})
        
        return info
    except Exception as e:
        logger.debug(f"Error parsing SUBSCRIBE: {e}")
        return None


def parse_connack_packet(data):
    """Parse MQTT CONNACK packet."""
    info = {}
    try:
        offset = 0
        
        packet_type = (data[0] & 0xF0) >> 4
        if packet_type != 2:
            return None
        
        # Remaining length
        remaining_length, offset = decode_remaining_length(data, 1)
        
        # Connect acknowledge flags
        ack_flags = data[offset]
        info['session_present'] = bool(ack_flags & 0x01)
        offset += 1
        
        # Return code
        return_code = data[offset]
        info['return_code'] = return_code
        info['return_message'] = CONNACK_CODES.get(return_code, f'Unknown ({return_code})')
        
        return info
    except Exception as e:
        logger.debug(f"Error parsing CONNACK: {e}")
        return None


def log_mqtt_packet(data, direction, client_addr):
    """Parse and log MQTT packet details."""
    if len(data) < 2:
        return
    
    packet_type = (data[0] & 0xF0) >> 4
    packet_name = MQTT_PACKET_TYPES.get(packet_type, f'UNKNOWN({packet_type})')
    
    prefix = f"[{client_addr[0]}:{client_addr[1]}] {direction}"
    
    if packet_type == 1:  # CONNECT
        info = parse_connect_packet(data)
        if info:
            logger.info(f"{prefix} CONNECT - Client ID: {info.get('client_id', 'N/A')}, "
                       f"Username: {info.get('username', 'N/A')}, "
                       f"Password: {'yes' if info.get('password') else 'no'} "
                       f"(len={info.get('password_length', 0)}), "
                       f"Protocol: {info.get('protocol', 'N/A')} v{info.get('protocol_version', 'N/A')}, "
                       f"Keep-alive: {info.get('keep_alive', 'N/A')}s")
        else:
            logger.info(f"{prefix} CONNECT (parse error)")
    
    elif packet_type == 2:  # CONNACK
        info = parse_connack_packet(data)
        if info:
            logger.info(f"{prefix} CONNACK - {info.get('return_message', 'N/A')} "
                       f"(code={info.get('return_code', 'N/A')}), "
                       f"Session present: {info.get('session_present', 'N/A')}")
        else:
            logger.info(f"{prefix} CONNACK (parse error)")
    
    elif packet_type == 3:  # PUBLISH
        info = parse_publish_packet(data)
        if info:
            logger.info(f"{prefix} PUBLISH - Topic: {info.get('topic', 'N/A')}, "
                       f"QoS: {info.get('qos', 'N/A')}, "
                       f"Payload ({info.get('payload_size', 0)} bytes): {info.get('payload', 'N/A')}")
        else:
            logger.info(f"{prefix} PUBLISH (parse error)")
    
    elif packet_type == 8:  # SUBSCRIBE
        info = parse_subscribe_packet(data)
        if info:
            topics = ', '.join([f"{t['topic']} (QoS {t['qos']})" for t in info.get('topics', [])])
            logger.info(f"{prefix} SUBSCRIBE - Topics: {topics}")
        else:
            logger.info(f"{prefix} SUBSCRIBE (parse error)")
    
    elif packet_type == 14:  # DISCONNECT
        logger.info(f"{prefix} DISCONNECT")
    
    elif packet_type in (12, 13):  # PINGREQ/PINGRESP
        logger.debug(f"{prefix} {packet_name}")
    
    else:
        logger.info(f"{prefix} {packet_name}")


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
    
    async def pipe(self, reader, writer, direction, client_addr):
        """Pipe data from reader to writer with MQTT packet logging."""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                
                # Log MQTT packet details
                log_mqtt_packet(data, direction, client_addr)
                
                writer.write(data)
                await writer.drain()
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
        logger.info(f"New connection from {client_addr[0]}:{client_addr[1]}")
        
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
            
            # Create bidirectional pipes with logging
            client_to_upstream = asyncio.create_task(
                self.pipe(client_reader, upstream_writer, "→ SEND", client_addr)
            )
            upstream_to_client = asyncio.create_task(
                self.pipe(upstream_reader, client_writer, "← RECV", client_addr)
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
            
            logger.info(f"Connection from {client_addr[0]}:{client_addr[1]} closed")
    
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
