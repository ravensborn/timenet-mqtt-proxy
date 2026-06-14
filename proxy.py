#!/usr/bin/env python3
"""
MQTT Proxy Service
Accepts plain MQTT connections on port 1883 and forwards them to a TLS-secured broker on port 8883.
Includes MQTT packet parsing for debugging and credential injection.

ADDED: application-layer ACK for MQTT-firmware TT18 devices.
The device publishes its data to its uplink topic and subscribes to the SAME topic, waiting for the
server to publish "@ACK,<packet index>#" before it will send the next packet. iot.teknykar only sends
the MQTT-level PUBACK, not this application ACK, so the device stalls. This proxy detects the device's
data PUBLISH and replies with an "@ACK,<index>#" PUBLISH on the device-facing socket only. Upstream
forwarding is unchanged.
"""

import asyncio
import ssl
import os
import json
import logging
import signal
import struct

logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO),
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

# Default credentials to inject if client doesn't provide them
DEFAULT_USERNAME = os.getenv('DEFAULT_USERNAME', '')
DEFAULT_PASSWORD = os.getenv('DEFAULT_PASSWORD', '')

# --- Application-layer ACK for MQTT TT18 firmware ---------------------------
ENABLE_MQTT_ACK = os.getenv('ENABLE_MQTT_ACK', 'true').lower() == 'true'
# Template for the ACK payload. {index} is substituted with the decimal packet index.
ACK_TEMPLATE = os.getenv('ACK_TEMPLATE', '@ACK,{index}#')
# QoS for the injected ACK PUBLISH. 0 is recommended (no PUBACK round-trip needed).
ACK_QOS = int(os.getenv('ACK_QOS', '0'))
# Leave blank to publish the ACK on the same topic the device published to (it's subscribed there).
# Set this to override, e.g. a downlink topic, if your firmware expects that.
ACK_TOPIC_OVERRIDE = os.getenv('ACK_TOPIC_OVERRIDE', '')
# Log the full (untruncated) payload of device PUBLISH packets, so you can confirm the index field.
LOG_FULL_PAYLOAD = os.getenv('LOG_FULL_PAYLOAD', 'true').lower() == 'true'
# JSON field names to look for the packet index, top-level and inside a nested "data" object.
INDEX_FIELD_CANDIDATES = [
    f.strip() for f in os.getenv(
        'INDEX_FIELDS',
        'sn,index,idx,packet_index,packetindex,pktindex,seq,seqno,sequence,fcnt,count,packetcount'
    ).split(',') if f.strip()
]

# --- One-shot downward command (e.g. clear data flash) ----------------------
# When set, the proxy sends this command ONCE to each device, the first time that device
# publishes (i.e. the moment it is known to be connected and subscribed), then reverts to
# normal ACK-only behaviour. Leave blank to disable.
#   Clear stored data flash (TT18 cmd 500):  @CMD,*000000,500#,#   <- safe remotely
#   Reboot (TT18 cmd 991):                   @CMD,*000000,991#,#
#   Do NOT send initialization/factory reset (990) remotely: it wipes the server target,
#   so the device would reconnect to Tzone's default cloud instead of this proxy.
ONESHOT_COMMAND = os.getenv('ONESHOT_COMMAND', '')

# MQTT Packet Types
MQTT_PACKET_TYPES = {
    1: 'CONNECT', 2: 'CONNACK', 3: 'PUBLISH', 4: 'PUBACK', 5: 'PUBREC',
    6: 'PUBREL', 7: 'PUBCOMP', 8: 'SUBSCRIBE', 9: 'SUBACK', 10: 'UNSUBSCRIBE',
    11: 'UNSUBACK', 12: 'PINGREQ', 13: 'PINGRESP', 14: 'DISCONNECT',
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


def encode_string(s):
    """Encode a string as MQTT UTF-8 string (length prefix + bytes)."""
    if isinstance(s, bytes):
        encoded = s
    else:
        encoded = s.encode('utf-8')
    return struct.pack('!H', len(encoded)) + encoded


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


def encode_remaining_length(length):
    """Encode remaining length as MQTT variable length field."""
    result = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length > 0:
            byte |= 0x80
        result.append(byte)
        if length == 0:
            break
    return bytes(result)


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


# ---------------------------------------------------------------------------
# Application-layer ACK helpers
# ---------------------------------------------------------------------------
def extract_mqtt_packets(buffer):
    """
    Split a byte buffer into complete MQTT packets.
    Returns (list_of_complete_packets, remaining_buffer).
    Handles partial reads and multiple packets per read.
    """
    packets = []
    i = 0
    n = len(buffer)
    while i < n:
        if n - i < 2:
            break  # need at least type byte + 1 length byte
        # Decode remaining length starting at i+1
        multiplier = 1
        value = 0
        j = i + 1
        rl_complete = False
        rl_bytes = 0
        while j < n and rl_bytes < 4:
            b = buffer[j]
            value += (b & 127) * multiplier
            multiplier *= 128
            j += 1
            rl_bytes += 1
            if (b & 128) == 0:
                rl_complete = True
                break
        if not rl_complete:
            break  # remaining-length field not fully arrived yet
        total = (j - i) + value  # (type + RL bytes) + payload
        if n - i < total:
            break  # full packet not arrived yet
        packets.append(bytes(buffer[i:i + total]))
        i += total
    return packets, buffer[i:]


def mqtt_publish_topic_payload(packet):
    """From a single PUBLISH packet, return (topic, payload_bytes)."""
    qos = (packet[0] & 0x06) >> 1
    _, offset = decode_remaining_length(packet, 1)
    topic, offset = decode_string(packet, offset)
    if qos > 0:
        offset += 2  # skip packet identifier
    payload = packet[offset:]
    return topic, payload


def find_packet_index(obj):
    """Search a decoded JSON object (top level + nested 'data') for the packet index."""
    def _coerce(v):
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            s = v.strip()
            try:
                return int(s)
            except ValueError:
                try:
                    return int(s, 16)  # in case it's a hex string
                except ValueError:
                    return None
        return None

    if isinstance(obj, dict):
        for k in INDEX_FIELD_CANDIDATES:
            if k in obj:
                val = _coerce(obj[k])
                if val is not None:
                    return val
        nested = obj.get('data')
        if isinstance(nested, dict):
            for k in INDEX_FIELD_CANDIDATES:
                if k in nested:
                    val = _coerce(nested[k])
                    if val is not None:
                        return val
    return None


def build_mqtt_publish(topic, payload_bytes, qos=0, packet_id=1):
    """Build a raw MQTT PUBLISH packet."""
    fixed_byte = 0x30 | ((qos << 1) & 0x06)
    variable_header = bytearray()
    variable_header += encode_string(topic)
    if qos > 0:
        variable_header += struct.pack('!H', packet_id)
    body = bytes(variable_header) + payload_bytes
    return bytes([fixed_byte]) + encode_remaining_length(len(body)) + body


def inject_credentials(data):
    """Parse MQTT CONNECT packet and inject default credentials if missing."""
    if len(data) < 2:
        return data

    packet_type = (data[0] & 0xF0) >> 4
    if packet_type != 1:
        return data
    if not DEFAULT_USERNAME:
        return data

    try:
        fixed_header_byte = data[0]
        remaining_length, offset = decode_remaining_length(data, 1)
        protocol_name, offset = decode_string(data, offset)
        protocol_level = data[offset]; offset += 1
        connect_flags = data[offset]; offset += 1

        has_username = bool(connect_flags & 0x80)
        if has_username:
            logger.info(f"Overriding client credentials with default (username: {DEFAULT_USERNAME})")
        else:
            logger.info(f"Injecting default credentials (username: {DEFAULT_USERNAME})")

        keep_alive = struct.unpack('!H', data[offset:offset+2])[0]; offset += 2
        client_id, offset = decode_string(data, offset)

        has_will = bool(connect_flags & 0x04)
        if has_will:
            will_topic, offset = decode_string(data, offset)
            will_message, offset = decode_string(data, offset)

        new_connect_flags = connect_flags | 0x80 | 0x40

        new_variable_header = bytearray()
        new_variable_header += encode_string(protocol_name)
        new_variable_header.append(protocol_level)
        new_variable_header.append(new_connect_flags)
        new_variable_header += struct.pack('!H', keep_alive)

        new_payload = bytearray()
        new_payload += encode_string(client_id)
        if has_will:
            new_payload += encode_string(will_topic)
            new_payload += encode_string(will_message)
        new_payload += encode_string(DEFAULT_USERNAME)
        new_payload += encode_string(DEFAULT_PASSWORD)

        new_remaining_length = len(new_variable_header) + len(new_payload)

        new_packet = bytearray()
        new_packet.append(fixed_header_byte)
        new_packet += encode_remaining_length(new_remaining_length)
        new_packet += new_variable_header
        new_packet += new_payload
        return bytes(new_packet)
    except Exception as e:
        logger.error(f"Error injecting credentials: {e}")
        return data


def parse_connect_packet(data):
    info = {}
    try:
        packet_type = (data[0] & 0xF0) >> 4
        if packet_type != 1:
            return None
        remaining_length, offset = decode_remaining_length(data, 1)
        protocol_name, offset = decode_string(data, offset); info['protocol'] = protocol_name
        info['protocol_version'] = data[offset]; offset += 1
        connect_flags = data[offset]; offset += 1
        has_username = bool(connect_flags & 0x80)
        has_password = bool(connect_flags & 0x40)
        has_will = bool(connect_flags & 0x04)
        info['clean_session'] = bool(connect_flags & 0x02)
        info['has_will'] = has_will
        info['keep_alive'] = struct.unpack('!H', data[offset:offset+2])[0]; offset += 2
        client_id, offset = decode_string(data, offset); info['client_id'] = client_id
        if has_will:
            _, offset = decode_string(data, offset)
            _, offset = decode_string(data, offset)
        if has_username:
            username, offset = decode_string(data, offset); info['username'] = username
        if has_password:
            password, offset = decode_string(data, offset)
            info['password'] = '***' if password else '(empty)'
            info['password_length'] = len(password) if password else 0
        return info
    except Exception as e:
        logger.debug(f"Error parsing CONNECT: {e}")
        return None


def parse_publish_packet(data):
    info = {}
    try:
        packet_type = (data[0] & 0xF0) >> 4
        if packet_type != 3:
            return None
        flags = data[0] & 0x0F
        info['dup'] = bool(flags & 0x08)
        info['qos'] = (flags & 0x06) >> 1
        info['retain'] = bool(flags & 0x01)
        remaining_length, offset = decode_remaining_length(data, 1)
        topic, offset = decode_string(data, offset); info['topic'] = topic
        if info['qos'] > 0:
            info['packet_id'] = struct.unpack('!H', data[offset:offset+2])[0]; offset += 2
        payload = data[offset:]
        try:
            payload_str = payload.decode('utf-8')
            info['payload'] = payload_str[:100] + '...' if len(payload_str) > 100 else payload_str
        except Exception:
            info['payload'] = f'(binary, {len(payload)} bytes)'
        info['payload_size'] = len(payload)
        return info
    except Exception as e:
        logger.debug(f"Error parsing PUBLISH: {e}")
        return None


def parse_subscribe_packet(data):
    info = {'topics': []}
    try:
        packet_type = (data[0] & 0xF0) >> 4
        if packet_type != 8:
            return None
        remaining_length, offset = decode_remaining_length(data, 1)
        end_offset = offset + remaining_length
        info['packet_id'] = struct.unpack('!H', data[offset:offset+2])[0]; offset += 2
        while offset < end_offset:
            topic, offset = decode_string(data, offset)
            qos = data[offset]; offset += 1
            info['topics'].append({'topic': topic, 'qos': qos})
        return info
    except Exception as e:
        logger.debug(f"Error parsing SUBSCRIBE: {e}")
        return None


def parse_connack_packet(data):
    info = {}
    try:
        packet_type = (data[0] & 0xF0) >> 4
        if packet_type != 2:
            return None
        remaining_length, offset = decode_remaining_length(data, 1)
        ack_flags = data[offset]; offset += 1
        info['session_present'] = bool(ack_flags & 0x01)
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

    if packet_type == 1:
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
    elif packet_type == 2:
        info = parse_connack_packet(data)
        if info:
            logger.info(f"{prefix} CONNACK - {info.get('return_message', 'N/A')} "
                        f"(code={info.get('return_code', 'N/A')}), "
                        f"Session present: {info.get('session_present', 'N/A')}")
        else:
            logger.info(f"{prefix} CONNACK (parse error)")
    elif packet_type == 3:
        info = parse_publish_packet(data)
        if info:
            logger.info(f"{prefix} PUBLISH - Topic: {info.get('topic', 'N/A')}, "
                        f"QoS: {info.get('qos', 'N/A')}, "
                        f"Payload ({info.get('payload_size', 0)} bytes): {info.get('payload', 'N/A')}")
        else:
            logger.info(f"{prefix} PUBLISH (parse error)")
    elif packet_type == 8:
        info = parse_subscribe_packet(data)
        if info:
            topics = ', '.join([f"{t['topic']} (QoS {t['qos']})" for t in info.get('topics', [])])
            logger.info(f"{prefix} SUBSCRIBE - Topics: {topics}")
        else:
            logger.info(f"{prefix} SUBSCRIBE (parse error)")
    elif packet_type == 14:
        logger.info(f"{prefix} DISCONNECT")
    elif packet_type in (12, 13):
        logger.debug(f"{prefix} {packet_name}")
    else:
        logger.info(f"{prefix} {packet_name}")


class MQTTProxy:
    def __init__(self):
        self.connections = set()
        self.server = None
        self.oneshot_sent = set()

    def create_ssl_context(self):
        ssl_context = ssl.create_default_context()
        if CA_CERT_PATH and os.path.exists(CA_CERT_PATH):
            ssl_context.load_verify_locations(CA_CERT_PATH)
            logger.info(f"Loaded CA certificate from {CA_CERT_PATH}")
        if not VERIFY_SSL:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            logger.warning("SSL verification is disabled")
        return ssl_context

    async def send_app_ack(self, ack_writer, client_addr, packet):
        """Given a device PUBLISH packet, publish an @ACK,<index># back to the device."""
        try:
            topic, payload = mqtt_publish_topic_payload(packet)
        except Exception as e:
            logger.debug(f"[{client_addr[0]}:{client_addr[1]}] could not parse PUBLISH for ACK: {e}")
            return

        if LOG_FULL_PAYLOAD:
            logger.info(f"[{client_addr[0]}:{client_addr[1]}] device PUBLISH full payload "
                        f"on '{topic}': {payload.decode('utf-8', errors='replace')}")

        index = None
        try:
            text = payload.decode('utf-8', errors='replace').strip().rstrip('\x00').strip()
            obj = json.loads(text)
            index = find_packet_index(obj)
        except Exception as e:
            logger.debug(f"[{client_addr[0]}:{client_addr[1]}] payload not JSON / no index: {e}")

        if index is None:
            logger.warning(f"[{client_addr[0]}:{client_addr[1]}] no packet index found in payload; "
                           f"ACK NOT sent. Checked fields {INDEX_FIELD_CANDIDATES}. "
                           f"Set INDEX_FIELDS to the correct field name.")
            return

        ack_topic = ACK_TOPIC_OVERRIDE or topic
        ack_payload = ACK_TEMPLATE.format(index=index).encode('utf-8')
        ack_packet = build_mqtt_publish(ack_topic, ack_payload, qos=ACK_QOS)

        ack_writer.write(ack_packet)
        await ack_writer.drain()
        logger.info(f"[{client_addr[0]}:{client_addr[1]}] \u2190 ACK to device: "
                    f"topic='{ack_topic}' payload={ack_payload!r} (index={index}, qos={ACK_QOS})")

    async def maybe_send_oneshot(self, ack_writer, client_addr, packet):
        """Send ONESHOT_COMMAND to a device once, on its uplink topic, then never again."""
        if not ONESHOT_COMMAND:
            return
        try:
            topic, _ = mqtt_publish_topic_payload(packet)
        except Exception:
            return
        if topic in self.oneshot_sent:
            return
        self.oneshot_sent.add(topic)
        cmd_packet = build_mqtt_publish(topic, ONESHOT_COMMAND.encode('utf-8'), qos=ACK_QOS)
        ack_writer.write(cmd_packet)
        await ack_writer.drain()
        logger.info(f"[{client_addr[0]}:{client_addr[1]}] \u2190 ONE-SHOT command to device: "
                    f"topic='{topic}' payload={ONESHOT_COMMAND!r} (will not repeat for this topic)")

    async def pipe(self, reader, writer, direction, client_addr,
                   modify_connect=False, ack_writer=None):
        """Pipe data from reader to writer with MQTT packet logging and optional app-layer ACK."""
        ack_buffer = b''
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break

                if modify_connect and len(data) > 0:
                    packet_type = (data[0] & 0xF0) >> 4
                    if packet_type == 1:
                        data = inject_credentials(data)

                log_mqtt_packet(data, direction, client_addr)

                # Forward upstream unchanged (transparent).
                writer.write(data)
                await writer.drain()

                # Application-layer ACK on the device -> upstream path only.
                if ack_writer is not None and ENABLE_MQTT_ACK:
                    ack_buffer += data
                    if len(ack_buffer) > 262144:
                        ack_buffer = ack_buffer[-8192:]
                    packets, ack_buffer = extract_mqtt_packets(ack_buffer)
                    for pkt in packets:
                        if ((pkt[0] & 0xF0) >> 4) == 3:  # PUBLISH from device
                            await self.send_app_ack(ack_writer, client_addr, pkt)
                            await self.maybe_send_oneshot(ack_writer, client_addr, pkt)
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
        client_addr = client_writer.get_extra_info('peername')
        logger.info(f"New connection from {client_addr[0]}:{client_addr[1]}")

        upstream_reader = None
        upstream_writer = None

        try:
            ssl_context = self.create_ssl_context()
            upstream_reader, upstream_writer = await asyncio.open_connection(
                TARGET_HOST, TARGET_PORT, ssl=ssl_context
            )
            logger.info(f"Connected to upstream {TARGET_HOST}:{TARGET_PORT}")

            connection_info = (client_writer, upstream_writer)
            self.connections.add(connection_info)

            # device -> upstream: inject creds AND send app-layer ACK back to the device
            client_to_upstream = asyncio.create_task(
                self.pipe(client_reader, upstream_writer, "\u2192 SEND", client_addr,
                          modify_connect=True, ack_writer=client_writer)
            )
            upstream_to_client = asyncio.create_task(
                self.pipe(upstream_reader, client_writer, "\u2190 RECV", client_addr,
                          modify_connect=False)
            )

            done, pending = await asyncio.wait(
                [client_to_upstream, upstream_to_client],
                return_when=asyncio.FIRST_COMPLETED
            )
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
        self.server = await asyncio.start_server(self.handle_client, LISTEN_HOST, LISTEN_PORT)
        addr = self.server.sockets[0].getsockname()
        logger.info(f"MQTT Proxy listening on {addr[0]}:{addr[1]}")
        logger.info(f"Forwarding to {TARGET_HOST}:{TARGET_PORT} (TLS)")
        if ENABLE_MQTT_ACK:
            logger.info(f"App-layer ACK enabled (template='{ACK_TEMPLATE}', qos={ACK_QOS}, "
                        f"topic={'<same as publish>' if not ACK_TOPIC_OVERRIDE else ACK_TOPIC_OVERRIDE})")
        if ONESHOT_COMMAND:
            logger.warning(f"ONE-SHOT command armed: {ONESHOT_COMMAND!r} - will be sent ONCE per "
                           f"device topic. Disable (unset ONESHOT_COMMAND) and restart after both fire.")
        if DEFAULT_USERNAME:
            logger.info(f"Default credentials configured (username: {DEFAULT_USERNAME})")
        async with self.server:
            await self.server.serve_forever()

    async def stop(self):
        logger.info("Shutting down proxy...")
        if self.server:
            self.server.close()
            await self.server.wait_closed()
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
