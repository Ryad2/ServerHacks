import struct
import logging
import binascii

log = logging.getLogger(__name__)

TYPE_HELLO = 0x1
TYPE_TIMESTAMP = 0x2
TYPE_PASSWD = 0x3
TYPE_ACK = 0x4
TYPE_DATA = 0x5
TYPE_PING = 0x6
TYPE_FLAG = 0x7

# PROTOCOL FIELDS
# 0      4       8
# | TYPE | FLAGS | SPECIFIC DATA...

STRUCT_HELLO = '>B'
STRUCT_TIMESTAMP = '>BI'
STRUCT_PASSWD = '>B4s'
STRUCT_ACK = '>B'
STRUCT_DATA = '>BB'
STRUCT_PING = '>B'
STRUCT_FLAG = '>B42s'


def unpack_type_flags(b):
    flags = b & 0xF
    type_field = b >> 4
    return type_field, flags


def pack_hello():
    return struct.pack(STRUCT_HELLO, TYPE_HELLO << 4)


def pack_timestamp(timestamp):
    return struct.pack(STRUCT_TIMESTAMP, TYPE_TIMESTAMP << 4, timestamp)


def pack_passwd(passwd):
    return struct.pack(STRUCT_PASSWD, TYPE_PASSWD << 4, passwd)


def pack_ack():
    return struct.pack(STRUCT_ACK, TYPE_ACK << 4)


# Check a checksum (first byte of CRC32 checksum)
# (who neeeds longer checksums...)
def verify_checksum(data, checksum):
    return (binascii.crc32(data) >> 24) == checksum


# Parses an incoming message
# Returns empty tuple on error, otherwise a tuple of fields
def parse_message(data):
    if not data:
        log.error('Empty data received.')
        return tuple()

    message_type, flags = unpack_type_flags(data[0])
    if message_type == TYPE_HELLO:
        if len(data) > 1:
            log.error('More than one byte received for HELLO')
            return tuple()
        return (message_type,)
    elif message_type == TYPE_TIMESTAMP:
        _, timestamp = struct.unpack(STRUCT_TIMESTAMP, data)
        return message_type, timestamp
    elif message_type == TYPE_PASSWD:
        _, passwd = struct.unpack(STRUCT_PASSWD, data)
        return message_type, passwd
    elif message_type == TYPE_DATA:
        checksum_avail = bool(flags & 0x1)

        # Unpack payload according to header length
        _, length = struct.unpack(STRUCT_DATA, data[:2])
        payload = data[2 : length + 2]

        # Unpack one byte after length for checksum
        if checksum_avail:
            checksum = struct.unpack('>B', data[length + 2 : length + 2 + 1])[0]
        else:
            checksum = 0

        if not len(payload) == length:
            log.error('Data is missing in DATA packet.')
            return tuple()

        return message_type, checksum_avail, payload, checksum
    elif message_type == TYPE_PING:
        if len(data) > 1:
            log.error('More than one byte received for PING')
            return tuple()
        if flags:
            log.error('PING may not have any flags.')
            return tuple()
        return (message_type,)
    elif message_type == TYPE_ACK:
        if len(data) > 1:
            log.error('More than one byte received for ACK')
            return tuple()
        return (message_type,)
    elif message_type == TYPE_FLAG:
        _, flag = struct.unpack(STRUCT_FLAG, data)
        return message_type, flag
    else:
        log.error(f'Unknown message type received: {message_type}')
        return tuple()


def log_client(client_writer, client_id):
    try:
        remote = client_writer.get_extra_info('peername')
        if remote is None:
            log.error(f'[{client_id}] Could not get ip of client.')
            return

        log.info(f'[{client_id}] New connection from: {remote[0]}:{remote[1]}')
    except Exception:
        log.exception(f'[{client_id}] Could not get peername.')
        return
