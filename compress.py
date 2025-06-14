import struct
import gzip
import os
from template_map_new import template_map

PCAP_GLOBAL_HEADER_LEN = 24
PCAP_PACKET_HEADER_LEN = 16
ESCAPE_BYTE = b'\xff'
MAX_PACKETS = 500_000  # <–– Ограничение

def escape_data_safe(data, template_map):
    reverse_map = {v: k for k, v in template_map.items()}
    max_len = max(len(p) for p in reverse_map)

    result = bytearray()
    i = 0
    while i < len(data):
        matched = False
        for l in range(max_len, 0, -1):
            fragment = data[i:i+l]
            if fragment in reverse_map:
                result += reverse_map[fragment]
                i += l
                matched = True
                break
        if not matched:
            byte = data[i:i+1]
            if byte == ESCAPE_BYTE:
                result += ESCAPE_BYTE + ESCAPE_BYTE
            else:
                result += byte
            i += 1
    return bytes(result)

def compress_pcap(input_file, compressed_file, index_file):
    with open(input_file, 'rb') as f:
        global_header = f.read(PCAP_GLOBAL_HEADER_LEN)
        data = f.read()

    offset = 0
    compressed_payload = bytearray()
    index = []
    packet_count = 0
    total_input = 0
    total_output = 0

    while offset < len(data):
        packet_header = data[offset:offset + PCAP_PACKET_HEADER_LEN]
        if len(packet_header) < PCAP_PACKET_HEADER_LEN:
            break

        packet_len = struct.unpack('<I', packet_header[8:12])[0]
        start = offset + PCAP_PACKET_HEADER_LEN
        end = start + packet_len
        packet_data = data[start:end]

        if len(packet_data) < packet_len:
            break

        compressed_data = escape_data_safe(packet_data, template_map)
        new_len = len(compressed_data)

        new_packet_header = (
            packet_header[:8] +
            struct.pack('<I', new_len) +
            struct.pack('<I', new_len)
        )

        compressed_payload += new_packet_header + compressed_data
        index.append(new_len)

        total_input += len(packet_data)
        total_output += new_len

        offset += PCAP_PACKET_HEADER_LEN + packet_len
        packet_count += 1

        if packet_count % 10000 == 0:
            print(f"{packet_count} пакетов обработано...")

    with open(compressed_file, 'wb') as f:
        f.write(global_header)
        f.write(compressed_payload)

    with open(index_file, 'wb') as f:
        for length in index:
            f.write(struct.pack('<I', length))

    with open(compressed_file, 'rb') as f_in, gzip.open(compressed_file + '.gz', 'wb') as f_out:
        f_out.write(f_in.read())

    with open(index_file, 'rb') as f_in, gzip.open(index_file + '.gz', 'wb') as f_out:
        f_out.write(f_in.read())

    print(f"\nГотово. Обработано пакетов: {packet_count}")
    print(f"До сжатия: {total_input} байт")
    print(f"После замены шаблонов: {total_output} байт")
    print(f"Разница: {total_output - total_input} байт")

if __name__ == "__main__":
    compress_pcap(
        'test_data/srvSCADA_2020-10-12.pcap',
        'result/compressed_test_final.dat',
        'result/index_test_final.bin'
    )
