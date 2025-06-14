import struct
from template_map_new import template_map  # словарь: b'\xffX' → шаблон

PCAP_GLOBAL_HEADER_LEN = 24
PCAP_PACKET_HEADER_LEN = 16
ESCAPE_BYTE = b'\xff'

# Инвертируем словарь: b'\xffX' → шаблон  →  X (int) → шаблон
decoded_map = {token[1]: value for token, value in template_map.items()}

def unescape_data(data):
    result = bytearray()
    i = 0
    while i < len(data):
        if data[i:i+1] == ESCAPE_BYTE:
            i += 1
            if i >= len(data):
                break
            code = data[i]
            if code == 0xFF:
                result.append(0xFF)
            elif code in decoded_map:
                result += decoded_map[code]
            else:
                # Некорректный токен, можно логировать
                pass
        else:
            result.append(data[i])
        i += 1
    return bytes(result)

def decompress_pcap(compressed_file, output_file, index_file):
    with open(compressed_file, 'rb') as f:
        global_header = f.read(PCAP_GLOBAL_HEADER_LEN)
        data = f.read()

    with open(index_file, 'rb') as f:
        packet_lengths = []
        while True:
            chunk = f.read(4)
            if not chunk:
                break
            packet_lengths.append(struct.unpack('<I', chunk)[0])

    offset = 0
    restored_data = bytearray(global_header)
    packet_count = 0

    for length in packet_lengths:
        packet_header = data[offset:offset + PCAP_PACKET_HEADER_LEN]
        packet_data = data[offset + PCAP_PACKET_HEADER_LEN : offset + PCAP_PACKET_HEADER_LEN + length]

        restored_packet = unescape_data(packet_data)

        restored_len = len(restored_packet)

        new_packet_header = (
            packet_header[:8] +
            struct.pack('<I', restored_len) +
            struct.pack('<I', restored_len)
        )

        restored_data += new_packet_header + restored_packet
        offset += PCAP_PACKET_HEADER_LEN + length
        packet_count += 1

        if packet_count % 10000 == 0:
            print(f"{packet_count} пакетов восстановлено...")

    with open(output_file, 'wb') as f:
        f.write(restored_data)

    print(f"Готово. Всего восстановлено пакетов: {packet_count}")

if __name__ == "__main__":
    decompress_pcap(
        'result/compressed_test422.dat',
        'restored/restored_test422.pcap',
        'result/index_test422.bin'
    )
