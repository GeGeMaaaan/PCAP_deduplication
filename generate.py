import struct
from collections import Counter, defaultdict

PCAP_GLOBAL_HEADER_LEN = 24
PCAP_PACKET_HEADER_LEN = 16

def extract_patterns_optimized(pcap_file, pattern_len=8, max_templates=255, merge_threshold=3, max_packets=7_500_000):
    def to_key(fragment):
        return int.from_bytes(fragment, byteorder='big')

    def to_bytes(key):
        return key.to_bytes(pattern_len, byteorder='big')

    with open(pcap_file, 'rb') as f:
        f.read(PCAP_GLOBAL_HEADER_LEN)
        data = f.read()

    offset = 0
    patterns = Counter()
    packet_count = 0

    while offset < len(data):
        header = data[offset:offset + PCAP_PACKET_HEADER_LEN]
        if len(header) < PCAP_PACKET_HEADER_LEN:
            break

        packet_len = struct.unpack('<I', header[8:12])[0]
        start = offset + PCAP_PACKET_HEADER_LEN
        end = start + packet_len
        payload = data[start:end]

        if len(payload) >= pattern_len:
            for i in range(len(payload) - pattern_len + 1):
                fragment = payload[i:i + pattern_len]
                patterns[to_key(fragment)] += 1

        offset += PCAP_PACKET_HEADER_LEN + packet_len
        packet_count += 1
        if packet_count % 10000 == 0:
            print(f"{packet_count} пакетов обработано...")

        if packet_count >= max_packets:
            print(f"Достигнут лимит в {max_packets} пакетов.")
            break

    print("Фрагменты собраны. Начинаем отбор...")

    # Преобразуем обратно в bytes и сортируем по убыванию частоты
    sorted_fragments = [to_bytes(k) for k, _ in patterns.most_common(1000)]

    # Объединение пересекающихся шаблонов
    final_templates = []
    used = set()

    for i, frag in enumerate(sorted_fragments):
        if i in used:
            continue
        chain = bytearray(frag)
        used.add(i)
        for j in range(i + 1, len(sorted_fragments)):
            if j in used:
                continue
            candidate = sorted_fragments[j]
            # ищем пересечение
            for k in range(pattern_len - 1, merge_threshold - 1, -1):
                if chain[-k:] == candidate[:k]:
                    chain += candidate[k:]
                    used.add(j)
                    break
        final_templates.append(bytes(chain))
        if len(final_templates) >= max_templates:
            break

    print(f"Сформировано {len(final_templates)} шаблонов.")
    return final_templates

if __name__ == "__main__":
    result = extract_patterns_optimized(
        'test_data/srvSCADA_2020-10-12.pcap', # PCAP для обработки
        pattern_len=8,
        max_templates=255,
        max_packets=7_500_000
    )

    # Сохраняем как .py
    with open('template_map.py', 'w') as f:
        f.write("template_map = [\n")
        for pattern in result:
            f.write(f"    {list(pattern)},\n")
        f.write("]\n")
