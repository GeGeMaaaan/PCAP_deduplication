import struct

PCAP_GLOBAL_HEADER_LEN = 24
PCAP_PACKET_HEADER_LEN = 16
MAX_PACKETS = 500_000  # Количество сохраняемых пакетов

def extract_first_packets(input_file, output_file, max_packets=MAX_PACKETS):
    with open(input_file, 'rb') as f_in:
        global_header = f_in.read(PCAP_GLOBAL_HEADER_LEN)

        with open(output_file, 'wb') as f_out:
            f_out.write(global_header)

            packet_count = 0
            while packet_count < max_packets:
                packet_header = f_in.read(PCAP_PACKET_HEADER_LEN)
                if len(packet_header) < PCAP_PACKET_HEADER_LEN:
                    break  # Конец файла или повреждение

                packet_len = struct.unpack('<I', packet_header[8:12])[0]
                packet_data = f_in.read(packet_len)
                if len(packet_data) < packet_len:
                    break  # Неполный пакет

                f_out.write(packet_header)
                f_out.write(packet_data)

                packet_count += 1
                if packet_count % 10000 == 0:
                    print(f"{packet_count} пакетов сохранено...")

    print(f"\nГотово. Сохранено {packet_count} пакетов в файл: {output_file}")

if __name__ == "__main__":
    extract_first_packets(
        'test_data/srvSCADA_2020-10-12.pcap',
        'test_data/srvSCADA_first500k.pcap'
    )
