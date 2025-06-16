Порядок запуска файлов
1. generate.py генерирует - template_list с спишком шаблонов
2. convert_template_list_to_dict - добавлет ключи к template_list и создает уже готовый template_map
3. compress.py - сжимает пакет использую template_map и gzip.
В текущий верссии создает 4 файла:
compressed.dat - PCAP после сжатия шаблонированием, 
compressed.dat.gz - после шаблоннирование + gzip
index.bin - индекс начало каждого пакета, нужно для корректного востановление и потенциальной возможности обратиться к конкретному пакету
index.bin.gz - сжатый gzip index.bin

Для востановление
1. decompress_gzip_wrapper - расспаковывает архив gzip
2. deompress.py - использует обратный template_map(reverse_map) для востановление оригинального PCAP
