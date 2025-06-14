import gzip
import shutil

def decompress_gzipped_files(compressed_gz, index_gz):
    compressed_path = compressed_gz[:-3]  # убираем .gz
    index_path = index_gz[:-3]

    # Распаковка compressed.dat.gz → compressed.dat
    with gzip.open(compressed_gz, 'rb') as f_in, open(compressed_path, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)

    # Распаковка index.bin.gz → index.bin
    with gzip.open(index_gz, 'rb') as f_in, open(index_path, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)

    # Запуск восстановления

if __name__ == "__main__":
    decompress_gzipped_files(
        'result/compressed11.dat.gz',
        'result/index11.bin.gz',
    )
