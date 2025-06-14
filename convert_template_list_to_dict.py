# convert_template_list_to_dict.py

import ast

ESCAPE_BYTE = 0xFF

def convert_template_list_to_dict(input_file='template_map.py', output_file='template_map_new.py'):
    # Читаем список шаблонов
    with open(input_file, 'r') as f:
        content = f.read()

    # Извлекаем список
    start = content.find('[')
    end = content.rfind(']')
    raw_list = content[start:end+1]
    pattern_list = ast.literal_eval(raw_list)

    # Преобразуем в dict
    template_dict = {}
    for i, pattern in enumerate(pattern_list):
        token = bytes([ESCAPE_BYTE, i])
        template_dict[token] = bytes(pattern)

    # Сохраняем как словарь
    with open(output_file, 'w') as f:
        f.write("template_map = {\n")
        for token, pattern in template_dict.items():
            f.write(f"    {repr(token)}: {repr(pattern)},\n")
        f.write("}\n")

    print(f"Словарь шаблонов сохранён в: {output_file}")

if __name__ == "__main__":
    convert_template_list_to_dict()
