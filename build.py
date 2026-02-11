import urllib.parse
from database import SERVER_TEMPLATES, SUBSCRIPTIONS

def build():
    for filename, config in SUBSCRIPTIONS.items():
        ready_links = []
        
        for server_id, custom_name in config:
            if server_id in SERVER_TEMPLATES:
                base_link = SERVER_TEMPLATES[server_id]
                # Кодируем имя (пробелы в %20 и т.д.) для корректности ссылки
                encoded_name = urllib.parse.quote(custom_name)
                # Собираем воедино
                full_link = f"{base_link}#{encoded_name}"
                ready_links.append(full_link)
        
        # Сохраняем готовый файл
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(ready_links))
        
        print(f"Файл {filename} успешно собран.")

if __name__ == "__main__":
    build()