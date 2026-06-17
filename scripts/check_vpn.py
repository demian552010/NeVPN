import os
import re
import socket
import base64
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

CONFIG_FILE = "vpn-configs"          # ваш файл с конфигами (в корне)
OUTPUT_FILE = "working_configs.txt"   # результат
TIMEOUT = 3                           # секунды на проверку порта
MAX_WORKERS = 20                      # количество параллельных проверок

def extract_host_port(line):
    """
    Извлекает хост и порт из строки конфигурации.
    Поддерживает: vless://, trojan://, hysteria2://, vmess:// (Base64).
    Возвращает (host, port) или (None, None).
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None, None

    # --- VLESS, Trojan, Hysteria2 ---
    if line.startswith(('vless://', 'trojan://', 'hysteria2://')):
        # Ищем часть после @ до ? или # или конца строки
        match = re.search(r'@([^?#]+)', line)
        if match:
            host_port = match.group(1)
            # Разделяем хост и порт (может быть IPv6 в квадратных скобках)
            if ':' in host_port:
                # Проверяем, не IPv6 ли это с квадратными скобками
                if host_port.startswith('['):
                    # Пример: [2001:db8::1]:443
                    bracket_end = host_port.index(']')
                    host = host_port[1:bracket_end]
                    port_str = host_port[bracket_end+2:]  # после ]:
                    if port_str.isdigit():
                        return host, int(port_str)
                else:
                    # Обычный IPv4 или домен: хост:порт
                    parts = host_port.rsplit(':', 1)
                    if len(parts) == 2 and parts[1].isdigit():
                        return parts[0], int(parts[1])
        return None, None

    # --- VMess (Base64) ---
    if line.startswith('vmess://'):
        try:
            b64 = line[len('vmess://'):]
            b64 += '=' * (-len(b64) % 4)  # добавляем паддинг
            decoded = base64.b64decode(b64).decode('utf-8')
            data = json.loads(decoded)
            host = data.get('add')
            port = data.get('port')
            if host and port and str(port).isdigit():
                return host, int(port)
        except Exception:
            pass
        return None, None

    # Если строка другого формата – пропускаем
    return None, None

def check_tcp_port(host, port):
    """Проверяет доступность TCP-порта (таймаут 3 сек)."""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except Exception:
        return False

def check_line(index, line):
    """Проверяет одну строку конфигурации."""
    host, port = extract_host_port(line)
    if not host or not port:
        return None
    ok = check_tcp_port(host, port)
    status = "✅" if ok else "❌"
    print(f"{status} Строка {index+1} -> {host}:{port}")
    return index+1 if ok else None

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"❌ Файл {CONFIG_FILE} не найден!")
        return

    with open(CONFIG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    print(f"Найдено {len(lines)} строк. Проверяем рабочие конфигурации...")

    working_indices = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_line, i, line): i for i, line in enumerate(lines)}
        for future in as_completed(futures):
            result = future.result()
            if result:
                working_indices.append(result)

    working_indices.sort()
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for idx in working_indices:
            # Сохраняем номера строк (нумерация с 1)
            f.write(f"Line {idx}\n")
            # Если хотите сохранять сами строки, замените на:
            # f.write(lines[idx-1].strip() + '\n')

    print(f"✅ Готово. Рабочих строк: {len(working_indices)}. Файл {OUTPUT_FILE} обновлён.")

if __name__ == "__main__":
    main()
