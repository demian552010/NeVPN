import os
import re
import socket
import base64
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# ===== НАСТРОЙКИ =====
CONFIG_FILE = "vpn-configs"          # файл с конфигами
OUTPUT_FILE = "working_configs.txt"   # результат
TIMEOUT = 10                          # таймаут на подключение (сек) – увеличен до 10
MAX_WORKERS = 20                      # параллельных проверок
# =====================

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
        match = re.search(r'@([^?#]+)', line)
        if match:
            host_port = match.group(1)
            if ':' in host_port:
                if host_port.startswith('['):  # IPv6 в квадратных скобках
                    bracket_end = host_port.index(']')
                    host = host_port[1:bracket_end]
                    port_str = host_port[bracket_end+2:]
                    if port_str.isdigit():
                        return host, int(port_str)
                else:
                    parts = host_port.rsplit(':', 1)
                    if len(parts) == 2 and parts[1].isdigit():
                        return parts[0], int(parts[1])
        return None, None

    # --- VMess (Base64) ---
    if line.startswith('vmess://'):
        try:
            b64 = line[len('vmess://'):]
            b64 += '=' * (-len(b64) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            data = json.loads(decoded)
            host = data.get('add')
            port = data.get('port')
            if host and port and str(port).isdigit():
                return host, int(port)
        except Exception:
            pass
        return None, None

    return None, None

def check_tcp_port(host, port):
    """Проверяет доступность TCP-порта (без ограничения по задержке)."""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except Exception:
        return False

def check_line(idx, line):
    """Проверяет одну строку: парсит и пробует соединиться."""
    host, port = extract_host_port(line)
    if not host or not port:
        return None  # не удалось распарсить
    ok = check_tcp_port(host, port)
    status = "✅" if ok else "❌"
    print(f"{status} Строка {idx+1}: {host}:{port}")
    return (idx, line.strip()) if ok else None

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"❌ Файл {CONFIG_FILE} не найден!")
        return

    with open(CONFIG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    # Убираем пустые строки и комментарии для подсчёта, но сохраняем индексы
    # Проверяем только непустые строки
    print(f"Всего строк в файле: {len(lines)}")
    print(f"Начинаем проверку (таймаут {TIMEOUT} сек)...")

    working = []  # список (index, line)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for idx, line in enumerate(lines):
            # Пропускаем пустые или комментарии, но можно проверять любые
            if line.strip() and not line.strip().startswith('#'):
                futures[executor.submit(check_line, idx, line)] = idx
        for future in as_completed(futures):
            result = future.result()
            if result:
                working.append(result)

    # Сортируем по индексу
    working.sort(key=lambda x: x[0])

    # Записываем строки конфигураций
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for _, line in working:
            f.write(line + '\n')

    print(f"✅ Готово. Рабочих конфигураций: {len(working)}. Файл {OUTPUT_FILE} обновлён.")

if __name__ == "__main__":
    main()
