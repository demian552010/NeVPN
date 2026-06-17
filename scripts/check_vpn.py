import os
import re
import socket
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ===== НАСТРОЙКИ =====
CONFIG_FILE = "vpn-configs"          # файл с конфигами (в корне)
OUTPUT_FILE = "working_configs.txt"   # результат
TIMEOUT = 10                          # таймаут на подключение (сек)
MAX_WORKERS = 30                      # параллельных проверок (можно увеличить)
TOP_N = 5                             # сколько лучших конфигов сохранять
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
        # Ищем часть после @ до ? или # или конца строки
        match = re.search(r'@([^?#]+)', line)
        if match:
            host_port = match.group(1)
            if ':' in host_port:
                if host_port.startswith('['):  # IPv6 в скобках
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

def measure_latency(host, port):
    """
    Измеряет время установки TCP-соединения в миллисекундах.
    Возвращает float (мс) или None при ошибке/таймауте.
    """
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=TIMEOUT):
            elapsed = (time.time() - start) * 1000
            return elapsed
    except Exception:
        return None

def check_line(idx, line):
    """Проверяет одну строку: парсит, измеряет задержку."""
    host, port = extract_host_port(line)
    if not host or not port:
        return None  # не удалось распарсить

    latency = measure_latency(host, port)
    if latency is None:
        # print(f"❌ Строка {idx+1}: {host}:{port} (таймаут)")
        return None
    else:
        # print(f"✅ Строка {idx+1}: {host}:{port} ({latency:.0f} мс)")
        return (idx, line.strip(), latency)   # сохраняем индекс, строку и задержку

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"❌ Файл {CONFIG_FILE} не найден!")
        return

    with open(CONFIG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    total_lines = len(lines)
    print(f"📄 Всего строк в файле: {total_lines}")
    print(f"⏳ Начинаем проверку (таймаут {TIMEOUT} сек, параллельно {MAX_WORKERS} потоков)...")

    results = []  # список (idx, line, latency)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for idx, line in enumerate(lines):
            if line.strip() and not line.strip().startswith('#'):
                futures[executor.submit(check_line, idx, line)] = idx
        # Ждём завершения всех задач
        for future in as_completed(futures):
            res = future.result()
            if res is not None:
                results.append(res)

    # Сортируем по задержке (возрастание)
    results.sort(key=lambda x: x[2])

    # Берём ТОП-N
    top = results[:TOP_N]

    # Выводим статистику
    print(f"✅ Проверено строк: {len(results)}")
    print(f"🏆 Лучшие {len(top)} конфигураций по пингу:")

    # Записываем только строки конфигураций (без задержек)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for idx, line, latency in top:
            f.write(line + '\n')
            print(f"   {latency:.0f} мс -> {line[:60]}...")

    print(f"💾 Файл {OUTPUT_FILE} обновлён (сохранено {len(top)} конфигов).")

if __name__ == "__main__":
    main()
