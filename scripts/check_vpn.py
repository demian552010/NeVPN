#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import socket
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# === НАСТРОЙКИ ===
CONFIG_FILE = "vpn-configs"
OUTPUT_FILE = "working_configs.txt"
TIMEOUT = 15                     # секунд на подключение
MAX_WORKERS = 30                 # параллельных потоков
TOP_N = 5                        # сколько лучших сохранять
# ==================

def extract_host_port(line):
    """
    Универсальный парсер для любых протоколов вида protocol://...
    Поддерживает: vless, trojan, hysteria2, vmess, ss (shadowsocks),
                  socks, http, https, и любые другие.
    Возвращает (host, port) или (None, None).
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None, None

    # --- Специальная обработка для vmess (Base64 JSON) ---
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
        # если не вышло, попробуем общий метод
        # (хотя обычно vmess так и парсится)

    # --- Специальная обработка для ss (Shadowsocks) ---
    if line.startswith('ss://'):
        # Форматы:
        # 1) ss://base64-encoded-string (где base64 содержит хост:порт и метод)
        # 2) ss://method:password@host:port
        # Попробуем оба
        content = line[len('ss://'):]
        # Проверим, есть ли '@' без base64 (т.е. прямой формат)
        if '@' in content and not content.startswith('base64'):
            # прямой формат: method:password@host:port
            # извлекаем часть после @
            after_at = content.split('@', 1)[1]
            # теперь ищем host:port
            if ':' in after_at:
                # может быть IPv6 в скобках
                if after_at.startswith('['):
                    bracket_end = after_at.index(']')
                    host = after_at[1:bracket_end]
                    port_str = after_at[bracket_end+2:]
                    if port_str.isdigit():
                        return host, int(port_str)
                else:
                    parts = after_at.rsplit(':', 1)
                    if len(parts) == 2 and parts[1].isdigit():
                        return parts[0], int(parts[1])
        else:
            # base64 формат: декодируем, ожидаем JSON или строку вида method:password@host:port
            try:
                decoded = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8')
                # может быть JSON
                if decoded.startswith('{'):
                    data = json.loads(decoded)
                    host = data.get('host') or data.get('add')
                    port = data.get('port')
                    if host and port and str(port).isdigit():
                        return host, int(port)
                else:
                    # строка вида method:password@host:port
                    if '@' in decoded:
                        after_at = decoded.split('@', 1)[1]
                        if ':' in after_at:
                            if after_at.startswith('['):
                                bracket_end = after_at.index(']')
                                host = after_at[1:bracket_end]
                                port_str = after_at[bracket_end+2:]
                                if port_str.isdigit():
                                    return host, int(port_str)
                            else:
                                parts = after_at.rsplit(':', 1)
                                if len(parts) == 2 and parts[1].isdigit():
                                    return parts[0], int(parts[1])
            except Exception:
                pass
        return None, None

    # --- Общий парсер для любых других протоколов (vless, trojan, hysteria2, socks, http, https, и т.д.) ---
    # Проверяем, есть ли '://'
    if '://' in line:
        # Отрезаем протокол
        after_proto = line.split('://', 1)[1]
        # Если есть '@', берем часть после '@'
        if '@' in after_proto:
            after_at = after_proto.split('@', 1)[1]
        else:
            after_at = after_proto
        # Теперь после_at может содержать хост:порт, но может быть и путь (если нет порта, то пропускаем)
        # Ищем до '/', '?', '#', или конца строки
        match = re.match(r'^([^/?\#]+)', after_at)
        if match:
            host_port = match.group(1)
            if ':' in host_port:
                if host_port.startswith('['):
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

def measure_latency(host, port):
    """Измеряет время установки TCP-соединения в миллисекундах."""
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
        return None
    latency = measure_latency(host, port)
    if latency is None:
        return None
    else:
        return (idx, line.strip(), latency)

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"❌ Файл {CONFIG_FILE} не найден!")
        return

    with open(CONFIG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    total_lines = len(lines)
    print(f"📄 Всего строк в файле: {total_lines}")

    # Отфильтруем пустые и комментарии
    valid_lines = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            valid_lines.append((idx, stripped))

    print(f"🔍 Непустых строк (без комментариев): {len(valid_lines)}")

    # Пример первых строк для отладки
    print("📝 Пример первых строк:")
    for i, (_, line) in enumerate(valid_lines[:5], 1):
        print(f"   {i}: {line[:80]}...")

    print(f"⏳ Начинаем проверку (таймаут {TIMEOUT} сек, параллельно {MAX_WORKERS} потоков)...")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for idx, line in valid_lines:
            futures[executor.submit(check_line, idx, line)] = idx
        for future in as_completed(futures):
            res = future.result()
            if res is not None:
                results.append(res)

    # Сортируем по задержке
    results.sort(key=lambda x: x[2])
    top = results[:TOP_N]

    print(f"✅ Успешно проверено (с задержкой): {len(results)}")
    if top:
        print("🏆 Лучшие 5 конфигураций по пингу:")
        for i, (idx, line, latency) in enumerate(top, 1):
            print(f"   {i}. {latency:.0f} мс -> {line[:70]}...")
    else:
        print("⚠️  Не найдено ни одного работающего конфига!")

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for _, line, _ in top:
            f.write(line + '\n')

    print(f"💾 Файл {OUTPUT_FILE} обновлён (сохранено {len(top)} конфигов).")

if __name__ == "__main__":
    main()
