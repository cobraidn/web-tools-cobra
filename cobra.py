	
import sys
import os
import socket
import requests
from datetime import datetime
import json
import re
import time
import struct
import dns.resolver, dns.reversename
import ssl

RED = "\x1B[31m"
BRED = "\x1B[41m"
GREEN = "\x1B[32m"
BGREEN = "\x1B[42m"
DEFAULT = "\x1B[0m"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

art = '''
 _____           _        ___  ____ ___ _   _ _____   ____
|_   _|__   ___ | |___   / _ \/ ___|_ _| \ | |_   _| | __ ) _   _
  | |/ _ \ / _ \| / __| | | | \___ \| ||  \| | | |   |  _ \| | | |
  | | (_) | (_) | \__ \ | |_| |___) | || |\  | | |   | |_) | |_| |
  |_|\___/ \___/|_|___/  \___/|____/___|_| \_| |_|   |____/ \__, |
                                                            |___/
  ____      _
 / ___|___ | |__  _ __ __ _
| |   / _ \| '_ \| '__/ _` |
| |__| (_) | |_) | | | (_| | 
 \____\___/|_.__/|_|  \__,_|  IDN Created @2024      

'''
print(art)
def show_menu():
    print("1. Whois                  7. Scan Header Keamanan Website")
    print("2. Cek IP Website         8. Melihat Technology Website")
    print("3. Certf File             9. DNS Lookup")
    print("4. Traceroute            10. Keluar")
    print("5. IP History")
    print("6. Scan Header Website")
    choice = input("Ketik Sesuai Dengan Angka (1 s.d 10): ")
    return choice

while True:
    choice = show_menu()
    if choice == "1":
        art = '''
  ____ ___  ____  ____      _         
 / ___/ _ \| __ )|  _ \    / \       
| |  | | | |  _ \| |_) |  / _ \ 
| |__| |_| | |_) |  _ <  / ___ \  Whois Tools
 \____\___/|____/|_| \_\/_/   \_\     Created @2024

'''
        print(art)
        print("Ketik 'keluar' dan tekan 'Enter' untuk keluar")
        hostname = input("Masukan Website: ")
        if (hostname=='keluar'):
            os.system("python3 cobra.py")
            break
        else:
            try:
                DOMAIN = hostname
                if DOMAIN == "":
                    raise ValueError
                elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
            
                    try:
                        socket.gethostbyname(DOMAIN)
                    except Exception as ERROR:
                        print(f" ERROR {ERROR}")
                
                else:
                    if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                        print(f" Kesalahan Nama DOMAIN")
                
                    else:
                        print(f" Kesalahan Nama DOMAIN")

                try:
                    print(f"INFO START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                    REQUEST = requests.get(f"https://www.whois.com/whois/{DOMAIN.lower()}")
                    if "<div id=\"securityBlk\" style=\"display: block\">" in REQUEST.text:
                        print(f"INFO www.whois.com: CAPTCHA")
                    RAW_REQUEST = requests.post(f"https://whois-webform.markmonitor.com/whois",
                                        data={"btn": "getWhois", "domain": DOMAIN.lower()})
                    RAW_JSON = json.loads(RAW_REQUEST.text)
                    for NAME, INFO in zip(re.findall("df-label\">(.*?)</div>", REQUEST.text),
                                  re.findall("df-value\">(.*?)</div>", REQUEST.text)):
                        INFO = INFO.replace("<br>", " ")
                        print(f" {NAME} {INFO}")
                    print(f" INFO RAW VERSION:")
                    for RAW in RAW_JSON["whois"].replace("<br>", "\n").split("\n"):
                        if "Domain Name" in RAW or "Registrar:" in RAW or "Creation Date" in RAW or "Updated Date" in RAW or "Domain Status" in RAW:
                            RAW = f"{RAW}"
                        print(f" {RAW}")
                except Exception as ERROR:
                    print(f" {ERROR}")
                    os.system("python3 cobra.py")
                    break   
            except ValueError:
                print(f"INFO Kesalahan Nama Domain [example.com]")
                os.system("python3 cobra.py")
                break

    elif choice == "2":
        art = '''
  ____ ___  ____  ____      _         
 / ___/ _ \| __ )|  _ \    / \       
| |  | | | |  _ \| |_) |  / _ \ 
| |__| |_| | |_) |  _ <  / ___ \  Cek Ip Adrress Tools
 \____\___/|____/|_| \_\/_/   \_\     Created @2024

'''
        print(art)
        print("Ketik 'keluar' dan tekan 'Enter' untuk keluar")
        hostname = input("Masukan Website: ")
        try:
            if (hostname=='keluar'):
                os.system("python3 cobra.py")
                break
            else:
                print(f'IP Address {hostname} Adalah {socket.gethostbyname(hostname)}')
        except Exception as ERROR:
            print(f"INFO Kesalahan Nama Domain [example.com]")
            os.system("python3 cobra.py")
            break
    elif choice == "3":
        art = '''
  ____ ___  ____  ____      _         
 / ___/ _ \| __ )|  _ \    / \       
| |  | | | |  _ \| |_) |  / _ \ 
| |__| |_| | |_) |  _ <  / ___ \  Certificate Web Tools
 \____\___/|____/|_| \_\/_/   \_\      Created @2024

'''
        print(art)
        print("Ketik 'keluar' dan tekan 'Enter' untuk keluar")
        hostname = input("Masukan Website Untuk Di Cek: ")
        if (hostname=='keluar'):
            os.system("python3 cobra.py")
            break
        else:
            try:
                DOMAIN = hostname
                if DOMAIN == "":
                    raise ValueError
                elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
                    try:
                        socket.gethostbyname(DOMAIN)
                    except Exception as ERROR:
                        print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                        os.system("python3 cobra.py")
                        break
                else:
                    if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                        print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                            
                    else:
                        print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                
                
                try:
                    print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                    SLL_CONTEXT = ssl.create_default_context()
                    CONTEXT = SLL_CONTEXT.wrap_socket(socket.socket(socket.AF_INET), server_hostname=DOMAIN)
                    CONTEXT.connect((DOMAIN, 443))
                    INFO3 = CONTEXT.getpeercert()
                    SUBJECT = dict(LIST[0] for LIST in INFO3["subject"])
                    ISSUER = dict(LIST[0] for LIST in INFO3["issuer"])
                    print(f" {GREEN}|{DEFAULT} SUBJECT:")
                    for SUBJECT_NAME, SUBJECT_INFO3 in SUBJECT.items():
                        print(f" {GREEN}| |{DEFAULT} {SUBJECT_NAME}: {SUBJECT_INFO3}")
                    print(f" {GREEN}|{DEFAULT} ISSUER:")
                    for ISSUER_NAME, ISSUER_INFO3 in ISSUER.items():
                        print(f" {GREEN}| |{DEFAULT} {ISSUER_NAME}: {ISSUER_INFO3}")
                    print(f" {GREEN}|{DEFAULT} VALIDITY:")
                    print(f" {GREEN}| |{DEFAULT} notBefore: " + INFO3["notBefore"])
                    print(f" {GREEN}| |{DEFAULT} notAfter: " + INFO3["notAfter"])
                    print(f" {GREEN}|{DEFAULT} SERIAL NUMBER: " + INFO3["serialNumber"])
                except Exception as ERROR:
                    print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                    os.system("python3 cobra.py")
                    break  
            except Exception as ERROR:
                print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                os.system("python3 cobra.py")
                break    

    elif choice == "10":
        print("Sampai Jumpa Kawan :)")
        sys.exit()
    elif choice == "4":
        art = '''
 _____                                   
|_   _| __ __ _  ___ ___ _ __    
  | || '__/ _` |/ __/ _ \ '__/
  | || | | (_| | (_|  __/ |   Traceroute Tools Cobra
  |_||_|  \__,_|\___\___|_|         Created @ 2024

'''
        print(art)
        print("Ketik 'keluar' dan tekan 'Enter' untuk keluar")
        try:
            hostname = input("Masukan Website: ")
            if (hostname=='keluar'):
                os.system("python3 cobra.py")
                break
            else:
                TIMEOUT = 3 
                PORT = 33434
                ICMP = socket.getprotobyname('icmp')
                UDP = socket.getprotobyname('udp')


                icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP)
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, UDP)

                timeout_struct = struct.pack('ll', TIMEOUT, 0)
                icmp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout_struct)

                host = hostname
                dest_addr = socket.gethostbyname(host)
                ttl = 1 

                print(f"Tracerouting... {host}({dest_addr})")
                while True:
                    udp_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                    udp_sock.sendto(b'', (dest_addr, PORT))
                    start_time = time.time()
                    no_tries = 3
                    success = False
                    done = False
                    while no_tries > 0:
                        try:
                            packet, addr = icmp_sock.recvfrom(512)
                            success = True
                        except socket.error:
                            no_tries -= 1
                            continue
                    if addr[0] == dest_addr:
                        done = True
                        break
                    if success:
                        end_time = time.time()
                        try:
                            name = socket.gethostbyaddr(addr[0])[0]
                        except: pass
                        t = round((end_time - start_time) * 1000, 4)
                        print(f"TTL: {ttl} Addr: {name}({addr[0]}) Time: {t}ms")
                    else:
                        print(f"TTL: {ttl} *  *  *")

                    if done: 
                        break
                    ttl += 1
            print("Traceroute completed.")
        except Exception as ERROR:
            print(f"INFO Kesalahan Nama Domain [example.com]")
            os.system("python3 cobra.py")
            break
        

    elif choice == "5":
        art = '''
  ____ ___  ____  ____      _         
 / ___/ _ \| __ )|  _ \    / \       
| |  | | | |  _ \| |_) |  / _ \ 
| |__| |_| | |_) |  _ <  / ___ \  Ip History Tools
 \____\___/|____/|_| \_\/_/   \_\      Created @2024

'''
        print(art)
        print("Ketik 'keluar' dan tekan 'Enter' untuk keluar")
        while True:
            hostname = input("Masukan Website Untuk Di Cek: ")
            if (hostname=='keluar'):
                os.system("python3 cobra.py")
                break
            else:
                try:
                    DOMAIN = hostname
                    if DOMAIN == "":
                        raise ValueError
                    elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
                        try:
                            socket.gethostbyname(DOMAIN)
                        except Exception as ERROR:
                            print(f"INFO Kesalahan Nama Domain [example.com]")
                            os.system("python3 cobra.py")
                            break
                    else:
                        if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                            print(f"INFO Kesalahan Nama Domain [example.com]")
                            
                        else:
                            print(f"INFO Kesalahan Nama Domain [example.com]")
                           
                    try:
                        print(f"INFO START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                        REQUEST = requests.get(f"https://viewdns.info/iphistory/?domain={DOMAIN}", headers={
                            "user-agent": "Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1"}, timeout=30)
                        if "Unfortunately we do not have any records for this hostname." in REQUEST.text:
                            print(f"INFO viewdns.info: NOTHING FOUND")
                
                        elif "Please complete the security check to access viewdns.info" in REQUEST.text:
                            print(f"INFO viewdns.info: CAPTCHA")
               
                        elif "Completing the CAPTCHA proves you are a human and gives you temporary access to the web property." in REQUEST.text:
                            print(f"INFO viewdns.info: CAPTCHA")
                
                        print(" %-1s %-15s %-1s %-29s %-1s %-40s %-1s %s" % (
                            f" ", "IP Address:", f" ", "Location:", f" ",
                            "IP Address Owner:", f" ", "Last seen on this IP:"))
                        if len(re.findall(r"<td>(\d.*?)</td>", REQUEST.text)) >= 100:
                            for IP, LOCATION, OWNER, TIME in zip(re.findall(r"<td>(\d.*?)</td>", REQUEST.text)[0:100],
                                                                re.findall(r"\d</td><td>(.*?)</td>", REQUEST.text)[0:100],
                                                                re.findall(
                                                                    r"\d</td><td>.*?\w+[a-zA-Z]</td><td>(.*?)</td><td align=\"center\"",
                                                                    REQUEST.text)[0:100],
                                                                re.findall(r">([0-9]\w+-[0-9]\w+-[0-9]\w+)</td", REQUEST.text)[
                                                                0:100]):
                                print(" %-1s %-15s %-1s %-29s %-1s %-40s %-1s %s" % (
                                        f" ", IP, f" ", LOCATION, f" ", OWNER,
                                        f" ", TIME))
                            print(f" INFO  OUTPUT TOO BIG!")
                        else:
                            for IP, LOCATION, OWNER, TIME in zip(re.findall(r"<td>(\d.*?)</td>", REQUEST.text),
                                                                re.findall(r"\d</td><td>(.*?)</td>", REQUEST.text), re.findall(
                                        r"\d</td><td>.*?\w+[a-zA-Z]</td><td>(.*?)</td><td align=\"center\"", REQUEST.text),
                                                                re.findall(r">([0-9]\w+-[0-9]\w+-[0-9]\w+)</td", REQUEST.text)):
                                print(" %-1s %-15s %-1s %-29s %-1s %-40s %-1s %s" % (
                                    f" ", IP, f" ", LOCATION, f" ", OWNER,
                                    f" ", TIME))
                        FILE = open("iphistory.txt", "w+")
                        FILE.write(f"[INFO] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\nTARGET: {DOMAIN}\n\n")
                        for IP, LOCATION, OWNER, TIME in zip(re.findall(r"<td>(\d.*?)</td>", REQUEST.text),
                                                            re.findall(r"\d</td><td>(.*?)</td>", REQUEST.text), re.findall(
                                    r"\d</td><td>.*?\w+[a-zA-Z]</td><td>(.*?)</td><td align=\"center\"", REQUEST.text),
                                                            re.findall(r">([0-9]\w+-[0-9]\w+-[0-9]\w+)</td", REQUEST.text)):
                            FILE.write(" %-1s %-15s %-1s %-29s %-1s %-40s %-1s %s" % (f"|", IP, f"|", LOCATION, f"|", OWNER, f"|", TIME + "\n"))
                        FILE.close()
                        print(f" INFO SAVED: iphistory.txt")
                    except Exception as ERROR:
                        print(f"INFO Kesalahan Nama Domain [example.com]")
                        os.system("python3 cobra.py")
                        break
                       
                except Exception as ERROR:
                    print(f"INFO Kesalahan Nama Domain [example.com]")
                    os.system("python3 cobra.py")
                    break
    elif choice == "6":
            art = '''
  ____ ___  ____  ____      _         
 / ___/ _ \| __ )|  _ \    / \       
| |  | | | |  _ \| |_) |  / _ \ 
| |__| |_| | |_) |  _ <  / ___ \  Header Scan Tools
 \____\___/|____/|_| \_\/_/   \_\      Created @2024

'''
            print(art)
            print("Ketik 'keluar' dan tekan 'Enter' untuk keluar")
            hostname = input("Masukan Website Untuk Di Cek: ")
            if (hostname=='keluar'):
                os.system("python3 cobra.py")
                break
            else:
                try:
                    URL = hostname
                    if URL == "":
                        raise ValueError
                    try:
                        print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                        REQUEST = requests.get(URL.lower(), verify=True).headers
                        for NAME, INFO in REQUEST.items():
                            print(f" {GREEN}|{DEFAULT} {NAME}: {INFO}")
                    except Exception as ERROR:
                        print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                        os.system("python3 cobra.py")
                        break
                except ValueError:
                    print(f" {GREEN}=>{DEFAULT} INFO [https://example.com]")
                    os.system("python3 cobra.py")
                    break
    elif choice == "7":
        art = '''
  ____ ___  ____  ____      _         
 / ___/ _ \| __ )|  _ \    / \       
| |  | | | |  _ \| |_) |  / _ \ 
| |__| |_| | |_) |  _ <  / ___ \  Header Security Scan Tools
 \____\___/|____/|_| \_\/_/   \_\      Created @2024

'''
        print(art)
        print("Ketik 'keluar' dan tekan 'Enter' untuk keluar")
        SECURITY_LIST = ["Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options",
                     "Content-Security-Policy", "Referrer-Policy", "Cross-Origin-Embedder-Policy",
                     "Cross-Origin-Opener-Policy",
                     "Cross-Origin-Resource-Policy", "Cache-Control", "Permissions-Policy", "X-XSS-Protection"]
        SECURITY_LIST_ADD = []
        try:
            hostname = input("Masukan Website Untuk Di Cek: ")
            if (hostname=='keluar'):
                show_menu()
            else:
                URL = hostname
                if URL == "":
                    raise ValueError
                try:
                    print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                    REQUEST = requests.get(URL.lower(), verify=True).headers
                    for NAME, INFO in REQUEST.items():
                        if NAME in SECURITY_LIST:
                            NAME = f"{BGREEN}{NAME}{DEFAULT}"
                            SECURITY_LIST_ADD.append(NAME.strip(f"{BGREEN}{DEFAULT}"))
                        print(f" {GREEN}|{DEFAULT} {NAME}: {INFO}")
                    for SUCCES_LIST in SECURITY_LIST_ADD:
                        SECURITY_LIST.remove(SUCCES_LIST)
                    print(f" {GREEN}|{DEFAULT} [{GREEN}INFO{DEFAULT}] HEADERS:")
                    for FAIL_LIST in SECURITY_LIST:
                        print(f" {GREEN}| |{DEFAULT} no {BRED}{FAIL_LIST}{DEFAULT}")
                except Exception as ERROR:
                    print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                    os.system("python3 cobra.py")
                    break
        except ValueError:
            print(f" {GREEN}=>{DEFAULT} INFO [https://example.com]")
            os.system("python3 cobra.py")
            break
    elif choice == "8":
        art = '''
  ____ ___  ____  ____      _         
 / ___/ _ \| __ )|  _ \    / \       
| |  | | | |  _ \| |_) |  / _ \ 
| |__| |_| | |_) |  _ <  / ___ \  Info Tech Website Tools
 \____\___/|____/|_| \_\/_/   \_\      Created @2024

'''
        print(art)
        print("Ketik 'keluar' dan tekan 'Enter' untuk keluar")
        hostname = input("Masukan Website Untuk Di Cek: ")
        if (hostname=='keluar'):
            os.system("python3 cobra.py")
            break
        else:
            try:
                DOMAIN = hostname
                if DOMAIN == "":
                    raise ValueError
                elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
                    try:
                        socket.gethostbyname(DOMAIN)
                    except Exception as ERROR:
                        print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                        os.system("python3 cobra.py")
                        break
                else:
                    if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                        print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                        show_menu()
                    else:
                        print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                        show_menu()
                try:
                    print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                    REQUEST = requests.get(f"https://w3techs.com/sites/info/{DOMAIN.lower()}")
                    if "This site is currently under maintenance. We will be back soon." in REQUEST.text:
                        print(f" [{GREEN}INFO{DEFAULT}] w3techs.com: BLOCKED YOU")
                        show_menu()
                    elif "W3Techs has not yet crawled this site!" in REQUEST.text:
                        print(f" [{GREEN}INFO{DEFAULT}] w3techs.com: NOTHING FOUND")
                        show_menu()
                    for EXCEPTION, NAME, INFO in re.findall(
                            r"(<.*?>)<a href=\"https://w3techs.com/technologies/(.*?)/.*?>(.*?)</a>", REQUEST.text):
                        if NAME == "details":
                            INFO = f"{GREEN}|{DEFAULT} {INFO}"
                        if "<s>" in EXCEPTION:
                            INFO = f"{INFO}: {BRED}used until recently{DEFAULT}"
                        print(f" {GREEN}|{DEFAULT} {INFO}")
                except Exception as ERROR:
                    print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                    os.system("python3 cobra.py")
                    break
            except Exception as ERROR:
                print(f" {GREEN}=>{DEFAULT} Info {ERROR}")
                os.system("python3 cobra.py")
                break

    elif choice == "9":
        art = '''
  ____ ___  ____  ____      _         
 / ___/ _ \| __ )|  _ \    / \       
| |  | | | |  _ \| |_) |  / _ \ 
| |__| |_| | |_) |  _ <  / ___ \  Dns Lookup Tools
 \____\___/|____/|_| \_\/_/   \_\      Created @2024

'''
        print(art)
        print("Ketik 'keluar' dan tekan 'Enter' untuk keluar")
        try:
            hostname = input("Masukan Website Untuk Di Cek: ")
            if (hostname=='keluar'):
                os.system("python3 cobra.py")
                break
            else:   
                RECORD_LIST = ["A", "A6", "AAAA", "AFSDB", "AVC", "CAA", "CNAME", "DNAME", "DNSKEY", "DS", "HINFO",
                               "ISDN", "KEY", "KX", "LOC", "MB", "MG", "MINFO", "MR", "MX", "NAPTR", "NULL", "NS", "NSAP", "NSEC",
                               "NSEC3", "NSEC3PARAM", "PTR", "PX", "RP", "RRSIG", "RT", "SIG", "SOA", "SRV", "SSHFP"]
                DOMAIN = hostname
                if DOMAIN == "":
                    raise ValueError
                elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
                    try:
                        socket.gethostbyname(DOMAIN)
                    except Exception as ERROR:
                        print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                        os.system("python3 cobra.py")
                        break
                else:
                    if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                        print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                        show_menu()
                    else:
                        print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                        show_menu()
                try:
                    print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                    for RECORD in RECORD_LIST:
                        ANSWER = dns.resolver.resolve(DOMAIN, RECORD, raise_on_no_answer=False)
                        for RESULT in ANSWER:
                            print(f" {GREEN}|{DEFAULT} {RECORD}: {RESULT}")
                except Exception as ERROR:
                    print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                    os.system("python3 cobra.py")
                    break
        except Exception as ERROR:
            print(f" {RED}ERROR{DEFAULT}] {ERROR}")
            os.system("python3 cobra.py")
            break  
    else:
        print("Pilihan tidak valid. Silakan coba lagi.")



        


        