import argparse
import socket
import threading

def port_scan(target_host, target_ports):
    try:
        target_ip=socket.gethostbyname(target_host)
    except socket.herror:
        return
    try:
        target_name=socket.gethostbyaddr(target_ip)
        print(f"\n[+] Scan Results for: {target_name[0]}")
    except socket.herror:
        print(f"\n[+] Scan Results for: {target_ip}")
    socket.setdefaulttimeout(1)
    for ports in target_ports:
        t=threading.Thread(target=conn_scan, args=(target_host, int(ports)))
        t.start()
            
def conn_scan(target_host, target_ports):
    screen_lock = threading.Semaphore()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn_skt:
        try:
            conn_skt.connect((target_host,target_ports))
            conn_skt.send(b"Cyber\r\n")
            results = conn_skt.recv(100).decode("utf-8")
            screen_lock.acquire()
            print(f"[+] {target_ports}/tcp open")
            print(f"  [>] {results}")
        except OSError:
            screen_lock.acquire()
            print(f"[-] {target_ports}/tcp closed")
        finally:
            screen_lock.release()
            
parser = argparse.ArgumentParser(usage="port_scan.py TARGET_HOST -p TARGET_PORTS"
                                 "\nexample: python scan.py scanme.nmap.org -p 21,80")
parser.add_argument("target_host",type=str,metavar="TARGET_HOST",
                    help="specify target host (IP address or domain name)",)
parser.add_argument("-p",required=True,type=str,metavar="TARGET_PORTS",
                    help="specify target port[s] separated by comma" "(no spaces)",)
args = parser.parse_args()
args.target_ports = str(args.p).split(",")
port_scan(args.target_host,args.target_ports)

            
            
                        
