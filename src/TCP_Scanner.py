import socket
import ssl
import concurrent.futures
from scapy.all import *


def TCP_Scanner(destination, resolved_ip, port):
    # We'll return the port if it's open, None if closed
    request = b"GET / HTTP/1.0\r\n\r\n" # sends HTTP GET Request to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # created the socket connections

    try:
        s.settimeout(0.1) # a port wait time or 0.1 second

        if port in [443, 465, 636, 993, 995, 8443]:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            s.connect((resolved_ip, port))
            s = context.wrap_socket(s, server_hostname=destination)
        else:
            s.connect((resolved_ip, port))
        
        service_name = socket.getservbyport(port) # tries to get the service of a running port
        s.sendall(request) # sends data to server

        try:
            response = s.recv(4096) # receives answer from server
            banner = response.decode()
        except:
            banner = "No banner available"
            
        print(f"[OPEN PORT]: {port} | [SERVICE]: {service_name} | [BANNER]: {banner}") # prints open port and service name and banner
        return port  # Return the open port

    except (socket.timeout, ConnectionRefusedError):
        #print(f"[PORT CLOSED] {port}") # prints any closed ports
        return None

    except socket.error as e:
        print(f"Error scanning {port}: {e}") # any errors in the process will be printed
        return None

    finally:
        s.close() # closes the socket, and then loops back until all ports are completed


def threadpoolexecutor(destination):
    try:
        resolved_ip = socket.gethostbyname(destination) # if they choose a domain name, it will be converted to an IPv4
    except socket.gaierror:
        print("Invalid address/domain")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        open_ports = [] # list for all open ports
    
        future_to_port = {executor.submit(TCP_Scanner, destination, resolved_ip, port): port for port in range(1, 65536)} # goes through TCP function and through the range of ports

        for future in concurrent.futures.as_completed(future_to_port): # For loops the future_to_port through all the ports in order to scan faster
            port = future_to_port[future]
            try:
                result = future.result()
                if result:  # If the result is not None (meaning the port is open)
                    open_ports.append(result)
            except Exception as e:
                print(f"Error with port {port}: {e}")

        # Total open and closed ports
        print("\nScan results:")
        print(f"Open ports: {(open_ports)}")
        closed_count = 65535 - len(open_ports)
        print(f"Closed ports: {closed_count}")
        
        return open_ports, resolved_ip


def os_fingerprinting(destination, open_ports):
    if not open_ports:
        open_ports = [80]  # Default to port 80 if no open ports
    
    data_sent = IP(dst=destination)/TCP(dport=open_ports[0], flags="S", seq=102) # Sends a TCP Packet to a specific destination
    response = sr1(data_sent, timeout=2, verbose=0)

    if not response:
        print(f"[-] No response from {destination}")
        return

    result = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=destination)
    ans, unans = srp(result, timeout=5, verbose=0)

    get_mac = get_if_hwaddr(conf.iface)

    # Checks the Time Till Live for a packet, and depending on the answer, prints its likely operating system
    if response.ttl <= 64:
        print(f"[+] TTL from {destination}: {response.ttl} Likely a Linux Machine")
    elif response.ttl >= 128:
        print(f"[+] TTL from {destination}: {response.ttl} Likely a Windows Machine")
    elif response.ttl >= 255:
        print(f"[+] TTL from {destination}: {response.ttl} Likely a Cisco Machine ")
    else:
        print(f"[-] No Response: {response.ttl} Unknown OS")

    print(f"[*] Your MAC Address: {get_mac}")

    if ans:
        for sent, received in ans:
            print(f"[+] Target MAC Address {destination}: {received.hwsrc}")
            return
    
    print(f"[-] No ARP reply received from {destination}")
         

# if __name__ == "__main__":

def run(destination=None):
    if not destination:
        destination = input("Enter in a domain name or IPv4 Address: ") # Asks a user for a specified domain name or IPv4 address
    open_ports, resolved_ip = threadpoolexecutor(destination) or ([], None)
    
    if resolved_ip:
        os_fingerprinting(resolved_ip, open_ports)