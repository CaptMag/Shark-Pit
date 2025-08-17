import requests, csv, re, socket


def check_for_service():
    domain = input("Enter a domain name: ")

    reg = r'http://'

    append_http = 'http://'
    destination = append_http + domain

    if re.match(reg, domain):
        print("http:// has been added twice, invalid domain!")
        return
    else:
        print("Valid Domain!")

    r = requests.get(destination)


    available_cve = []
    unavailable_cve = []

    try:
        if 'Server' in r.headers:
            http_get = r.headers["Server"]
            server_service = http_get.split()[0]
            server_service = server_service.replace("/", " ")
            print(server_service)
        else:
            print(f"Service cannot be detected for {destination}")

    
        with open('files_exploits.csv', 'r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)

            for line in csv_reader:
                # print(line)
                if server_service in line['description']:
                    print(f"[+] CVE found for {server_service} !")
                    print(line['codes'])
                    available_cve.append(line)
                else:
                    # print(f"[-] Could not find CVE for {server_service}")
                    unavailable_cve.append(line)
    except FileNotFoundError as e:
        print(f"Could not aquire CVE for {server_service}. Reason: {e}")

    print("\n Summary \n")
    print(f"Total CVE's Checked: {len(available_cve) + len(unavailable_cve)}")
    print(f"Open CVE's: {len(available_cve)}")
    print(f"Closed CVE's: {len(unavailable_cve)}")

    check_ports(domain)

def check_ports(domain):
    get_req = b"GET / HTTP/1.0\r\n\r\n"
    ports = [21, 23, 53, 79, 80, 111, 135, 139, 161, 445, 513, 514, 1433, 1521, 2049, 3306, 5432, 5984, 6379, 8000, 8080, 9200, 27017]

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.1)
            resolved_ip = socket.gethostbyname(domain)

            s.connect((resolved_ip, port))
            service_name = socket.getservbyport(port)
            s.sendall(get_req)
            try:
                response = s.recv(4096)
                banner = response.decode()
            except:
                banner = "No Banner Available!"

            print(f"[PORT] {port} | [SERVICE] {service_name} | [BANNER] {banner}")

        except (socket.timeout, ConnectionRefusedError):
            print(f"[PORT CLOSED] {port}") # prints any closed ports

        except socket.error as e:
            print(f"Error scanning {port}: {e}") # any errors in the process will be printed
        finally:
            s.close()
        


# if __name__ == "__main__":
    # check_for_service()