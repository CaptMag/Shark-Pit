from bs4 import BeautifulSoup
import urllib.request, requests, whois, json
from urllib.parse import urljoin

filehandle = open('doc.html', encoding="utf-8")
soup = BeautifulSoup(filehandle, 'html.parser') #Allows for soup to read the HTML doc

# HTTP Headers
http_response = ['Content-Type', 'Content-Length', 'Set-Cookie', 'Cache-Control', 'ETag', 'Last-Modified', 'Location', 'Server', 'Access-Control-Allow-Origin', 'WWW-Authenticate', 
                 'Connection', 'Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']

def crawler(url):


    r = requests.get(url)
    for response in http_response:
        if response in r.headers:
            print(f"{response}: {r.headers[response]}") # Check for Response Header, and print proper output


def html_download(url):

    # Downloads the webpage
    opener = urllib.request.urlopen(url)
    WebContent = opener.read().decode('utf-8')
    content = open('doc.html', 'w', encoding="utf-8")
    content.write(WebContent)
    content.close()
    
    print(f"Completed {url} response! Time to parse!")

    # Prints any links
    for link in soup.find_all('a'):
            print(link.get('href')) 

def get_whois(url):
     
     try:
        domain_info = whois.whois(url)

        print("Domain: ", domain_info.domain) # checks domain name
        print("Registrar: ", domain_info.registrar) # Certificate Registry
        print("Creation Date: ", domain_info.creation_date)
        print("Expiration Date: ", domain_info.expiration_date)
        print("Name Servers: ", domain_info.name_servers) # CNAMEs
        print("WHOIS Server: ", domain_info.whois_server)
        print("Updated Date: ", domain_info.updated_date)
     except whois.parser.PywhoisError as e:
         print(f"Error: {e}")

def path_probing(url):

    open_domain = []
    closed_domain = []

    with open ('paths.json', 'r') as f:
        paths = json.load(f)

    for path in paths["paths"]:
            probe_url = urljoin(url, path)
            try:
                probe = requests.get(probe_url)

                if probe.status_code == 200:
                    print(f"[+] {probe_url} is online!")
                    open_domain.append(probe_url)
                else:
                    print(f"[-] {probe_url} is not online!")
                    closed_domain.append(probe_url)
            except requests.exceptions.RequestException as e:
                print(f"Error! Could not locate {probe_url} Reason: {e}")

    print(f"\n Summary \n")
    print(f"Total Probes Checked: {len(open_domain) + len(closed_domain)}")
    print(f"Open Probes: {len(open_domain)}")
    print(f"Closed Probes: {len(closed_domain)}")


# if __name__ == "__main__":   

def run():

    url = input("Enter in a valid URL or IPv4 Address: ")   
    append_http = 'http://'
    url = append_http + url 
    # Adds http :// to chosen domain

    crawler(url)
    [html_download(url) for _ in range (2)]
    get_whois(url)
    path_probing(url)
