import HTTP_Web_Crawler, CVE_Scanner, TCP_Scanner, Alternative_Sites, Wordlist, Banner
from rich import print

def main():

    tools = {
        "1" : TCP_Scanner.run,
        "2" : CVE_Scanner.check_for_service,
        "3" : HTTP_Web_Crawler.run,
        "4" : Alternative_Sites.check_for_alt_sites
    }

    Banner.banner()

    print("[green][+] Welcome to Shark Pit! A pentesting toolkit designed for evasion and enumeration techniques. [/green]")

    print("1 : TCP Port Scanner\n2 : CVE Scanner\n3 : HTTP Web Crawler\n4 : TLD Enumeration")


    choice = input("Select Tool: ")

    if choice in tools:
        tools[choice]()

if __name__ == "__main__":
    main()
