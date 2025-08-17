import json, requests, concurrent.futures
from rich import print
def check_for_alt_sites():

    #Asks user for domain (without TLD)
    destination = input("Enter a valid domain or ipv4 address: ")
    append_http = 'http://'
    destination = append_http + destination

    #Check if input already has http://
    if destination.startswith('http://'):
        print("Valid Domain!")
        
    else:
        print("Invalid Domain! http:// already added!")
        return    

    # Load JSON file
    with open('suffix.json', 'r') as f:
        icann = json.load(f)
    
    concurrent_futures(destination, icann)

def load_url(destination, suffix):
    closed_probe_text: str = f"[red][/red]" # Coloring

    try:
            new_destination = destination.rstrip('/') + '.' + suffix.lstrip('.') # Removes / from suffix path
            suffix_probe = requests.get(new_destination, timeout=2)

            return new_destination if suffix_probe.status_code == 200 else None # return success if HTTP status gives 200
    except requests.exceptions.RequestException as e:
        print(f"{closed_probe_text}[-] {new_destination} NOT ONLINE\n") # if not online

def concurrent_futures(destinations, icann):
    # Coloring
    open_probe_text: str = f"[green][/green]"
    summary_text: str = f"[white][/white]"


    closed_path = []
    open_path = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_url = {executor.submit(load_url, destinations, suffix): suffix for suffix in icann['icann']} # Loops through all suffixes for chosen domain

        for future in concurrent.futures.as_completed(future_to_url):
            new_destination = future_to_url[future]
            try:
                result = future.result() # Adds open probes to result
                if result:
                    print(f"{open_probe_text}[+] {new_destination} is online!\n")
                    open_path.append(result)
                else:
                    closed_path.append(new_destination)
            except Exception as exc:
                print('%r generated an exception: %s' % (new_destination, exc))
           
        print(f"{summary_text}\n Summary \n")
        print(f"{summary_text}Total Checked: {len(open_path) + len(closed_path)}\n")
        print(f"{summary_text}Open Probes: {len(open_path)}\n")
        print(f"{summary_text}Closed Probes: {len(closed_path)}\n")

        # Saves open probes into open_probes.txt
        with open('open_probes.txt', 'w', encoding='utf-8') as result_file:
            result_line = f"OPEN PROBES: {open_path}"
            result_file.write(str(result_line))


# if __name__ == "__main__":

#     check_for_alt_sites()