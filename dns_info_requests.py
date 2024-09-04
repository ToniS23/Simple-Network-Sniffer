import requests

# function to get DNS information for a given IP
def get_dns_info(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url)
    
    # check if the request was successful
    if response.status_code == 200:
        data = response.json()
    else:
        print(f"Error: Unable to fetch data for {ip_address}\n")
        return None

    output = "" # string for holding the result

    # enumerate the json file (dictionary) stored in data
    if data:
        for key,value in data.items():
            try:
                output += f"{str(key)}: {str(value)}\n"
            except BaseException:
                print("Unexpected Error\n")
        return output
    else:
        print("Failed to retrieve information.\n")
