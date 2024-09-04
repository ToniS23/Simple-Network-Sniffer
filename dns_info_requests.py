import requests

# function to get DNS information for a given IP
def get_dns_info(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url)
    
    # check if the request was successful
    if response.status_code == 200:
        data = response.json()
    else:
        print(f"Error: Unable to fetch data for {ip_address}")
        return None

    # enumerate the json file (dictionary) stored in data
    if data:
        for key,value in data.items():
            try:
                print(f"{str(key)}: {str(value)}")
            except BaseException:
                print("Unexpected Error")
    else:
        print("Failed to retrieve information.")
