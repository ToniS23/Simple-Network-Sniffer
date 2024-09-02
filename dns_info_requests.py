import requests

# function to get DNS information for a given IP
def get_dns_info(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url)
    
    # check if the request was successful
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: Unable to fetch data for {ip_address}")
        return None

# example usage
ip_address = "8.8.8.8"  # Replace with the IP address you want to query
dns_info = get_dns_info(ip_address)

if dns_info:
    for key,value in dns_info.items():
        try:
            print(f"{str(key)}: {str(value)}")
        except BaseException:
            print("Unexpected Error")
else:
    print("Failed to retrieve information.")
