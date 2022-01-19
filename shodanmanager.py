from shodan import Shodan, APIError
import file_utilty
import time_utility

#globals
api = Shodan('POm5XT3RZdHVxSawQbn2CVu7IcDYtTrH')
save_folder = 'shodanResults' 

empty_shodan = {
    "region_code": None,
    "tags": [
    ],
    "ip": "999.999.999",
    "area_code": None,
    "domains": [],
    "hostnames": [],
    "postal_code": None,
    "dma_code": None,
    "country_code": None,
    "org": None,
    "data": [],
    "asn": None,
    "city": None,
    "latitude": None,
    "isp": None,
    "longitude": None,
    "last_update": None,
    "country_code3": None,
    "country_name": None,
    "ip_str": None,
    "os": None,
    "ports": []
}

# Lookup an IP
def query_shodan_with_ip(log_file, ip='8.8.8.8'):
    try:
        ipinfo = api.host(ip)
        file_utilty.write_json_to_file(str(time_utility.filetimestamp()+'-'+ip+'-shodan.json'),save_folder,ipinfo)
        return ipinfo
    except APIError as e:
        return empty_shodan
    except Exception as e:
        print(f'ERROR IN shodanmanager.ipInfo(): {e}: error type: {type(e)}')
        file_utilty.write_shodan_log(log_file, 'shodanmanager.query_shodan_with_ip()', e)
        return empty_shodan


def hacked_sites():
    # Search for websites that have been "hacked"
    for banner in api.search_cursor('http.title:"hacked by"'):
        print(banner)

def count_industrial_control_systems():
    # Get the total number of industrial control systems services on the Internet
    ics_services = api.count('tag:ics')
    print('Industrial Control Systems: {}'.format(ics_services['total']))