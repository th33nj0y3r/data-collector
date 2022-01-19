import requests
import json
import file_utilty

#global variables
url = "https://api.greynoise.io/v2/experimental/gnql"
headers = {"accept": "application/json","key": "ISjx2FRlgeYGAaMsNjRCaX7zdj7koyccgShvJfMj2PJZFzkF6T7Jifop96Q1HOyM"}


def query_greynoise(querystring, log_file_name):
    try:
        jsn = (requests.request("GET", url, headers=headers, params=querystring)).json()
    except Exception as e:
        #TODO: Write Errors to an external log file
        file_utilty.write_greynoise_log(log_file_name, 'greynoise_manager.query_greynoise()', e)
        print(f'Error in run_query(): {e})')
    else:
        file_utilty.write_greynoise_log(log_file_name, 'greynoise_manager.query_greynoise()', 'Greynoise .json retrieved successfully')
    finally:
        return jsn


def get_query_city(city):
    country = 'metadata.country:"United Kingdom" metadata.city:"London" '
    location = 'metadata.city:"'+city+'" '
    year = 'last_seen: 2019-10-03'
    query_dict = dict()
    query_dict["query"] = country+location+year
    return query_dict

def get_seen_this_month_query(year_month):
    country = 'metadata.country:"United Kingdom" '
    year = 'last_seen: '+year_month
    query_dict = dict()
    query_dict["query"] = country+year
    return query_dict

def get_seen_on_this_day_query(day):
    country = 'metadata.country:"United Kingdom" '
    year = 'last_seen:'+day
    query_dict = dict()
    query_dict["query"] = country+year
    return query_dict

def get_seen_today_query():
    country = 'metadata.country:"United Kingdom" '
    year = 'last_seen:today'
    query_dict = dict()
    query_dict["query"] = country+year
    return query_dict