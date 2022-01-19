#!/usr/bin/python3

import config
import json
import time
import connection_manager
import greynoise_interface
import location_manager
import time_utility
import greynoisequery_manager as gnq_manager
import shodanmanager
import shodan_report_manager
import shodanquery_manager as sq_manager
import file_utilty

ip_list = list()

def run_greynoise():
    greynoise_success = True
    shodan_success = False

    #1. Create filename for greynoise logs and Shodan logs. 
    # NOTE: The timestamps on both files match so they can later be associated and cross referenced if necessary 
    timestamp = time_utility.filetimestamp()
    greynoise_log_file = 'greynoise_log-'+timestamp+'.log'
    shodan_log_file = 'shodan_log-'+timestamp+'.log'
    
    #2. Record in greynoise.log that the greynoise query process has started.
    #NOTE: This process should also be the one creating the log file for today's greynoise activities. 
    file_utilty.write_greynoise_log(greynoise_log_file,'main.run_greynoise()','Greynoise query process started')
    
    print(f'Greynoise query Process starting...')

    #NOTE: There are 49,021 UK locations in the DB. Of these 41,275 place names are unique. Sorting is required later when processing this data to ensure locations are associated accuratley 

    #3. Create a query string for querying greynoise.
    #NOTE: This string will query greynoise for any devices seen this month. 
    #TODO: consider changing this string so it only queries for traffic seen today.
    #querystring = greynoise_interface.get_seen_this_month_query(time_utility.year_month())
    #querystring = greynoise_interface.get_query_city('London')
    querystring = greynoise_interface.get_seen_on_this_day_query(time_utility.yesterdaydate())

    #4. Run Greynoise  query
    greynoise = greynoise_interface.query_greynoise(querystring, greynoise_log_file)

    #5. write raw greynoise .json to folder for future reference in case of errors reported in logs.
    #NOTE: the same timestmap is used for this as the system log files so they can all be crossed referenced if neccessary. 
    # eg a reported error in a log can be used to locate data in the raw json.
    fname = str(timestamp)+'-greynoise.json'
    file_utilty.write_json_to_file(fname,'greynoiseResults',greynoise)    

    #4. If running remote open ssh tunnel to my server
    print(f'remote is {config.remote}')
    if config.remote:
        print(f'Attempting to open SSH tunnel...')
        server = connection_manager.get_ssh_tunnel()
        server.start()
        print(f'Tunnel process complete.')
    else:
        server = None
    
    #5. insert greynoise data to Database
    print(f'Attempting to insert greynoise data into database. Calling gnq_manager.insert_greynoise_transaction()...')
    greynoise_success = gnq_manager.insert_greynoise_transaction(greynoise, server, greynoise_log_file)
    print(f'gnq_manager.insert_greynoise_transaction() complete. Returned to main loop')


    if greynoise_success:
        file_utilty.write_greynoise_log(greynoise_log_file, 'main.run_greynoise()', 'SUCCESS: Greynoise Process Complete')
        shodan_success = run_shodan(server, shodan_log_file, timestamp)
        #TODO: Log completion details if all is successful 
    else:
        #TODO: LOG If greynoise fails...
        print(f'get_greynoise.rungreynoise(): failure in greynoise so quit')
        file_utilty.write_greynoise_log(greynoise_log_file, 'main.run_greynoise()', 'ERROR: Greynoise Process Failed')
    
    if shodan_success:
        file_utilty.write_shodan_log(shodan_log_file, 'main.run_greynoise()','SUCCESS: Shodan Process complete')
    else:
        file_utilty.write_shodan_log(shodan_log_file, 'main.run_greynoise()','ERROR: Shodan Process complete, with errors')
    print(f'shodan_complete without errors: {shodan_success}')
    
    if config.remote:
        server.close()
        server.stop()
    return greynoise_success


def run_shodan(server, log_file, original_date_timestamp):    
    print('Start Shodan Process...')
    file_utilty.write_shodan_log(log_file,'main.run_shodan()','Shodan query process started')
    success = True
    #1. Get list of IPs from OUR DATABASE. This is a list of tupples to query shodan with...
    shodan_ips = sq_manager.get_search_ips(server, log_file)

    #NOTE: Collection of IPs that exist in shodan
    found_ips = []
    
    #2. Itterate through the list of tupples, query each IP
    for i in shodan_ips:
        shodan_result = shodanmanager.query_shodan_with_ip(log_file, i[2])
        db_success = shodan_report_manager.insert_shodan_report_transaction(shodan_result, i[1], i[2], server, log_file, original_date_timestamp)
        #NOTE: Shodan will fall over if you exceed its maximum query rate of one query per second. So sleep the program for 1.5 secs to be kind
        time.sleep(1.25)
        if db_success == False:
            success = False
        if i[2] != '999.999.999':
            found_ips.append(i[2])

        #update 'found' in shodanquery table...
        sq_manager.update_found_ips(server, found_ips, log_file)

    #update tne queired column so these aren't checked again
    sq_manager.update_queried(server, time_utility.yesterdaydate(), log_file)))'

    #NOTE: Log the basic stats on how effective the query was
    num_queried = len(shodan_ips)
    num_found = len(found_ips)
    file_utilty.write_shodan_log(log_file,'main.run_shodan()',(f'Shodan complete: {num_queried} IPs queried {num_found} IP Address found.'))

    #TODO: RETURN THE STATUS OF THE INSERTS TO GREYNOISE FUNCTION AND LOG
    return success


if __name__ == '__main__':
    greynoise = run_greynoise()  
    #print(time_utility.yesterdaydate())
    #print(config.remote)         
