import json
import pymysql
import time
import datetime
import time_utility
import connection_manager
import file_utilty

'''
This code is for managing inputting Greynoise data into our mySQL database. 
For code that queries greynoise see: query_creator 
'''


def insert(gn):
    #db = connection_manager.get_connection()
    server = connection_manager.get_ssh_tunnel()
    server.start()
    db = connection_manager.get_ssh_tunnelled_connection(server)
    cursor = db.cursor()
    sql = 'INSERT INTO greynoisequery (complete, count, message, query, scroll, timestamp) VALUES(%s, %s, %s, %s, %s, %s);'
    try:
        cursor.execute(sql, (gn.get('complete'), gn.get('count'), gn.get('message'), gn.get('query'), gn.get('scroll'), time_utility.sqltimestamp()))
        db.commit()
        db.close()
        server.stop()
    except Exception as e:
        print(f'ERROR in greynoisequery_manager().insert(): {e}')
    else:
        print('greynoisequery_manager().insert(): Insert Successful')



def insert_greynoise_transaction(gn, server, log_file):
    success = True
    db = connection_manager.get_db_connection(server)
    cursor = db.cursor() 

    sql_gnq = 'INSERT INTO greynoisequery (complete, count, message, query, scroll, timestamp) VALUES(%s, %s, %s, %s, %s, %s);'
    sql_report = 'INSERT INTO greynoise_report (greynoisequeryid, ip_address, classification, spoofable, first_seen, last_seen, actor, country, country_code, city, organisation,\
         rdns, asn_num, tor, operating_system, catagory, timestamp, vpn, vpn_service) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);'
    sql_symptom = 'INSERT INTO symptom (name, greynoisereport_id) VALUES(%s, %s);'
    sql_cve = 'INSERT INTO cve (cve_id, greynoisereport_id) VALUES(%s, %s);'
    sql_scan_data = 'INSERT INTO scan_data (port, protocol, greynoisereport_id) VALUES(%s, %s, %s);'
    sql_web_path = 'INSERT INTO web_path (web_path, greynoisereport_id) VALUES(%s, %s);'
    sql_web_useragent = 'INSERT INTO web_useragent (useragent, greynoisereport_id) VALUES(%s, %s);'
    sql_ja3 = 'INSERT INTO ja3 (ja3_fingerprint, ja3_port, greynoisereport_id) VALUES(%s, %s, %s);'
    sql_shodan_ips = 'INSERT INTO shodanquery (greynoisereport_id, ip, found, queried, timestamp) VALUES (%s, %s, %s, %s, %s);'

    try:
        # INSERT INTO greynoisequery...
        cursor.execute(sql_gnq, (gn.get('complete'), gn.get('count'), gn.get('message'), gn.get('query'), gn.get('scroll'), time_utility.sqltimestamp()))
        gn_query_id = cursor.lastrowid 

        #NO EXPECTIONS SO INSERT INTO report...
        #NOTE: 'report' is a list of dictonaries so we need to cycle thorugh and get each dictionary and insert each in turn
        for r in gn.get('data'):
            current_ip = r.get('ip')
            print(f'Beginning DB write process for {current_ip}')
            cursor.execute(sql_report, (gn_query_id, r.get('ip'), r.get('classification'), r.get('spoofable'), r.get('first_seen'), r.get('last_seen'), r.get('actor'),\
                r.get('metadata').get('country'), r.get('metadata').get('country_code'), r.get('metadata').get('city'), r.get('metadata').get('organisation'),\
                    r.get('metadata').get('rdns'), r.get('metadata').get('asn'), r.get('metadata').get('tor'), r.get('metadata').get('os'), r.get('metadata').get('catagory'),\
                        time_utility.sqltimestamp(), r.get('metadata').get('vpn'), r.get('metadata').get('vpn_service') ) )
            print(f'report entry written for {current_ip}')
            
            #You need this for inserting into the other tales to link the data across them            
            report_id = cursor.lastrowid
            
            #NO EXPECTIONS SO INSERT INTO symptom if its not empty...
            if len(r.get('tags')) > 0:
                for s in r.get('tags'):
                    cursor.execute(sql_symptom, (s, report_id))
                    print(f'writing tag for {current_ip}')
            else:
                print(f'no tags for {current_ip}. moving to CVE')
            
            #NO EXPECTIONS SO INSERT INTO cve if its not empty...
            if len(r.get('cve')) > 0:
                for c in r.get('cve'):
                    cursor.execute(sql_cve, (c, report_id))
                    print(f'writing CVE for {current_ip}')
            else:
                print(f'no CVEs for {current_ip}. moving to scan data')
 
            #NO EXPECTIONS SO INSERT INTO scan_data if its not empty...
            if len(r.get('raw_data').get('scan')) > 0:
                #print('length test was ok on SCAN')
                for n in r.get('raw_data').get('scan'):
                    cursor.execute(sql_scan_data, (n.get('port'), n.get('protocol'), report_id))
                    print(f'writing scan_data for {current_ip}')
            else:
                print(f'no scan data for {current_ip}. moving to raw_data.web')

            
            #Web ENTRY WORKS
            if r.get('raw_data').get('web'):
                if r.get('raw_data').get('web').get('paths'):
                    #print('paths available')
                    for p in r.get('raw_data').get('web').get('paths'):
                        cursor.execute(sql_web_path, (p, report_id))
                        print(f'writing web data paths for {current_ip}')
                else:
                    print(f'no raw_data.web.paths for {current_ip}. moving to raw_data.web.useragents')

            else:
                print(f'no raw_data.web for {current_ip}. moving to scan data')

                if r.get('raw_data').get('web').get('useragents'):
                    for u in r.get('raw_data').get('web').get('useragents'):
                        cursor.execute(sql_web_useragent, (u, report_id)) 
                        print(f'writing raw_data.web.useragents for {current_ip}')
                else:
                    print(f'no raw_data.web.useragents for {current_ip}. moving to ja3')

            #ja3
            if r.get('raw_data').get('ja3'):
                for j in r.get('raw_data').get('ja3'):
                    cursor.execute(sql_ja3, (j.get('fingerprint'), j.get('port'), report_id))
                    print(f'writing raw_data.ja3 for {current_ip}.')
            else:
                print(f'no raw_data.ja3 for {current_ip}.')
            
            print(f'Writing IP info to shodanquery...')
            cursor.execute(sql_shodan_ips, (report_id, r.get('ip'), False, False, time_utility.sqltimestamp())) 
            print(f'Writing IP info to shodanquery COMPLETE')
            #TODO: Move the commit statement from the else clause to below otherwise you only commit when all data is written. 
            db.commit()

    except Exception as e:
        #print(f'ERROR in greynoisequery_manager.insert_greynoise_transaction(): {repr(e)}')
        #TODO: Write to log file
        file_utilty.write_greynoise_log(log_file, 'greynoisequery_manager.insert_greynoise_transaction()', e)
        success = False
    else:
        file_utilty.write_greynoise_log(log_file, 'greynoisequery_manager.insert_greynoise_transaction()', 'completed DB inserts without error' )
    finally:
        print(f'Grey noise query process complete')
        db.close()
        return success