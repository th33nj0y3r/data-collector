import json
import pymysql
import time
import datetime
import time_utility
import connection_manager
import file_utilty

#sd is short for 'shodan' report 
def insert_shodan_report_transaction(sd, reportid, queried_ip, server, log_file, original_file_timestamp):
    #db = connection_manager.get_ssh_tunnelled_connection(server)
    db = connection_manager.get_db_connection(server)
    cursor = db.cursor()
    
    #var for if the data was sucessfully inserted
    success = True
    
    sql_shodan_report = 'INSERT INTO shodan_report (report_id, shodan_record, region_code, ip, area_code, postal_code, dma_code, country_code, org, asn, city, latitude,\
        isp, longitude, last_update, country_code3, country_name,\
            ip_str, os, timestamp)\
              VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);'
    sql_shodan_report_null ='INSERT INTO shodan_report(report_id, shodan_record, ip_str, timestamp) VALUES (%s, %s, %s, %s);'
    sql_shodan_tag = 'INSERT INTO shodan_tag (shodanreport_id, tag) VALUES (%s, %s);'
    sql_shodan_domain = 'INSERT INTO shodan_domain (shodanreport_id, domain) VALUES (%s, %s);'
    sql_shodan_hostname = 'INSERT INTO shodan_hostname (shodanreport_id, hostname) VALUES (%s, %s);'
    sql_shodan_port = 'INSERT INTO shodan_port (shodanreport_id, port) VALUES (%s, %s);'
    sql_shodan_vuln = 'INSERT INTO shodan_vuln (shodanreport_id, vulnerability) VALUES (%s, %s);'
    
    #sql_shodan_ports

    #NOTE: If shodan didn't find a record for an IP, we've given assigned a blank shodan record as a return value with an impossible IP 
    # to make filtering positive and negative shodan results easier in this function easier. See shodanmanager.query_shodan_with_ip() for more clarification. 
    shodan_record_found = True
    if sd.get('ip') == '999.999.999':
        shodan_record_found = False
    
    try:
        if shodan_record_found:
            cursor.execute(sql_shodan_report, (reportid, shodan_record_found, sd.get('region_code'), sd.get('ip'), sd.get('area_code'), sd.get('postal_code'),\
                 sd.get('dma_code'), sd.get('country_code'), sd.get('org'), sd.get('asn'), sd.get('city'), sd.get('latitude'), sd.get('isp'), sd.get('longitude'),\
                      sd.get('last_update'), sd.get('country_code3'), sd.get('country_name'), sd.get('ip_str'), sd.get('os'), time_utility.sqltimestamp()))
            shodan_report_id = cursor.lastrowid

            #insert shodan tag
            if sd.get('tags'):
                for tag in sd.get('tags'):
                    cursor.execute(sql_shodan_tag, (shodan_report_id, tag))
            
            #insert shodan domain
            if sd.get('domains'):
                for domain in sd.get('domains'):
                    cursor.execute(sql_shodan_domain, (shodan_report_id, domain))

            #insert shodan hostname
            if sd.get('hostnames'):
                for hostname in sd.get('hostnames'):
                    cursor.execute(sql_shodan_hostname, (shodan_report_id, hostname))

            
            #insert shodan ports
            if sd.get('ports'):
                for port in sd.get('ports'):
                    cursor.execute(sql_shodan_port, (shodan_report_id, port))

            #insert shodan vulnerability
            if sd.get('vulns'):
                for vuln in sd.get('vulns'):
                    cursor.execute(sql_shodan_vuln, (shodan_report_id, vuln))

            #TODO: write shodan data tag to a .json file because its structure is always varied
            if sd.get('data'):
                st = sd.get('ip_str')
                jfn = (f'{st}-{original_file_timestamp}')
                count = 0
                try:
                    for d in sd.get('data'):
                        count = count + 1
                        fl = (f'{jfn}-{count}.json')
                        file_utilty.write_json_to_file(fl, 'shodan_data_dump', d)
                except Exception as e:
                    print(f'shodan_report_manager.insert_shodan_report+transaction(). ERROR writing dat achunk: {e}')
                    file_utilty.write_shodan_log(log_file, 'shodan_report_manager.insert_shodan_report_transaction',(f'Error writing data file for {st}'))
            db.commit()
        else:
            cursor.execute(sql_shodan_report_null, (reportid, shodan_record_found, queried_ip, time_utility.sqltimestamp()))
            db.commit()

    except Exception as e:
        print(f'ERROR IN shodan_report_manager.insert_shodan_report_transation() when inserting {queried_ip}. ERROR: {e}')
        file_utilty.write_shodan_log(log_file, 'shodan_report_manager.insert_shodan_report_transaction()', e)
        success = False
    finally:
        db.close()
        return success

