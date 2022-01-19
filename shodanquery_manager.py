import json
import pymysql
import time
import datetime
import time_utility
import connection_manager
import file_utilty

def get_search_ips(server, log_file):
    #database connection
    sql_shodan = 'SELECT * FROM shodanquery WHERE queried = %s;'
    #db = connection_manager.get_ssh_tunnelled_connection(server)
    try:
        db = connection_manager.get_db_connection(server)
        cursor = db.cursor()
        cursor.execute(sql_shodan, False)
        results = cursor.fetchall()
    except Exception as e:
        print(f'Error in shodanquery_manager.get_search_ips() of type {type(e)} Message: {e}')
        file_utilty.write_shodan_log(log_file, 'shodanquery_manager.get_search_ips()', e)
        results = tuple()
    finally:
        db.close()
        return results

def update_found_ips(server, ls, log_file):
    sql = 'UPDATE shodanquery SET found = TRUE WHERE ip = %s;'
    try:
        db = connection_manager.get_db_connection(server)
        cursor = db.cursor()
        for ip in ls:
            cursor.execute(sql, (ip))
            db.commit()
    except Exception as e:
        print(f'shodanquery_manager.update_found_ips(): ERROR {e}')
        file_utilty.write_shodan_log(log_file, 'shodanquery_manager.update_found_ips()', e)
    finally:
        db.close()


def update_queried(server, query_date, log_file):
    sql = 'UPDATE shodanquery SET queried = TRUE where timestamp = %s'
    try:
        db = connection_manager.get_db_connection(server)
        cursor = db.cursor()
        for ip in ls:
            cursor.execute(sql, (ip))
            db.commit()
    except Exception as e:
        print(f'shodanquery_manager.update_queried(): ERROR {e}')
        file_utilty.write_shodan_log(log_file, 'shodanquery_manager.update_queired()', e)
    finally:
        db.close())    



