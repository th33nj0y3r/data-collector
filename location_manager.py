import json
import pymysql
import time
import datetime
import time_utility
import connection_manager

def getlocations(server):
    #database connection
    db = connection_manager.get_ssh_tunnelled_connection(server)
    cursor = db.cursor()
    sql = 'SELECT DISTINCT(name) FROM location'
    cursor.execute(sql)
    results = cursor.fetchall()
    cities = [x[0] for x in results]
    print(f'Cities type: {type(cities)}')
    return cities
    
