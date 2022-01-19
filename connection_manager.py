import secrets
import pymysql
import config
from sshtunnel import SSHTunnelForwarder
from keysecrets import *

def get_db_connection(server=None):
    if config.remote:
        return get_ssh_tunnelled_connection(server)
    else:
        return get_connection()


def get_ssh_tunnel():
    try:
        return SSHTunnelForwarder(server_ip, ssh_username=ssh_user, ssh_pkey=ssh_key_path, remote_bind_address=(bind_address, reomte_port))
    except Exception as e:
        print(f'ERROR in connection_manager().get_ssh_tunnel(): {e}')


#use this when the script is running on the remote server
def get_connection():
    try:
        return pymysql.connect(host=local_host, user=local_user, password=local_password, db=local_db)
    except Exception as e:
        print(f'Error in get_connection(): {e}')


#use this when you're trying to test the script remotely via ssh
def get_ssh_tunnelled_connection(server):
    try:
        return pymysql.connect(host=local_host, port= server.local_bind_port, user=local_user, password=local_password, db=local_db)
    except Exception as e:
        print(f'ERROR IN connection_manager().get_ssh_tunnelled_connection(): {e}')
        return None