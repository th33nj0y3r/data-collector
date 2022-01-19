import json
import time_utility

#Write a json file...
def write_json_to_file(name, folder, data):
    fname = folder+'/'+name 
    with open(f'{fname}', 'w') as f:
        json.dump(data, f)
    f.close()
        

#TODO: Finish writing this for logs...
def write_log_to_file(target_file, folder, log_entry):
    fname = folder+'/'+target_file
    with open(f'{fname}','a') as f:
        print(log_entry, file=f)
    f.close()

def write_greynoise_log(file_name, function, message):
    datetime = time_utility.sqltimestamp()
    t = '\t'
    entry = datetime + t + message + t + function
    write_log_to_file(file_name, 'g_logs', entry)

def write_shodan_log(file_name, function, message):
    datetime = time_utility.sqltimestamp()
    t = '\t'
    entry = datetime + t + message + t + function
    write_log_to_file(file_name, 's_logs', entry)