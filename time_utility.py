import time
import datetime

def sqltimestamp():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

def filetimestamp():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d-%H-%M-%S')

def logfiletimestamp():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d-%H-%M-%S')

def year_month():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m')

def yesterdaydate():
    ts = (datetime.date.today())-datetime.timedelta(days=1)
    return ts.strftime('%Y-%m-%d')
