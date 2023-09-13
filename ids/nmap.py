import json
import time
import logging
import logging_loki
import subprocess
from scrape import scrape

DEBUG = False
INTERVAL = 60 * 5

logging_loki.emitter.LokiEmitter.level_tag = "level"

# assign to a variable named handler
handler = logging_loki.LokiHandler(
    url="http://localhost:3100/loki/api/v1/push",
    version="1"
)

# create a new logger instance
sweep = logging.getLogger("nmap-sweep")
sweep.addHandler(handler)
sweep.setLevel(logging.DEBUG)

stats = logging.getLogger("nmap-stats")
stats.addHandler(handler)
stats.setLevel(logging.DEBUG)

outliers = logging.getLogger("nmap-outliers")
outliers.addHandler(handler)
outliers.setLevel(logging.DEBUG)

outlier_buff = {}

if __name__ == '__main__':

    while True:

        if DEBUG:
            with open('sample.txt', 'r') as f:
                command_out = f.read()
            stats.debug('Test script opened')
        else:
            command_out = subprocess.run(["sudo", "./command.sh"], capture_output=True).stdout.decode('utf-8')
            stats.info('Scanning complete')
        
        devices, ts = scrape(command_out)
        devices_count = len(devices)

        # transform
        devices_dict = {}
        for device in devices:

            key = device['mac_addr']
            devices_dict[key] = device
            
        diff_dict = {}
        # Detect Outliers from buffer
        if len(outlier_buff) > 0:
            diff = set(devices_dict).difference(outlier_buff)
            if len(diff) > 0:
                for key in diff:
                    diff_dict[key] = devices_dict[key]
        outlier_buff = devices_dict.copy()
            

        d = {'ts':str(ts), 'device_count':len(devices), 'devices':devices_dict, 'new_devices':diff_dict}
        d_outliers = {'new_devices':diff_dict, 'count':len(diff_dict)}
        if len(diff_dict) > 0:
            sweep.warn(json.dumps(d)) if not DEBUG else sweep.debug(json.dumps(d))
            outliers.warn(json.dumps(d_outliers)) if not DEBUG else outliers.debug(json.dumps(d_outliers))
        else:
            sweep.info(json.dumps(d)) if not DEBUG else sweep.debug(json.dumps(d))

        stats.debug('Awaiting interval') if DEBUG else stats.info('Awaiting interval')
        time.sleep(INTERVAL)

        # sweep.info("""ts={} devices=\"{}\"""".format(ts, devices)) if not DEBUG else sweep.debug("""ts={} devices=\"{}\"""".format(ts, devices))
        
    


    
    print(devices)