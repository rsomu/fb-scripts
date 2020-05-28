#!/usr/bin/python
################################################################################
#  Author: Somu Rajarathinam (somu) @ Pure Storage                             #
#  Date  : 2020-05-27                                                          #
#                                                                              #
#  Python script to extract audit trail from FlashBlade running Purity 3.0.    #
#  The script appends the output to a csv file which can be fed into Splunk.   #
#  Set the sourcetype to CSV and monitor the csv file.                         #
#  Script can be scheduled to run periodically and every time the script is    #
#  run it extracts the audit data since the last run.                          #
#                                                                              #
#  getaudit.py <conf file>                                                     #
#                                                                              #
#  Prerequisite:                                                               #
#                                                                              #
#  The script expects a configuration file with following stanzas and entries  #
#                                                                              #
#  [FlashBlade]                                                                #
#  array_address = https://10.20.10.21                                         #
#  api-token = xxxxxxxxx                                                       #
#                                                                              #
#  [Output]                                                                    #
#  file = <absolute-file-name.csv>                                             #
#                                                                              #
#  [Log]                                                                       #
#  file = <absolute-log-file-name.log>                                         #
#                                                                              #
#  [lastrun]                                                                   #
#  sequence = 0                                                                #
#                                                                              #
# Note: Don't update the sequence info as the script will automatically        #
# update it after every run for continuation.                                  #
#                                                                              #
# If the log file is not provided, script will log messages into audit-fb.log. #
#                                                                              #
#*******Disclaimer:************************************************************#
# This script is offered "as is" with no warranty.  While this script is       #
# tested and worked in our environment, it is recommended that you test        #
# this script in a test lab before using in a production environment.          #
# No written permission needed to use this script but me or Pure Storage       #
# will not be liable for any damage or loss to the system.                     #
################################################################################

import sys
import time
import requests
import ConfigParser
import json
from datetime import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

def log(lf,msg):
  now = datetime.now()
  ct = now.strftime("%Y-%m-%d %H:%M:%S")
  lf.write("%19s: %s\n"% (ct,msg))

def die(lf, msg):
  log(lf, msg)
  log(lf, "Run failed")
  sys.exit(-1)

def get_audit(conf_file):

   config = ConfigParser.ConfigParser()
   config.read(conf_file)

   if (not(config.has_option('Log','file'))):
     logfile = './audit-fb.log'
   else:
     logfile = config.get('Log','file')

   lfile = open(logfile,'a')
   log(lfile,"Run started")


   if (config.has_option('FlashBlade','array_address')):
      array_address = config.get('FlashBlade','array_address')
   else:
      die(lfile,"FlashBlade array_address not specified in the config file")

   if (config.has_option('FlashBlade','api-token')):
      api_token = config.get('FlashBlade','api-token')
   else:
      die(lfile,"FlashBlade api-token option not specified in the config file")
   url=array_address+"/api/login"
   header = { 'api-token' : api_token,
              'user-agent': "Python-Custom-script"
            }

   if (config.has_option('lastrun','sequence')):
      last_seq = config.get('lastrun','sequence')
      upd = 0
   else:
      last_seq = "0"
      upd = 1

   if (config.has_option('Output','file')):
      outfile = config.get('Output','file')
   else:
      die(lfile,"Output file not specified in the config file")

   ct = 0
   try:
     resp = requests.post(url,headers=header, verify=False)
     del header['api-token']
     header['x-auth-token'] = resp.headers['x-auth-token']
     resp = requests.get(array_address+"/api/1.9/audits?start="+last_seq, headers=header, verify=False)
     aData = resp.json()
     if (len(aData["items"]) == 0):
         die(lfile,"No new audit entries")
   except Exception as e:
     die(lfile,e)

   ofile = open(outfile,'a')
   if (last_seq == "0") :
      ofile.write("date_time, user, command, sub_command, arguments, ip_address, user_interface, user_agent\n")
   for index, item in enumerate(aData["items"]):
      tm = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item['time']/1000))
      ct += 1
      lseq = item['name']
      ua = item.get('user_agent',"No_user_agent")
      ofile.write("{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}\n".format(tm, item['user'], item['command'], item['subcommand'], item['arguments'], item['ip_address']
, item['user_interface'], ua))
   ofile.close()

   log(lfile,"Loaded "+str(ct)+" entries ")
   with open(conf_file,"r+") as configfile:
       if (upd == 1):
          config.add_section('lastrun')
       config.set('lastrun','sequence',lseq)
       config.write(configfile)
   log(lfile,"Run completed")
   lfile.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('usage: \n./getaudit.py <conf file>\n')
    else:
        get_audit(sys.argv[1])
