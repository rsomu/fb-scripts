#!/usr/bin/python 
################################################################################
#  Author  : Somu Rajarathinam (somu) @ Pure Storage                           #
#  Date    : 2020-07-16                                                        #
#  Filename: getaudit.py - Version 2.0                                         #
#                                                                              #
#  Python script to extract audit trail from FlashBlade running Purity 3.0.    #
#  The script appends the output to a csv file which can be fed into Splunk.   #   
#  Set the sourcetype to CSV and monitor the csv file.                         #
#  Script can be scheduled to run periodically and every time the script is    #
#  run it extracts the audit data since the last run.                          #
#  Ideally set a cron schedule to run this script.                             #
#                                                                              #
#  getaudit.py <conf file>                                                     #
#                                                                              #
#  Prerequisite:                                                               #
#                                                                              #
#  The script expects a configuration file with following stanzas and entries. #
#  If you have more than one FlashBlade to capure, please enter the count      #
#  in the default section against fbcount and create a separate stanza for     #
#  each FlashBlade with a suffix including the hyphen and sequence number.     #
#  If the number of FlashBlade sections doesn't match the fbcount, the code    #
#  will report an error.                                                       #
#                                                                              #
#  [default]                                                                   #
#  fbcount = 2                                                                 #
#  logfile = <absolute-log-file-name.log>                                      #
#  outfile = <absolute-file-name.csv>  # All data will be written to one file  #
#                                                                              #
# Note: If outfile is included in default section, all date will be written to #
# one file and the outfile from other sections will be ignored.                #
#                                                                              #
#  [FlashBlade-1]                                                              #
#  array_address = https://10.20.10.21                                         #
#  api-token = xxxxxxxxx                                                       #
#  outfile = <absolute-file-name.csv>                                          #
#  lastrun = 0                                                                 #
#                                                                              #
#  [FlashBlade-2]                                                              #
#  array_address = https://10.40.50.90                                         #
#  api-token = xxxxxxxxx                                                       #
#  outfile = <absolute-file-name.csv>                                          #
#  lastrun = 0                                                                 #
#                                                                              #
# Note: Don't update the lastrun info as the script will automatically         #
# update it after every run for continuation.                                  #
#                                                                              #
# If the log file is not provided, script will log messages into audit-fb.log. #
#                                                                              #
# 2020/05/27 1.0 Initial version                                               #
# 2020/07/16 2.0 Updated the script to extract array information,              #
#                changed the conf file to include multiple Flashblades         #
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

def log(lf,ltype,msg):
  now = datetime.now()
  ct = now.strftime("%Y-%m-%d %H:%M:%S")
  lf.write("%19s: %5s : %s\n"% (ct,ltype,msg))

def die(lf, msg):
  log(lf, "ERROR", msg)
  log(lf, "WARN", "Run failed")
  sys.exit(-1)

def get_audit(conf_file):

   config = ConfigParser.ConfigParser()
   config.read(conf_file)

   if (not(config.has_option('default','logfile'))):
     logfile = './audit-fb.log'
   else:
     logfile = config.get('default','logfile')
     
   lfile = open(logfile,'a') 
   log(lfile,"INFO", "Run started")


   if (config.has_option('default','fbcount')):
      fbcount = int(config.get('default','fbcount'))
   else:
      fbcount = 1

   singleoutfile = False
   if (config.has_option('default','outfile')):
     outfile = config.get('default','outfile')
     ofile = open(outfile,'a')
     singleoutfile = True
     log(lfile,"INFO","Events will be loaded into "+outfile)

   i = 1   
   missing=False
   while i <= fbcount :
     opt = 'FlashBlade-'+str(i)
     if not (config.has_section(opt)): 
       log(lfile,"ERROR", "Section "+opt+" missing ")
       missing=True
     i+=1
   if (missing):
      die(lfile,"Not all sections available in the conf file")

   i = 0   
   while i < fbcount :
     i += 1
     opt = 'FlashBlade-'+str(i)
     if (config.has_option(opt,'array_address')):
       array_address = config.get(opt,'array_address')
     else:
       log(lfile,"ERROR",opt+" array_address not specified in the config file")
       continue

     if (config.has_option(opt,'api-token')):
        api_token = config.get(opt,'api-token')
     else:
        log(lfile,"ERROR", opt+" api-token option not specified in the config file")
        continue

     url=array_address+"/api/login"
     header = { 'api-token' : api_token, 
                'user-agent': "Python-Custom-script"
              }
  
     if (config.has_option(opt,'lastrun')):
        last_seq = config.get(opt,'lastrun')
        upd = 0
     else:
        last_seq = "0" 
        upd = 1
  
     if not (singleoutfile):
       if (config.has_option(opt,'outfile')):
          outfile = config.get(opt,'outfile')
       else:
          log(lfile,"ERROR", "Output file not specified in the config file for "+opt)
          continue
  
     ct = 0
     try:
       resp = requests.post(url,headers=header, verify=False)
       del header['api-token']
       header['x-auth-token'] = resp.headers['x-auth-token']
       arr = requests.get(array_address+"/api/1.9/arrays", headers=header, verify=False)
       arrData = arr.json()
       resp = requests.get(array_address+"/api/1.9/audits?start="+last_seq, headers=header, verify=False)
       audData = resp.json()
       if (len(audData["items"]) == 0):
           log(lfile,"INFO", "No new audit entries for "+opt)
           continue
     except Exception as e:
       log(lfile,"ERROR","Exception with "+opt)
       log(lfile,"ERROR", e)
       continue
  
     arrName = arrData["items"][0]['name']
     arrId = arrData["items"][0]['id']
     arrVer = arrData["items"][0]['version']
     if (not singleoutfile):
       ofile = open(outfile,'a')
     if (last_seq == "0" and i == 1) :
        ofile.write("date_time, array_name, array_id, array_version, user, command, sub_command, arguments, ip_address, user_interface, user_agent\n")
     for index, item in enumerate(audData["items"]):
        tm = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item['time']/1000))
        ct += 1
        lseq = item['name']
        ua = item.get('user_agent',"No_user_agent")
        ofile.write("{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}\n".format(tm, arrName, arrId, arrVer, item['user'], item['command'], item['subcommand'], item['arguments'], item['ip_address'], item['user_interface'], ua))
     if (not singleoutfile):
       ofile.close()
       log(lfile,"INFO", "Loaded "+str(ct)+" entries from "+opt+" into "+outfile) 
     else: 
       log(lfile,"INFO", "Loaded "+str(ct)+" entries from "+opt) 
     with open(conf_file,"r+") as configfile:
       config.set(opt,'lastrun',lseq) 
       config.write(configfile)
   if (singleoutfile):
     ofile.close()
   log(lfile,"INFO", "Run completed")
   lfile.close()
  
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('usage: \n./getaudit.py <conf file>\n')
    else:
        get_audit(sys.argv[1])
