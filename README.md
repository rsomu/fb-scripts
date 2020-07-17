# fb-scripts
Python Scripts to extract audit information from FlashBlades

## getaudit.py
Python script to extract audit trail information from one or more FlashBlades into a csv output file.
This csv file can be ingested into Splunk as sourcetype CSV and can be monitored for new entries.
This python script can be scheduled to run at a given interval and can extract any new audit trail information since last run.
The script expects a configuration file of the format as documented in the fb.conf file.

Usage
```
getaudit.py <conf file>
```

## fb.conf
1) If you want to configure more than one FlashBlade, specify the count against fbcount in the default section.
   If the count doesn't match the FlashBlade sections suffixed with hyphen and sequence number, the code will report an error and stop.
   For example, when fbcount=2 the code expects two sections named FlashBlade-1 and FlashBlade-2.
   If fbcount is not provided, the code expects a single section named FlashBlade-1.
2) If you want to extract the audit details across all FlashBlades to a single output file, specify outfile in the default section.
   This will ignore the individual outfile entries in each FlashBlade section.
   Alternatively, not including the outfile in default section will allow the code to extract the audit details to individual output files
   specified under each section.
3) Do not update the lastrun in any of the sections as the code will use it for continuation after every run.
   Setting it to 0 or removing lastrun will collect the audit details again for that FlashBlade.
4) If the logfile is not specified in the default section, messages will be logged into a file
   audit-fb.log under the current directory.
```
[default]
fbcount = 2
outfile = /data/splunk/audit-fb.csv
logfile = <absolute-path-for-logfile>

[FlashBlade-1]
array_address = https://10.10.100.100
api-token = T-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
outfile = <absolute-path-for-outfile>
lastrun = 214

[FlashBlade-2]
array_address = https://10.20.200.150
api-token = T-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
outfile = /data/splunk/fb2/fb-audit2.csv
lastrun = 170
```

To create/get the api-token for an user from the FlashBlade use the following CLI command.
1) To create the api-token for the very first time
```
pureadmin create --api-token
```

2) To get the existing api-token
```
pureadmin list --api-token --expose
```

## flashblade_audit_dashboard.xml
Splunk dashboard to show Audit information from one or more FlashBlades.
The dashboard search queries uses index=fbaudit.  If you are using any other
index name, please edit the dashboard and update it.
