# fb-scripts
Python Scripts to extract audit information from FlashBlades

## getaudit.py
Python script to extract audit trail information from FlashBlade in a csv format.
This csv file can be ingested into Splunk as sourcetype CSV and can be monitored for new entries.
The script can be scheduled to run at a given interval and will extract any new audit trail information since last run.

The script expects a configuration file of the format as documented in the fb.conf file.

## fb.conf
1) If you want to configure more than one FlashBlade, specify the count against fbcount in the default section.
   If the count doesn't match the FlashBlade sections suffixed with hyphen and sequence numbers, the code will report an error and stop.
2) If you want to extract the audit details across all FlashBlades to a single file, specify outfile in the default section.
   This will ignore the individual outfile entries in each FlashBlade section.
3) Do not update the lastrun as the code will use it for continuation after every run.
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

## flashblade_audit_dashboard.xml
Splunk dashboard to show Audit information from one or more FlashBlades.
