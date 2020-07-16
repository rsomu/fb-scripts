# fb-scripts
Python Scripts to extract information from FlashBlade

## getaudit.py
Python script to extract audit trail information from FlashBlade in a csv format.
This csv file can be ingested into Splunk as sourcetype CSV and can be monitored for new entries.
The script can be scheduled to run at a given interval and will extract any new audit trail information since last run.

The script expects a configuration file of the format as documented in the fb.conf file.

## flashblade_audit_dashboard.xml
Splunk dashboard to show Audit information from one or more FlashBlades.
