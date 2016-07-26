# zabbix-ssl
Zabbix check SSL certificates

This script and the templates allow your zabbix server
to validate SSL certificates.

It supports direct SSL/HTTPS checks as well as STARTTLS connections

How to install:
- Download the ssltls.check file to your Zabbix Server 
  external script directory (Or your proxy if the servers are behind a Zabbix proxy)
  For example ExternalScripts=/usr/lib/zabbix/externalscripts
- Make it executable
- Import the templates for the different check types in your zabbix server
- Assign the templates to the hosts you wish to monitor


