# zabbix-ssl #
Zabbix check SSL certificates

We have to different ways to check for ssl certificates

1. If you have only one certificate per IP address, use the standard 
   templates along with the ssltls.check script
2. If you use multiple SSL certificates per IP address, then you
   need to use the ssltls-sni.check and Template_App_HTTPS_Autodiscovery.xml

This script and the templates allow your zabbix server
to validate SSL certificates.

It supports direct SSL/HTTPS checks as well as STARTTLS connections
Supported check types
* simple    Checks if SSL is active
* startdate Startdate of certificate
* enddate   Enddate of certificate
* lifetime  How long the certificate is valid
* ssl3      SSLv3 active ? (Poodle vulnerable) 
            This only works when your openssl binaries still have built in ssl3 support
* digestmode Hash algorithm (For example detect SHA1 certificates)

## How to install ##
* Download the ssltls.check file to your **Zabbix Server**
  external script directory (Or your proxy if the servers are behind a Zabbix proxy)
  For example ExternalScripts=/usr/lib/zabbix/externalscripts
* Make it executable
* Import the templates for the different check types in your zabbix server
* Assign the templates to the hosts you wish to monitor

### Additional setup required for SNI ###
Only needed if you have multiple certificates on the same IP+Port

* Put the /etc/zabbix/zabbix_agentd.d/ssl-sites.conf in the config directory
  of your **client agent** (The server where your sites reside)
* Put the /etc/zabbix/ssl_sites.json in the config directory
  of your **client agent** (The server where your sites reside)
  and modify the list of sites which should be checked.
  This is the list of certificates to check on this server
  Make sure it has a valid json syntax
* Restart the zabbix agent


(C) 2017 André Schild <a.schild aarboard.ch>
