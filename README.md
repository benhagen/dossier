dossier
=======

An all-in-one web service & frontend for quickly researching IP addresses and Hostnames.

The intent with this application was to develop some simple rest-ful web services for querying information about IP addresses and hostnames/DNS names. The frontend HTML file consumes this API directly via JavaScript and displays results via mustache.js templates. Why? I wanted to tinker with them.

Not really something you should want to deploy for public consumption yet, but it has been incredibly useful as a personal/internal tool.

Current data sources include:
DNS/hostname:
whois
DNS
SHODAN

IPv4 Address:
Reverse DNS
GeoIP Information (via MaxMind)
Shodan Information (if API key is provided)
ARIN Record (via the Arin WebAPI)


No attempt has been made to implement IPv6.

The following steps will get Dossier working on an Ubuntu 12.04 machine:
Download the MaxMind GeoLite Cuty Free datafile from: http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
Unzip and put it in the same directory as dossier.py
sudo apt-get install python-pip
sudo pip install flask requests pygeoip dnspython shodan
./app.py
Goto: http://127.0.0.1:5000 in your web browser

The flask application should be configurable as any other WSGI application for "permanent" installation. See: http://flask.pocoo.org/docs/deploying/ for more information

Next Steps:
Implement (better) logging
Add more information resources