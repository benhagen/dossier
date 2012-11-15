#!/usr/bin/env python

import requests
import pygeoip
import re
import socket
import dns
import dns.resolver
import dns.rdatatype
import dns.message
import dns.query
import dns.reversename
import dns.exception
from shodan import WebAPI


# Add custom whois servers for rare domains here
WHOIS_SERVERS = {
	"ly": "whois.nic.ly",
	"io": "whois.nic.io"
}

# Modify prefix for domains ending with:
WHOIS_MODIFIERS_PRE = {
	"com": "domain "
}

# Modify postfix for domains ending with:
WHOIS_MODIFIERS_POST = {
	"jp": " /e"
}

# Regex patterns to remove some of the junk returned by WHOIS servers
WHOIS_DEFLUFF = [
"Whois Server Version .* detailed information\.",
"NOTICE.*Registrars\.",
"Access to \.ORG WHOIS.*abide by this policy\.",
"--\nThis WHOIS .* restricted at any time\.",
"\[ JPRS .* \]\n\n",
"The data contained in GoDaddy\.com.* listed in this database\.",
"=-=-=-=\nThe data in this whois .*2002",
"MarkMonitor is the Global Leader in Online Brand Protection\.",
"The Data in MarkMonitor\.com's WHOIS .* abide by this policy\.",
"Domain Management\nMarkMonitor Brand Protection.\nMarkMonitor AntiPiracy.\nMarkMonitor AntiFraud.\nProfessional and Managed Services",
"Visit MarkMonitor at www\.markmonitor\.com\nContact us at 1 \(800\) 745-9229\nIn Europe, at \+44 \(0\) 203 206 2220\n",
"\n--\n",
"=-=-=-=\n",
"NOTICE AND TERMS OF USE: You are not authorized to access or query our .* right to modify these terms at any time\.\n",
"Get a FREE domain name registration, transfer, or renewal with any annual hosting package\.\n",
"------------------------------------------------------------------------\n.*------------------------------------------------------------------------\n",
"This Registry database contains ONLY \.EDU domains.*type: help\n\n--------------------------\n"
]


def is_valid_ipv4(ip):
	match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
	if not match:
		return False
	quad = []
	for number in match.groups():
		quad.append(int(number))
	if quad[0] < 1:
		return False
	for number in quad:
		if number > 255 or number < 0:
			return False
	return True


def is_valid_domain(domain):
	match = re.match("^(.*)\.(.*)$", domain)
	if not match:
		return False
	return True


def arin(ip_address):
	response = requests.get("http://whois.arin.net/rest/ip/%s" % (ip_address), headers={'Accept': 'application/json'})
	output = {}
	if "comment" in response.json["net"]:
		output["comment"] = ""
		if type(response.json["net"]["comment"]["line"]) == type([]):
			for line in response.json["net"]["comment"]["line"]:
				output["comment"] += line["$"].strip() + "\n"
		else:
			output["comment"] += response.json["net"]["comment"]["line"]["$"].strip()
	output["startAddress"] = response.json["net"]["startAddress"]["$"]
	output["endAddress"] = response.json["net"]["endAddress"]["$"]
	output["updateDate"] = response.json["net"]["updateDate"]["$"]
	output["handle"] = response.json["net"]["handle"]["$"]
	output["name"] = response.json["net"]["name"]["$"]
	if "registrationDate" in response.json["net"]:
		output["registrationDate"] = response.json["net"]["registrationDate"]["$"]
	if "orgRef" in response.json["net"]:
		output["orgRef"] = {}
		output["orgRef"]["name"] = response.json["net"]["orgRef"]["@name"]
		output["orgRef"]["handle"] = response.json["net"]["orgRef"]["@handle"]
		output["orgRef"]["reference"] = response.json["net"]["orgRef"]["$"]
	output["netBlocks"] = []
	for netblock in response.json["net"]["netBlocks"].values():
#		block = []
		block_section = {}
		if type(netblock) == type([]):
			for section in netblock:
				for key, value in section.items():
					block_section[key] = value["$"]
#				block.append(block_section)
		else:
			for key, value in netblock.items():
				block_section[key] = value["$"]
#			block.append(block_section)
		output["netBlocks"].append(block_section)
	return output


def geoip(ip_address, file='./GeoLiteCity.dat'):
	output = {}
	gic = pygeoip.GeoIP('./GeoLiteCity.dat')
	mapping = {
		"area_code": "areaCode",
		"city": "city",
		"country_code": "countryCode",
		"country_code3": "countryCode3",
		"country_name": "country",
		"dma_code": "dmaCode",
		"latitude": "latitude",
		"longitude": "longitude",
		"metro_code": "metroCode",
		"postal_code": "postalCode",
		"region_name": "regionName",
		"time_zone": "timeZone",
	}
	result = gic.record_by_addr(ip_address)
	if result:
		for key, value in result.items():
			output[mapping[key]] = value
	return output


def reversedns(ip_address):
	output = {}
	address = dns.reversename.from_address(ip_address)
	try:
		results = dns.resolver.query(address, "PTR")
	except:
		return output
	output["records"] = []
	for result in results:
		output["records"].append(str(result))
	return output


def whois(domain, server=False, depth=0):
	if depth > 2:
		return False
	query = domain.lower()
	tld = query.split('.')[-1]
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(1)
	# Use WHOIS_SERVERS for identified tld's, magic whois-servers.net other
	if not server:
		if tld in WHOIS_SERVERS:
			server = WHOIS_SERVERS[tld]
		else:
			server = tld + ".whois-servers.net"
	try:
		sock.connect((server, 43))
	except:
		return False
	# Modifiers
	if tld in WHOIS_MODIFIERS_PRE and depth == 0:
		query = WHOIS_MODIFIERS_PRE[tld] + query
	if tld in WHOIS_MODIFIERS_POST and depth == 0:
		query = query + WHOIS_MODIFIERS_POST[tld]
	try:
		sock.send(query + "\r\n")
		response = ""
		while True:
			d = sock.recv(4096)
			response += d
			if d == '':
				break
		sock.close()
	except:
		return False
	# Cleanup
	output = ""
	response = response.decode('utf8')
	response = response.replace("\r", "")
	for line in response.split("\n"):
		output += line.rstrip() + "\n"
	# Apply defluffing regular expressions
	for fluff in WHOIS_DEFLUFF:
		output = re.sub(fluff, "", output, flags=re.DOTALL)

	while output.find("\n\n\n") != -1:
		output = output.replace("\n\n\n", "\n\n")
	output = output.strip()

	output = ("[ QUERY: %s ]\n[ WHOIS SERVER: %s ]\n\n" % (query, server)) + output

	match = re.search("Whois Server: (.*)", output)
	if match:
		extended = whois(domain, server=match.groups()[0], depth=(depth + 1))
		if extended:
			output = output + "\n\n" + extended

	return output


def shodanquery(query, api_key=None):
	if not api_key or api_key == "":
		return False
	api = WebAPI(api_key)
	if is_valid_ipv4(query):
		try:
			response = api.host(query)
		except:
			return False
	else:
		try:
			response = api.search(query)
		except:
			return False
	return response


def majordomain(domain):
	parts = domain.lower().split('.')
	if parts[-1] in ["com", "net", "org", "edu"]:
		return ".".join(parts[-2:])
	if parts[-2] in ["com", "net", "org", "edu", "ac", "co"]:
		return ".".join(parts[-3:])
	return ".".join(parts[-2:])


def dnsquery(domain):
	output = []
	recordtypes = ["A", "AAAA", "CERT", "CNAME", "MX", "NS", "PTR", "SOA", "TXT"]
	for recordtype in recordtypes:
		message = dns.message.make_query(domain, recordtype)
		message.timeout = 1
		results = dns.query.udp(message, "8.8.8.8")
		for answer in results.answer:
			output.append({"type": recordtype, "string": answer.to_text()})
	return output

if __name__ == "__main__":
	print "Nothing here."
