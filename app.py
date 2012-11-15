#!/usr/bin/env python

# "Standard" libraries
import os
import logging, logging.handlers
# "Non-Standard" libraries
from flask import Flask, make_response, render_template
import json
# Custom imports
import ip
import config

ApplicationName = "Dossier"
ApplicationEnvironment = "Development"

### Logging ###
logging.basicConfig()
logger = logging.getLogger(ApplicationName)
logger.setLevel(logging.INFO)

app = Flask(__name__)

### Configuration management ###
if ApplicationName + "_ENVIRONMENT" in os.environ:
	ApplicationEnvironment = os.environ[ApplicationName + "_ENVIRONMENT"]
# Load the specified environment class/configuration
app.config.from_object("config." + ApplicationEnvironment)
logger.info("Starting \"%s\" with configuration environment \"%s\"" % (ApplicationName, app.config["ENVIRONMENT"]))
# Override settings from file if set
if ApplicationName + "_SETTINGS" in os.environ:
	logger.info("Starting \"%s\" with configuration environment \"%s\"" % (ApplicationName, app.config["ENVIRONMENT"]))
	app.config.from_envvar(ApplicationName + "_SETTINGS")


def response_json(output, response_code=200):
	response = make_response(json.dumps(output, sort_keys=True, indent=4))
	response.headers['Content-Type'] = 'application/json'
	response.status_code = response_code
	return response


### Routes ###
@app.route("/", methods=['GET'])
def root():
	return render_template('root.html')


@app.route("/ip/<string:query>", methods=['GET'])
def query_ip(query):
	logger.info("IP query received for \"%s\"" % (query))
	if not ip.is_valid_ipv4(query):
		response = make_response()
		response.status_code = 404
		return response
	output = {}
	output["arin"] = ip.arin(query)
	output["geoip"] = ip.geoip(query, geoip_file=app.config['GEOIP_FILE'])
	output["reversedns"] = ip.reversedns(query)
	output["shodan"] = ip.shodanquery(query, api_key=app.config['SHODAN_API_KEY'])
	response_code = 200
	return response_json(output, response_code=response_code)


@app.route("/dns/<string:query>", methods=['GET'])
def query_dns(query):
	logger.info("DNS query received for \"%s\"" % (query))
	if not ip.is_valid_domain(query):
		response = make_response()
		response.status_code = 404
		return response
	output = {}
	output["dns"] = ip.dnsquery(query)
	output["whois"] = ip.whois(query)
	output["shodan"] = ip.shodanquery(query, api_key=app.config['SHODAN_API_KEY'])
	output["resources"] = [
		{"name":"Built With - Display the technology 'profile' of a website", "value":"http://builtwith.com/" + query},
		{"name":"Snapito - Website Screenshot", "value":"http://snapito.com/?url=%s&freshness=86400" % (query)}
	]
	response_code = 200
	return response_json(output, response_code=response_code)

if __name__ == "__main__":
	app.run(host='127.0.0.1')
