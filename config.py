
class Config(object):
	DEBUG = False
	# Shodan API Key goes here
	SHODAN_API_KEY = ""
	GEOIP_FILE = './GeoLiteCity.dat'

class Production(Config):
	ENVIRONMENT = "Production"
	DEBUG = False

class Development(Config):
	ENVIRONMENT = "Development"
	DEBUG = True

class Testing(Config):
	ENVIRONMENT = "Testing"
	DEBUG = True
