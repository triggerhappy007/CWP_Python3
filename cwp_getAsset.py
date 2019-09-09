#Import Libraries
import json
from typing import List
import re
import requests
import configparser
import os
import logging
from pathlib import Path


# create logger
logger = logging.getLogger("Loggercwp")
logger.setLevel(logging.INFO)

# create console handler (ch) and set level to debug
ch = logging.StreamHandler()

# create formatter
formatter = logging.Formatter("%(asctime)s: %(levelname)s: %(message)s",
                              "%Y-%m-%d %H:%M:%S")
# add formatter to console handler
ch.setFormatter(formatter)

# add console handler to logger
logger.addHandler(ch)


logger.info("cwp_getAsset: Starting")

# Getting current working directory
Current_Working_Dir = os.getcwd()
#Display folder
logger.info("cwp_getAsset: Current working Directory is " + Current_Working_Dir)
logger.info("cwp_getAsset: Checking if config file present in current directory")

#Set config.ini
config_file = Path(Current_Working_Dir+'/config.ini')

# Checking if config file present
if not config_file.is_file():
    logger.error("cwp_getAsset: File config.ini not found in current working directory, "
                 "place config.ini fle in directory \n " + Current_Working_Dir)
    exit()
else :
    logger.info("cwp_getAsset: Configfile found in directory " + Current_Working_Dir)

# Setting variables from config.ini file
AUTHURL = 'AuthUrl'
CLIENT_ID = 'ClientId'
CLIENT_SECRET = 'ClientSecretKey'
CONFIG_CREDS_SECTION = 'Credentials'
CONFIG_URL_SECTION = 'RequestURL'
GET_EVENTS_URL = 'FetchAssetService'
BODYOPTIONS = 'Bodyoptions'
LIMIT = 'limit'
OFFSET = 'offset'
EXTERNAL_SECTION = 'External'
FILENAME_OUT = 'filename_asset'

# Creating http request and headers

auth_headers = {}
access_token: None
authurl: None
get_events_url: None
x_epmp_customer_id:  None
x_epmp_domain_id: None



#Reading Config.ini
logger.info("set_request_headers(): Parsing and reading values from config files")
config = configparser.ConfigParser()
config.read(config_file)


get_events_limit = config.get(BODYOPTIONS, LIMIT)
get_events_offset = config.get(BODYOPTIONS, OFFSET)

#define output data
get_filename_out = config.get(EXTERNAL_SECTION, FILENAME_OUT)


 
def output_to_file(event_output):
    fo=open(get_filename_out,"w+")
    fo.write(event_output)
    fo.close()

def get_authentication_token():
    token_cust_domain_id = False
    try:
        auth_request_json = json.dumps(set_request_headers.auth_request)
        logger.info("get_authentication_token(): Hitting http request to generate auth token")
        auth_response = requests.post(authurl, data=auth_request_json, headers=auth_headers)
        if auth_response.status_code == 200:
            logger.info("get_authentication_token(): auth token generated successfully, "
                        "http status code is " + str(auth_response.status_code))
            global access_token
            access_token = auth_response.json()['access_token']
            global x_epmp_customer_id
            x_epmp_customer_id = auth_response.json()['x-epmp-customer-id']
            global x_epmp_domain_id
            x_epmp_domain_id = auth_response.json()['x-epmp-domain-id']
            print("access_token :: " + access_token)
            print("customer_id :: " + x_epmp_customer_id)
            print("domain_id :: " + x_epmp_domain_id)
            token_cust_domain_id = True
        else:
            logger.error("get_authentication_token(): Response from http auth not received status code is " + str(auth_response.status_code))

    except Exception as ex:
        logger.error("get_authentication_token(): Exception occurred while hitting http request to generate token" + str(ex))
    return token_cust_domain_id

def set_request_headers():
    set_request_headers.auth_request = {}
    headers_got_set = False
    try:
        logger.info("set_request_headers(): Parsing and reading values from config files")
        config = configparser.ConfigParser()
        config.read(config_file)
        client_id = config.get(CONFIG_CREDS_SECTION, CLIENT_ID)
        client_secret = config.get(CONFIG_CREDS_SECTION, CLIENT_SECRET)
        global authurl
        authurl = config.get(CONFIG_URL_SECTION, AUTHURL)
        global get_events_url
        get_events_url = config.get(CONFIG_URL_SECTION, GET_EVENTS_URL)
        if client_id == "" or client_secret == "" or authurl == "" or get_events_url == "":
            logger.error("set_request_headers(): One or more values empty in config_file")
            return headers_got_set
        else:
            set_request_headers.auth_request['client_id'] = client_id
            set_request_headers.auth_request['client_secret'] = client_secret
            auth_headers['Content-type'] = 'application/json'
            headers_got_set = True

    except Exception as ex:
        logger.error("generateAuthToken: Exception occurred while reading values from config file " + str(ex))
    return headers_got_set

def get_events_details():
    global auth_headers
    get_events_details.get_events_request_body = {'limit': get_events_limit, 'offset': get_events_offset}
    auth_headers['Authorization'] = access_token
    auth_headers['x-epmp-customer-id'] = x_epmp_customer_id
    auth_headers['x-epmp-domain-id'] = x_epmp_domain_id
    
    print (get_events_details.get_events_request_body)

    try:
        logger.info("get_events_details(): Hitting http request get events details ")
        request_json = json.dumps(get_events_details.get_events_request_body)
        get_events_details_response = requests.post(get_events_url, data=request_json, headers=auth_headers)
        if get_events_details_response.status_code == 200:
            logger.info("get_events_details(): Get events successful status code "
                        + str(get_events_details_response.status_code))
            #print(get_events_details_response.text)
            output_to_file(get_events_details_response.text)
        else:
            logger.error("get_events_details(): Failed to get data for events, status code is " + str(get_events_details_response.status_code))
    except Exception as ex:
        logger.error("get_events_details(): Exception occurred while getting events details  " + str(ex))
    

if set_request_headers():
    if get_authentication_token():
        get_events_details()



#end
logger.info("Finished")