#!/bin/python3
import os, logging, sys, traceback, argparse

import yaml
import dns.resolver
from armorapi import ArmorApi

REGISTRY_FILE = 'registry.yml'
CONFIG_FILE = 'config.yml'
VALID_LOCATIONS = [ 'DFW01','LHR01','PHX01','SIN01','FRA01']
VALID_LOG_LEVELS = ['DEBUG','INFO','WARNING','ERROR','CRITICAL']
LOG_LEVEL = 'DEBUG'
LOG_FILE = 'domwall.log'
RULE_PREFIX = 'DOMWALL_'

# Logging levels can be set to:
# DEBUG
# INFO
# WARNING
# ERROR
# CRITICAL

config = {}
old_registry = {}
current_registry = {}
LOCATION_VCDORGVCDID = {}
VCDORGVCDID_LOCATION = {}

def configure_logging():
    """
    Configure logging, called directely after config is loaded
    """
    global logger

    log_level =  config['global_config'].get('log_level') or LOG_LEVEL
    log_file =  config['global_config'].get('log_file') or LOG_FILE

    logger = logging.getLogger()    
    fileHandler = logging.FileHandler(log_file)
    logFormatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
    fileHandler.setFormatter(logFormatter)
    logger.addHandler(fileHandler)
    logger.setLevel(log_level)

def load_config():
    """
    Load user config and backend saved data in the registry
    """
    global config
    global old_registry
    global RULE_PREFIX

    #Load config
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE) as config_file:
            config = yaml.safe_load(config_file)
            configure_logging()
            logger.debug('config loaded from file : %s' % CONFIG_FILE)
    else:
        logger.critical('config.yml does not exist or is not readable')
        sys.exit('config.yml does not exist or is not readable')

    #Open registry file
    if os.path.isfile(REGISTRY_FILE):
        with open(REGISTRY_FILE) as registry_file:
            old_registry = yaml.safe_load(registry_file)
            logger.debug('registry loaded from file : %s' % REGISTRY_FILE)
    else:
        logger.debug('registry not found, building registry from scratch')

    RULE_PREFIX = config['global_config'].get('prefix') or RULE_PREFIX

def set_creds(args):
    """
    Function to set creds from config if CLI cread are not passed
    """
    global username
    global password

    username = args.username
    password = args.password
    if not username:
        username = config['global_config'].get('username')
    if not password:
        password = config['global_config'].get('password')
    if not username or not password:
        logger.critical('username/password not provided')
        sys.exit('username/password not provided')

def get_vcdOrgVdcId():
    """
    create a dict of location names to vcdids for future lookup
    """
    global LOCATION_VCDORGVCDID
    global VCDORGVCDID_LOCATION

    firewalls = aa.make_request('https://api.armor.com/firewalls')
    for i in firewalls:
        #Skip recovery POD IDs
        if 'R' not in i['name']:
            LOCATION_VCDORGVCDID[i['location']] = i['vcdOrgVdcId']
            VCDORGVCDID_LOCATION[i['vcdOrgVdcId']] = i['location']

def sync_registry():
    """
    Sync config rules into registy, check for any domain changes or ip changes
    """
    global current_registry

    group_list = []
    for i in config['ip_groups']:
        #Validate location
        if i['location'] not in VALID_LOCATIONS:
            logger.critical('%s is not a valid firewall location, bailing' % i['location'])
            sys.exit('%s is not a valid firewall location' % i['location'])
       
        #Validate group name is unique (per location)
        registry_name = '%s_%s' % (i['group_name'], i['location'])
        if registry_name in group_list:
            logger.critical('already a group named %s for location %s. Group names must be uniq per location' % ( i['group_name'], i['location']))
            sys.exit('already a group named %s for location %s. Group names must be uniq per location' % (i['group_name'], i['location']))
        group_list.append(registry_name)

        #Perform logic if group already exists in registry
        if old_registry.get(registry_name):
            current_registry[registry_name] = old_registry.get(registry_name)
            current_registry[registry_name]['updated'] = 'false'

            #Check if domains have changed.
            if diff_lists(current_registry[registry_name].get('domain_names'),i['domain_names']):
                logger.debug('DOMAIN NAMES CHANGED FOR ITEM: %s \t NEW DOMAIN LIST: %s' % (current_registry[registry_name], i['domain_names']))
                current_registry[registry_name]['domain_names'] = i['domain_names']
            #Check if IPs have changed
            ips = return_ip_list(current_registry[registry_name]['domain_names'])
            if diff_lists(current_registry[registry_name].get('ips'),ips):
                logger.debug('IP ADDRESSES CHANGED FOR ITEM : %s \t NEW IP LIST : %s' % (current_registry[registry_name], ips))
                current_registry[registry_name]['ips'] = ips
                current_registry[registry_name]['updated'] = 'true'
            if current_registry[registry_name]['updated'] == 'false':
                logger.debug('NO IP ADDRESS CHANGES FOR ITEM : %s' % current_registry[registry_name])
        #Perform logic if is a new registry item
        else:
            ips = return_ip_list(i['domain_names'])
            current_registry[registry_name]= {'location' : i['location'], 'name' : i['group_name'], 'vcdOrgVcdId' : LOCATION_VCDORGVCDID.get(i['location']), 'domain_names' : i['domain_names'], 'ips' : ips, 'updated': 'true'}
            logger.debug('NEW REGISTRY ITEM CREATED : %s' %  current_registry[registry_name])

def api_updates():
    """
    iterates through new registry, creates and updates items via API
    """
    global current_registry

    for registry_name, group in current_registry.items():
        if not group.get('id'):
            #groups that don't have an ID are not created on the firewall yet, so create them
            group['id'] = create_group('%s%s' % (RULE_PREFIX, group['name']),group['ips'], group['domain_names'], group['vcdOrgVcdId'])
        elif group['updated'] == 'true':
             update_group('%s%s' % (RULE_PREFIX, group['name']),group['ips'], group['domain_names'], group['vcdOrgVcdId'], group['id'])
        else:
            logger.debug('Group not marked for update: %s' % group)

def return_ip_list(domains):
    """
    returns a list of IPs from a list of domains
    """
    #use a set to ensure addresses are not duplicated
    ips = set()
    resolver = dns.resolver.Resolver()
    for i in domains:
        try:
            results = resolver.query(i, 'A')
        except Exception as error:
            logger.critical(error)
            traceback.print_exc()
            sys.exit()
        for x in results:
            ips.add(str(x))
    logger.debug('resolved domains : %s . To IPs : %s ' % (domains, ips))
    return list(ips)

def diff_lists(list1, list2):
    """
    function compares lists and returns true if they are different 
    used to compared lists of domain names and lists of IP addresses to detect changes
    """
    list1.sort()
    list2.sort()
    if list1 == list2:
        return False
    else:
        return True


def write_registry():
    """
    write registry out to file on disk
    """
    logger.debug('writing registry to %s' % REGISTRY_FILE)
    with open(REGISTRY_FILE, 'w') as registry_file:
        yaml.dump(current_registry, registry_file)


def create_group(name, ips, domains, vcdOrgVdcId):
    """
    makes api call to create an IP group
    """
    data = { 'name' : name, 'description' : 'DOMWALL AUTOMATION FOR DOMAINS: %s' % domains, 'values' : ips }
    logger.debug('Creating the following IP group: %s' % data)
    group = aa.make_request('https://api.armor.com/firewall/%s/groups' % vcdOrgVdcId , method='post', data=data)
    logger.debug('Api returned the following data: %s' % group)
    return group.get('id')
 

def update_group(name, ips, domains, vcdOrgVdcId, groupId):
    """
    makes api call to update an IP group
    """
    data = { 'name' : name, 'description' : 'DOMWALL AUTOMATION FOR DOMAINS: %s' % domains, 'values' : ips }
    logger.debug('Updating the following IP group: %s' % data)
    group = aa.make_request('https://api.armor.com/firewall/%s/groups/%s' % (vcdOrgVdcId,groupId) , method='put', data=data)
    logger.debug('Api returned the following data: %s' % group)
    return group.get('id')



def get_groups():
    """
    NOT IN USE ---- Gets all firewall groups for FW
    """
    fwgroups = aa.make_request('https://api.armor.com/firewall/%s/groups' % vcdOrgVdcId)
    for i in fwgroups:
        if RULE_PREFIX in i['name']:
            print(i)



     

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', help='Armor API username, overrides config value')
    parser.add_argument('-p', '--password', help='Armor API password, overrides config value') 

    args = parser.parse_args()
   
    load_config()
    set_creds(args) 
    aa = ArmorApi(username,password)
    logger.info('Initial API authentication complete')
    get_vcdOrgVdcId()
    sync_registry()
    api_updates()
    write_registry()
