#!/bin/python3

import os
import logging
import sys
import traceback

import yaml
import dns.resolver
from armorapi import ArmorApi

username = os.environ.get('armor_username')
password = os.environ.get('armor_password')

#configure logging
#
# Logging levels can be set to:
# DEBUG
# INFO
# WARNING
# ERROR
# CRITICAL
#

logging.basicConfig(filename='domwall.log', 
level=logging.DEBUG, 
format='%(asctime)s | %(levelname)s | %(message)s')

REGISTRY_FILE = 'registry.yml'


def load_config():
    """
    Load user config and backend saved data in the registry
    """
    global config
    global old_registry
    old_registry = {}
    global current_registry
    current_registry = {}
    global RULE_PREFIX
    global VALID_LOCATIONS
    #Load config
    if os.path.isfile('config.yml'):
        with open('config.yml') as config_file:
            config = yaml.safe_load(config_file)
            logging.debug('config loaded')
    else:
        logging.critical('config.yml does not exist or is not readable')
        sys.exit('config.yml does not exist or is not readable')

    #Open registry file
    if os.path.isfile(REGISTRY_FILE):
        with open(REGISTRY_FILE) as registry_file:
            old_registry = yaml.safe_load(registry_file)
            logging.debug('registry loaded from file %s' % REGISTRY_FILE)
    else:
        logging.debug('registry not found, building registry from scratch')

    RULE_PREFIX = config['global_config'].get('prefix') or 'DOMWALL_'
    VALID_LOCATIONS = [ 'DFW01','LHR01','PHX01','SIN01','FRA01']

def get_vcdOrgVdcId():
    """
    create a dict of location names to vcdids for future lookup
    """
    global LOCATION_VCDORGVCDID
    global VCDORGVCDID_LOCATION
    LOCATION_VCDORGVCDID = {}
    VCDORGVCDID_LOCATION = {}

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
    group_list = []

    for i in config['ip_groups']:
        #Validate location
        if i['location'] not in VALID_LOCATIONS:
            logging.critical('%s is not a valid firewall location, bailing' % i['location'])
            sys.exit('%s is not a valid firewall location' % i['location'])
       
        #Validate group name is unique (per location)
        registry_name = '%s_%s' % (i['group_name'], i['location'])
        if registry_name in group_list:
            logging.critical('already a group named %s for location %s. Group names must be uniq per location' % ( i['group_name'], i['location']))
            sys.exit('already a group named %s for location %s. Group names must be uniq per location' % (i['group_name'], i['location']))
        group_list.append(registry_name)

        #Perform logic if group already exists in registry
        if old_registry.get(registry_name):
            current_registry[registry_name] = old_registry.get(registry_name)
            current_registry[registry_name]['updated'] = 'false'

            #Check if domains have changed.
            if diff_lists(current_registry[registry_name].get('domain_names'),i['domain_names']):
                current_registry[registry_name]['domain_names'] = i['domain_names']
                current_registry[registry_name]['updated'] = 'true'
                logging.debug('DOMAIN NAMES UPDATED FOR ITEM: %s' % current_registry[registry_name])
            #Check if IPs have changed
            ips = return_ip_list(current_registry[registry_name]['domain_names'])
            if diff_lists(current_registry[registry_name].get('ips'),ips):
                logging.debug('IP ADDRESSES CHANGED FOR ITEM : %s \t NEW IPS : %s' % (current_registry[registry_name], ips))
                current_registry[registry_name]['ips'] = ips
                current_registry[registry_name]['updated'] = 'true'
            if current_registry[registry_name]['updated'] == 'false':
                logging.debug('NO UPDATES FOR ITEM: %s' % current_registry[registry_name])
        #Perform logic if is a new registry item
        else:
            ips = return_ip_list(i['domain_names'])
            current_registry[registry_name]= {'location' : i['location'], 'name' : i['group_name'], 'vcdOrgVcdId' : LOCATION_VCDORGVCDID.get(i['location']), 'domain_names' : i['domain_names'], 'ips' : ips, 'updated': 'true'}
            logging.debug('REGISTRY ITEM CREATED : %s' %  current_registry[registry_name])

def api_updates():
    """
    iterates through new registry, creates and updates items via API
    """
    for registry_name, group in current_registry.items():
        if not group.get('id'):
            #groups that don't have an ID are not created on the firewall yet, so create them
            group['id'] = create_group('%s%s' % (RULE_PREFIX, group['name']),group['ips'], group['domain_names'], group['vcdOrgVcdId'])
        elif group['updated'] == 'true':
             update_group('%s%s' % (RULE_PREFIX, group['name']),group['ips'], group['domain_names'], group['vcdOrgVcdId'], group['id'])
        else:
            logging.debug('Group not marked for update: %s' % group)

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
            logging.critical(error)
            traceback.print_exc()
            sys.exit()
        for x in results:
            ips.add(str(x))
    logging.debug('resolved domains : %s . To IPs : %s ' % (domains, ips))
    return list(ips)

def diff_lists(list1, list2):
    """
    function compares lists and returns true if they are different
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
    logging.debug('writing registry to %s' % REGISTRY_FILE)
    with open(REGISTRY_FILE, 'w') as registry_file:
        yaml.dump(current_registry, registry_file)




def create_group(name, ips, domains, vcdOrgVdcId):
    """
    makes api call to create an IP group
    """

    data = { 'name' : name, 'description' : 'DOMWALL AUTOMATION FOR DOMAINS: %s' % domains, 'values' : ips }
    logging.debug('Creating the following IP group: %s' % data)
    group = aa.make_request('https://api.armor.com/firewall/%s/groups' % vcdOrgVdcId , method='post', data=data)
    logging.debug('Api returned the following data: %s' % group)
    return group.get('id')
 

def update_group(name, ips, domains, vcdOrgVdcId, groupId):
    """
    makes api call to update an IP group
    """

    data = { 'name' : name, 'description' : 'DOMWALL AUTOMATION FOR DOMAINS: %s' % domains, 'values' : ips }
    logging.debug('Updating the following IP group: %s' % data)
    group = aa.make_request('https://api.armor.com/firewall/%s/groups/%s' % (vcdOrgVdcId,groupId) , method='put', data=data)
    logging.debug('Api returned the following data: %s' % group)
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

    aa = ArmorApi(username,password)
    logging.info('Initial API authentication complete')
    load_config()
    get_vcdOrgVdcId()
    sync_registry()
    api_updates()
    write_registry()