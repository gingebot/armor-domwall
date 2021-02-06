#!/bin/python3
import os
import sys
import traceback
import time
import logging

import requests
from bs4 import BeautifulSoup




class ArmorApi:
    """
    Rest API client for the Armor API, manages 0auth2 authentication.
    """    

    def __init__(self,username,password,accountid=None,retries401=4):
        self.username = username
        self.password = password
        self.accountid = accountid
        self.session = requests.session()
        self.retries401 = retries401
        self.count401 = self.retries401
        self.timer = time.time()

        self._v2_authentication()

    def _v2_authentication(self):
        self._set_bearer_request_url()
        self._bearer_authenticate()
        self._get_bearer_token()
        self._test_request_and_accountid()

    def _401_timer(self):
        """
        counter method that allows n executions every 10 mintes
        """
        time_now = time.time()
        if time_now - self.timer > 60:
            #reset timer and retires if more than 10 minutes has passed since last execution 
            self.timer = time_now
            self.count401 = self.retries401

        interval = time_now - self.timer
        self.count401 -= 1
        if self.count401 >= 0:
            return True
        else:
            return False

    def make_request(self,uri,method="get",data={},json=True):
        """
        Makes a request and returns response, catches exceptions 
        """
        try:
            if method == "get":
                response = self.session.get(uri,data=data)
            elif method == "post":
                response = self.session.post(uri,data=data)
            elif method == "put":
                response = self.session.put(uri,data=data)
            response.raise_for_status()
            if json == False:
                return response.text
            else:
                return response.json()

        except requests.exceptions.HTTPError as error:
            if response.status_code == 401 and self._401_timer():
                logging.warning(error)
                logging.warning('Attempting reauthentication')
                self._v2_authentication()
            else:    
                logging.critical(error)
                traceback.print_exc()
                sys.exit()
        except requests.exceptions.ConnectionError as error:
            logging.critical(error)
            traceback.print_exc()
            sys.exit()
        except requests.exceptions.RequestException as error:
            logging.critical(error)
            traceback.print_exc()
            sys.exit()

    def _set_bearer_request_url(self):
        """
        Sets the request url, including parameters for the bearer token request cycles
        """
        response_type = 'id_token'
        response_mode = 'form_post'
        client_id = 'b2264823-30a3-4706-bf48-4cf80dad76d3'
        redirect_uri = 'https://amp.armor.com/'
        client_request_id = 'f85529a0-7f20-4212-073c-0080000000a3'
        self.bearer_request_url = 'https://sts.armor.com/adfs/oauth2/authorize?response_type=%s&response_mode=%s&client_id=%s&redirect_uri=%s' % (response_type, response_mode, client_id, redirect_uri)
        
    def _bearer_authenticate(self):
        """
        Completes the initial username/password auth and retrieve context token required for the gest bearer ID request.
        """
        payload = { 'UserName' : self.username, 'Password' : self.password, 'AuthMethod' : 'FormsAuthentication' }
        sso_auth_response = self.make_request(self.bearer_request_url,"post",data=payload,json=False)
        soup = BeautifulSoup(sso_auth_response, 'html.parser')
        self.context_token = soup.find('input', {'id' : 'context'})['value']

    def _get_bearer_token(self):
        """
        Completes the final request in the bearer auth method, retrieves the bearer token and sets headers required headers for API requests
        """
        payload = { 'AuthMethod' : 'AzureMfaServerAuthentication', 'Context' : self.context_token }
        bearer_response = self.make_request(self.bearer_request_url,"post",data=payload,json=False)
        soup = BeautifulSoup(bearer_response, 'html.parser')
        bearer = soup.find('input')['value']
        self.session.headers.update({ 'Accept' : 'application/json', 'Authorization' : 'Bearer %s' % bearer})

    def _test_request_and_accountid(self):
        """
        performs an API request to confirm Authentication has worked, also sets the header for account ID, either as provide ID or First account ID from request
        """
        json_response = self.make_request('https://api.armor.com/me')
        
        accountid = json_response['accounts'][0]['id'] 
        if not self.accountid and accountid:
            self.session.headers.update({'X-Account-Context' : '%s' % accountid})
        elif self.accountid:
            self.session.headers.update({'X-Account-Context' : '%s' % self.accountid})

    def _simulate_fail(self):
        """
        For testing purpoases only, creates a 401 error
        """
        print(self.count401)
        self.session = requests.session()
        response = self.make_request('https://api.armor.com/me')
        print(response)

if __name__ == "__main__":
    
    username = os.environ.get('armor_username')
    password = os.environ.get('armor_password')
    #accountid = os.environ.get('armor_accountid')
    armorapi = ArmorApi(username,password)
