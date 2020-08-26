# Copyright 2020 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# -*- coding: utf-8 -*-
"""
An example of set syslog server on HPE iLO Server.
"""

import sys
import json
import redfish
from redfish.rest.v1 import ServerDownOrUnreachableError 

def set_syslog(_redfishobj, syslog_server):

    model_uri = "/redfish/v1/Systems/1/"
    model = _redfishobj.get(model_uri).obj['Model']
    if "Gen9" in model:
        hp = "Hp"
    else:
        hp = "Hpe"

    syslog_uri = "/redfish/v1/Managers/1/NetworkService/" 

    body = {"Oem": {hp: {"RemoteSyslogServer": syslog_server, "RemoteSyslogEnabled": True}}}
    resp = _redfishobj.patch(syslog_uri, body)
    ilo_response(_redfishobj, resp) 

def ilo_response(_redfishobj, resp):

    if resp.status == 400:
        try:
            print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4, \
                                                                         sort_keys=True))
        except Exception as excp:
            sys.stderr.write("A response error occurred, unable to access iLO Extended "\
                             "Message Info...")
    elif resp.status != 200:
        sys.stderr.write("An http response of \'%s\' was returned.\n" % resp.status)
    else:
        print("Success")

if __name__ == "__main__":

    SYSTEM_URL = "https://"+str(sys.argv[1])
    LOGIN_ACCOUNT = "XXXXXX"
    LOGIN_PASSWORD = "XXXXXX"
   
    try:
        # Create a Redfish client object
        REDFISHOBJ = redfish.RedfishClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, password=LOGIN_PASSWORD)
        # Login with the Redfish client
        REDFISHOBJ.login()
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or does not support RedFish.\n")
        sys.exit()

    set_syslog(REDFISHOBJ, SYSLOG_SERVER)
    REDFISHOBJ.logout()
