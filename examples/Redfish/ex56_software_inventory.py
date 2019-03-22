 # Copyright 2016 Hewlett Packard Enterprise Development, LP.
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

import sys
from _redfishobject import RedfishObject
from redfish.rest.v1 import ServerDownOrUnreachableError

def ex56_get_firmware_inventory(redfishobj):
    sys.stdout.write("\nEXAMPLE ##: Get Firmware Inventory\n")
    instances = redfishobj.search_for_type("UpdateService")
    #sys.stdout.write("\t" + str(instances) + "\n")
    for instance in instances:
        rsp = redfishobj.redfish_get(instance["@odata.id"])
        #sys.stdout.write("\n\n"+"\t" + str(rsp) + "\n")
        fwInventory = redfishobj.redfish_get(rsp.dict["FirmwareInventory"]["@odata.id"])
        #sys.stdout.write("\t" + str(fwInventory) + "\n")
        for entry in fwInventory.dict["Members"]:
            response = redfishobj.redfish_get(entry["@odata.id"])
            sys.stdout.write("\n\n\tId: " + str(response.dict["Id"]) + "\n")
            sys.stdout.write("\tName: " + str(response.dict["Name"]) + "\n")
            sys.stdout.write("\tVersion: " + str(response.dict["Version"]) + "\n")
            sys.stdout.write("\tDescription: " + str(response.dict["Description"]) + "\n")
            if "Status" in response.dict:
                sys.stdout.write("\tStatus: Health " + str(response.dict["Status"]["Health"]) + "\n")
                sys.stdout.write("\t        State " + str(response.dict["Status"]["State"]) + "\n")
            else:
                sys.stdout.write("\tHealth status and State information is not available on "\
                                    "your system for this device.\n")
            
            

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # iLO_https_url = "blobstore://."
    # iLO_account = "None"
    # iLO_password = "None"

    # When running remotely connect using the iLO secured (https://) address, 
    # iLO account name, and password to send https requests
    # iLO_https_url acceptable examples:
    # "https://10.0.0.100"
    # "https://ilo.hostname"
    iLO_https_url = "https://10.0.0.100"
    iLO_account = "admin"
    iLO_password = "password"
    
    # Create a REDFISH object
    try:
        REDFISH_OBJ = RedfishObject(iLO_https_url, iLO_account, iLO_password)
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or doesn't support " \
                                                                "RedFish.\n")
        sys.exit()
    except Exception as excp:
        raise excp

    ex56_get_firmware_inventory(REDFISH_OBJ)
    REDFISH_OBJ.redfish_client.logout()
