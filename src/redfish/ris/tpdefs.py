###
# Copyright 2016 Hewlett Packard Enterprise, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

# -*- coding: utf-8 -*-
"""Typedefs implementation"""
#---------Imports---------
import logging

from redfish import redfish_client, rest_client
from redfish.rest.v1 import ServerDownOrUnreachableError
from redfish.ris.rmc_helper import UnableToObtainIloVersionError
#---------End of imports---------

LOGGER = logging.getLogger(__name__)

class Typesandpathdefines(object):
    """Global types and path definitions class"""
    def __init__(self):
        self.url = None
        self.defs = None
        self.ilogen = None
        self.iloversion = None
        self.flagiften = False
        self.adminpriv = True

    def getgen(self, gen=None, url=None, username=None, password=None, logger=None,\
                                                    proxy=None, isredfish=True):
        """Function designed to verify the servers platform

        :param url: The URL to perform the request on.
        :type url: str.
        :param logger: The logger handler.
        :type logger: str.

        """

        self.url = url
        self.is_redfish = isredfish
        self.gencompany = self.rootresp = False
        self.ilogen = 5 # If no iLO or Anonymous data , default to iLO 5 types
        logger = logger if not logger else LOGGER
        client = None
        self.noschemas = False
        self.schemapath = self.regpath = ''

        if not gen:
            getclient = lambda func: func(base_url=self.url, \
                                   username=username, password=password, \
                                   cache=False, proxy=proxy)
            try:
                client = getclient(redfish_client)
            except ServerDownOrUnreachableError as excp:
                if self.is_redfish:
                    raise excp
            if not self.is_redfish:
                try:
                    restclient = getclient(rest_client)
                    self.is_redfish = False
                    client = restclient
                except Exception as excep:
                    if not client:
                        logger.info("Gen get rest error:"+str(excep)+"\n")
                        raise excep
                    else:
                        self.is_redfish = True

            rootresp = client.root
            self.rootresp = rootresp
            client.logout()

            self.gencompany = next(iter(self.rootresp["Oem"].keys()), None) in ('Hpe', 'Hp')
            comp = 'Hp' if self.gencompany else None
            comp = 'Hpe' if rootresp["Oem"].get('Hpe', None) else comp
            if comp and rootresp["Oem"][comp]["Manager"][0].get('ManagerType', None):
                self.ilogen = rootresp["Oem"][comp]["Manager"][0]["ManagerType"]
                self.ilover = rootresp["Oem"][comp]["Manager"][0]["ManagerFirmwareVersion"]
                if self.ilogen.split(' ')[-1] == "CM":
                    # Assume iLO 4 types in Moonshot
                    self.ilogen = 4
                    self.iloversion = None
                else:
                    self.iloversion = float(self.ilogen.split(' ')[-1] + '.' + \
                                                    ''.join(self.ilover.split('.')))
        else:
            self.ilogen = int(gen)

        try:
            if not isinstance(self.ilogen, int):
                self.ilogen = int(self.ilogen.split(' ')[-1])
            self.flagiften = True if int(self.ilogen) >= 5 else False
        except:
            raise UnableToObtainIloVersionError("Unable to find the iLO generation.")

        self.noschemas = True if self.rootresp and "JsonSchemas" in self.rootresp and not \
                                        self.rootresp.get("JsonSchemas", None) else False
        if self.noschemas:
            self.ilogen = self.ilover = self.iloversion = None
        if self.rootresp and not self.noschemas:
            self.defineregschemapath(self.rootresp)

        if self.flagiften:
            self.defs = Definevalstenplus()
        else:
            self.defs = DefinevalsNine()

    def defineregschemapath(self, rootobj):
        """Define the schema and registry paths using data in root path
        :param rootobj: The root path data.
        :type rootobj: dict.

        """
        self.gencompany = next(iter(rootobj["Oem"].keys()), None) in ('Hpe', 'Hp')
        self.schemapath = rootobj["JsonSchemas"]["@odata.id"] if rootobj.\
            get("JsonSchemas", None) else rootobj["links"]["Schemas"]["href"]
        self.schemapath = self.schemapath.rstrip('/')+"/?$expand=." if \
                self.is_redfish and self.flagiften and self.gencompany else self.schemapath
        self.regpath = rootobj["Registries"]["@odata.id"] if rootobj.get\
            ("Registries", None) else rootobj["links"]["Registries"]["href"]
        self.regpath = self.regpath.rstrip('/')+"/?$expand=." if \
                self.is_redfish and self.flagiften and self.gencompany else self.regpath

class Definevals(object):
    """Class for setting platform dependent variables"""
    def __init__(self):
        pass

class Definevalstenplus(Definevals):
    """Platform dependent variables"""
    # pylint: disable=too-many-instance-attributes
    # As a defines class this will need all the attributes
    def __init__(self):
        self.oemhp = "Hpe"

        self.oempath = "/Oem/Hpe"
        self.startpath = "/redfish/v1/"
        self.systempath = "/redfish/v1/Systems/1/"
        self.managerpath = "/redfish/v1/Managers/1/"
        self.biospath = "/redfish/v1/systems/1/bios/"
        self.addlicensepath = "/redfish/v1/Managers/1/LicenseService/"
        self.accountspath = "/redfish/v1/AccountService/Accounts/"
        self.federationpath = "/redfish/v1/Managers/1/FederationGroups/"
        self.resourcedirpath = "/redfish/v1/ResourceDirectory/"

        self.biostype = "Bios."
        self.hpeskmtype = "HpeESKM."
        self.hpcommontype = "HpeCommon"
        self.hpilossotype = "HpeiLOSSO."
        self.hpsecureboot = "SecureBoot."
        self.logservicetype = "#LogService."
        self.iscsisource = "iSCSISources"
        self.iscsiattemptinstance = "iSCSIAttemptInstance"
        self.iscsiattemptname = "iSCSIAttemptName"
        self.hphttpscerttype = "HpeHttpsCert."
        self.snmpservice = "HpeiLOSnmpService."
        self.attributenametype = "AttributeName"
        self.hpilodatetimetype = "HpeiLODateTime."
        self.attributeregtype = "#AttributeRegistry."
        self.hpilofirmwareupdatetype = "UpdateService."
        self.resourcedirectorytype = "HpeiLOResourceDirectory."
        self.hpilofederationgrouptype = "HpeiLOFederationGroup."
        self.managernetworkservicetype = "ManagerNetworkProtocol."
        self.schemafilecollectiontype = "#JsonSchemaFileCollection."
        self.regfilecollectiontype = "#MessageRegistryFileCollection."
        self.hpilolicensecollectiontype = "HpeiLOLicenseCollection."
        self.hpiloactivehealthsystemtype = "#HpeiLOActiveHealthSystem."
        self.hpiscsisoftwareinitiatortype = "HpeiSCSISoftwareInitiator."
        self.hpilofederationgrouptypecoll = "HpeiLOFederationGroupCollection."
        self.bootoverridetargettype = "BootSourceOverrideTarget@Redfish.AllowableValues"
        self.messageregistrytype = "#MessageRegistry."

        self.typestring = "@odata.type"
        self.hrefstring = "@odata.id"
        self.collectionstring = "Members"
        self.biossettingsstring = "@Redfish.Settings"
        self.attname = "AttributeName"
        self.iscsistring = "iSCSISources"

        self.isgen9 = False
        self.isgen10 = True
        self.flagforrest = False
        super(Definevalstenplus, self).__init__()

    def redfishchange(self):
        """Function to update redfish variables"""
        pass


class DefinevalsNine(Definevals):
    """Platform dependent variables"""
    # pylint: disable=too-many-instance-attributes
    # As a defines classt this will need all the attributes
    def __init__(self):
        self.oemhp = "Hp"

        self.oempath = "/Oem/Hp"
        self.startpath = "/rest/v1"
        self.systempath = "/rest/v1/Systems/1"
        self.managerpath = "/rest/v1/Managers/1"
        self.biospath = "/rest/v1/systems/1/bios"
        self.addlicensepath = "/rest/v1/Managers/1/LicenseService"
        self.accountspath = "/rest/v1/AccountService/Accounts"
        self.federationpath = "/rest/v1/Managers/1/FederationGroups"
        self.resourcedirpath = "/rest/v1/ResourceDirectory"

        self.biostype = "HpBios."
        self.hpeskmtype = "HpESKM."
        self.hpcommontype = "HpCommon"
        self.hpilossotype = "HpiLOSSO."
        self.snmpservice = "SnmpService."
        self.attributenametype = "Name"
        self.logservicetype = "LogService."
        self.iscsisource = "iSCSIBootSources"
        self.iscsiattemptinstance = "iSCSIBootAttemptInstance"
        self.iscsiattemptname = "iSCSIBootAttemptName"
        self.hpsecureboot = "HpSecureBoot."
        self.hphttpscerttype = "HpHttpsCert."
        self.hpilodatetimetype = "HpiLODateTime."
        self.hpilofirmwareupdatetype = "HpiLOFirmwareUpdate."
        self.resourcedirectorytype = "HpiLOResourceDirectory."
        self.hpilofederationgrouptype = "HpiLOFederationGroup."
        self.attributeregtype = "HpBiosAttributeRegistrySchema."
        self.schemafilecollectiontype = "#SchemaFileCollection."
        self.regfilecollectiontype = "#SchemaFileCollection."
        self.managernetworkservicetype = "ManagerNetworkService."
        self.hpiloactivehealthsystemtype = "HpiLOActiveHealthSystem."
        self.messageregistrytype = "MessageRegistry."
        self.hpilolicensecollectiontype = None
        self.hpilofederationgrouptypecoll = None
        self.bootoverridetargettype = "BootSourceOverrideSupported"
        self.hpiscsisoftwareinitiatortype = "HpiSCSISoftwareInitiator"

        self.typestring = "Type"
        self.hrefstring = "href"
        self.collectionstring = "Items"
        self.biossettingsstring = "SettingsResult"
        self.attname = "Name"
        self.iscsistring = "iSCSIBootSources"

        self.isgen9 = True
        self.isgen10 = False
        self.flagforrest = True
        super(DefinevalsNine, self).__init__()

    def redfishchange(self):
        """Function to update redfish variables"""
        self.startpath = "/redfish/v1/"
        self.systempath = "/redfish/v1/Systems/1/"
        self.managerpath = "/redfish/v1/Managers/1/"
        self.biospath = "/redfish/v1/systems/1/bios/"
        self.addlicensepath = "/redfish/v1/Managers/1/LicenseService/"
        self.resourcedirpath = "/redfish/v1/ResourceDirectory/"

        self.typestring = "@odata.type"
        self.hrefstring = "@odata.id"
        self.collectionstring = "Members"

        self.logservicetype = "#LogService."
        self.hpiloactivehealthsystemtype = "#HpiLOActiveHealthSystem."
        self.hpilolicensecollectiontype = "HpiLOLicenseCollection."
        self.hpilofederationgrouptypecoll = "HpiLOFederationGroupCollection."
        self.managernetworkservicetype = "ManagerNetworkProtocol."

        self.flagforrest = False
