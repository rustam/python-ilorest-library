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
"""RMC implementation """

#---------Imports---------
import os
import re
import sys
import time
import copy
import shutil
import logging
import itertools

from collections import OrderedDict, Mapping

import six
import jsonpatch
import jsonpath_rw
import jsonpointer
import redfish.ris.tpdefs
import redfish.ris.validation

from redfish.ris.ris import SessionExpired
from redfish.ris.validation import ValidationManager, Typepathforval
from redfish.ris.rmc_helper import (UndefinedClientError, InstanceNotFoundError, \
                        CurrentlyLoggedInError, NothingSelectedError, IdTokenError, \
                        ValidationError, RmcClient, RmcConfig, RmcFileCacheManager, \
                         NothingSelectedSetError, LoadSkipSettingError, ValueChangedError, \
                         IloResponseError, UserNotAdminError, EmptyRaiseForEAFP, IncorrectPropValue)

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class RmcApp(object):
    """Application level implementation of RMC"""
    def __init__(self, Args=[]):
        """Initialize RmcApp

        :param Args: arguments to be passed to RmcApp
        :type Args: str

        """
        configfile = None
        self.logger = LOGGER
        self._rmc_clients = None

        foundsomething = False
        for item in Args:
            if foundsomething:
                configfile = item
                break

            if item == "-c":
                foundsomething = True
            elif item.startswith("--config="):
                configfile = item.split("=", 1)[1]
                break
            elif item == "--config":
                foundsomething = True

        # use the default config file
        if configfile is None:
            if os.name == 'nt':
                configfile = os.path.join(os.path.dirname(sys.executable), \
                                                                 'redfish.conf')
            else:
                configfile = '/etc/ilorest/redfish.conf'

        if not os.path.isfile(configfile):
            self.warn("Config file '%s' not found\n\n" % configfile)

        self._config = RmcConfig()
        self.config_file = configfile
        self._cm = RmcFileCacheManager(self)
        self._monolith = None
        self._iloversion = None
        self._validationmanager = None

        if "--showwarnings" not in Args:
            self.logger.setLevel(logging.WARNING)
            if self.logger.handlers and self.logger.handlers[0].name == 'lerr':
                self.logger.handlers.remove(self.logger.handlers[0])

        self.typepath = redfish.ris.tpdefs.Typesandpathdefines()
        Typepathforval(typepathobj=self.typepath)

    def restore(self):
        """Restore monolith from cache"""
        self._cm.uncache_rmc()

    def deletelogoutfunction(self, url=None):
        """Wrapper function for logout helper function

        :param url: The URL to perform a logout request on.
        :type url: str.

        """
        return self._cm.logout_del_function(url)

    def set_encode_funct(self, funct):
        """ set the encoding function for cache to use
        :param funct: The function to use for encoding data
        :type funct: function.
        """
        self._cm.encodefunct = funct

    def set_decode_funct(self, funct):
        """ set the decoding function for cache to use
        :param funct: The function to use for decoding data
        :type funct: function.
        """
        self._cm.decodefunct = funct

    def save(self):
        """Cache current monolith build"""
        self._cm.cache_rmc()

    def out(self):
        """Helper function for runtime error"""
        raise RuntimeError("You must override this method in your derived" \
                                                                    " class")

    def err(self, msg, inner_except=None):
        """Helper function for runtime error

        :param msg: The error message.
        :type msg: str.
        :param inner_except: The internal exception.
        :type inner_except: str.

        """
        LOGGER.error(msg)
        if inner_except is not None:
            LOGGER.error(inner_except)

    def warning_handler(self, msg):
        """Helper function for handling warning messages appropriately

        :param msg: The warning message.
        :type msg: str.

        """
        if LOGGER.getEffectiveLevel() == 40:
            sys.stderr.write(msg)
        else:
            LOGGER.warning(msg)

    def warn(self, msg, inner_except=None):
        """Helper function for runtime warning

        :param msg: The warning message.
        :type msg: str.
        :param inner_except: The internal exception.
        :type inner_except: str.

        """
        LOGGER.warning(msg)
        if inner_except is not None:
            LOGGER.warning(inner_except)

    def get_config(self):
        """Return config"""
        return self._config

    config = property(get_config, None)

    def get_cache(self):
        """Return config"""
        return self._config

    cache = property(get_cache, None)

    def config_from_file(self, filename):
        """Get config from file

        :param filename: The config file name.
        :type filename: str.

        """
        self._config = RmcConfig(filename=filename)
        self._config.load()

    def remove_rmc_client(self):
        """Remove RMC client

        """
        self._rmc_clients = None

    def checkandupdate_rmc_client(self, url=None, username=None, proxy=None,
                                  password=None, biospassword=None, \
                                  is_redfish=False):
        """Return if RMC client already exists, do update to passed client

        :param url: The URL for the check and update request.
        :type url: str.
        :param username: user name required to login to server.
        :type: str.
        :param password: password credentials required to login.
        :type password: str.
        :param biospassword: BIOS password for the server if set.
        :type biospassword: str.
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type is_redfish: boolean.
        """
        if self._rmc_clients and url == self._rmc_clients.get_base_url():
            if username:
                self._rmc_clients.set_username(username)
            if password:
                self._rmc_clients.set_password(password)
            if biospassword:
                self._rmc_clients.set_biospassword(biospassword)
            return self._rmc_clients
        if self._rmc_clients and not url == self._rmc_clients.get_base_url():
            raise CurrentlyLoggedInError("Currently logged into another " \
                                         "server. \nPlease log out out first " \
                                         "before logging in to another.")
        self._rmc_clients = RmcClient(username=username, \
                    password=password, url=url, typepath=self.typepath, \
                    biospassword=biospassword, is_redfish=is_redfish, \
                    proxy=proxy)

    def get_current_client(self):
        """Get the current client"""
        if self._rmc_clients:
            return self._rmc_clients
        raise UndefinedClientError()
    current_client = property(get_current_client, None)

    def login(self, username=None, password=None, base_url='blobstore://.', \
              verbose=False, path=None, skipbuild=False, includelogs=False, \
              biospassword=None, is_redfish=False, proxy=None):
        """Main worker function for login command

        :param username: user name required to login to server.
        :type: str.
        :param password: password credentials required to login.
        :type password: str.
        :param base_url: redfish host name or ip address.
        :type base_url: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param path: path to initiate login to.
        :type path: str.
        :param skipbuild: flag to determine whether to start monolith download.
        :type skipbuild: boolean.
        :param includelogs: flag to determine id logs should be downloaded.
        :type includelogs: boolean.
        :param biospassword: BIOS password for the server if set.
        :type biospassword: str.
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type is_redfish: boolean.

        """
        self.getgen(url=base_url, username=username, password=password, \
                                                proxy=proxy, isredfish=is_redfish)
        is_redfish = self.updatedefinesflag(redfishflag=is_redfish)

        self.checkandupdate_rmc_client(url=base_url, username=username, \
                           password=password, biospassword=biospassword, \
                                       is_redfish=is_redfish, proxy=proxy)

        self.current_client.login()
        if not skipbuild:
            self.build_monolith(verbose=verbose, path=path, \
                                                        includelogs=includelogs)
            self.save()
        else:
            self.current_client.monolith.update_member(resp=self.\
                current_client._rest_client.root_resp, path=self.typepath.defs.startpath, \
                init=False)

    def build_monolith(self, verbose=False, path=None, includelogs=False):
        """Run through the RIS tree to build monolith

        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param path: path to initiate login to.
        :type path: str.
        :param includelogs: flag to determine id logs should be downloaded.
        :type includelogs: boolean.

        """
        monolith = self.current_client.monolith
        inittime = time.time()
        monolith.load(path=path, includelogs=includelogs, init=True)
        monolith.populatecollections()
        endtime = time.time()

        if verbose:
            sys.stdout.write("Monolith build process time: %s\n" % \
                                                        (endtime - inittime))

    def logout(self, url=None):
        """Main function for logout command

        :param url: the URL for the logout request.
        :type url: str.

        """
        sessionlocs = []
        self._validationmanager = None
        self._iloversion = None

        try:
            self.current_client.logout()
        except Exception:
            sessionlocs = self.deletelogoutfunction(url)
        else:
            self.deletelogoutfunction(url)

        for session in sessionlocs:
            try:
                self.delete_handler(session[0], url=session[1], \
                            sessionid=session[2], silent=True, service=True)
            except:
                pass
        self.remove_rmc_client()
        self.save()

        cachedir = self.config.get_cachedir()
        if cachedir:
            try:
                shutil.rmtree(cachedir)
            except Exception:
                pass

    @property
    def monolith(self):
        """Get the monolith from the current client"""
        return self.current_client.monolith
    @monolith.setter
    def monolith(self, monolith):
        """Set the monolith"""
        self.current_client.monolith = monolith

    @property
    def validationmanager(self):
        """Get the valdation manager"""
        iloversion = self.getiloversion()
        return self.get_validation_manager(iloversion) if iloversion else None

    def getprops(self, selector=None, props=[], nocontent=None, \
                            skipnonsetting=True, remread=False, insts=None):
        """Special main function for get in save command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param skipnonsetting: flag to remove non settings path.
        :type skipnonsetting: boolean.
        :param nocontent: props not found are added to this list.
        :type nocontent: list.
        :param remread: flag to remove readonly properties.
        :type remread: boolean.
        :param props: provide the required property within current selection.
        :type props: list.
        :param insts: instances to be searched for specific props
        :type insts: list
        :returns: returns a list from the get command

        """
        results = list()
        nocontent = set() if nocontent is None else nocontent
        noprop = {prop:False for prop in props}
        instances = insts if insts else self.getinstances(selector=selector)
        instances = self.skipnonsettingsinst(instances) if skipnonsetting else instances

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            currdict = instance.dict
            for patch in instance.patches:
                currdict = jsonpatch.apply_patch(currdict, patch)
            _ = self.removereadonlyprops(currdict, emptyraise=True) if remread else None
            temp_dict = dict()
            if props:
                if isinstance(props, six.string_types):
                    props = [props]
                for prop in props:
                    copydict = copy.deepcopy(currdict)
                    propsdict = self.navigatejson(prop.split('/'), copydict)
                    if propsdict is None:
                        continue
                    noprop[prop] = True
                    self.merge_dict(temp_dict, propsdict)
                if temp_dict:
                    results.append(temp_dict)
            else:
                results.append(currdict)
        _ = [nocontent.add(prop) for prop in props if not noprop[prop]]
        return results

    def removereadonlyprops(self, currdict, emptyraise=False, \
                            removeunique=True, specify_props=None):
        """Remove readonly properties from dictionary

        :param currdict: dictionary to be filtered
        :type currdict: dictionary
        :param emptyraise: Raise empty error
        :type emptyraise: boolean
        :type removeunique: flag to remove unique values
        :type removeunique: boolean
        :parm specify_props: modify list of properties to be removed
        :type specify_props: list

        """
        try:
            type_str = self.current_client.monolith._typestring
            currtype = currdict.get(type_str, None)
            oridict = copy.deepcopy(currdict)
            if specify_props:
                templist = specify_props
            else:
                templist = ["Modified", "Type", "Description", "Status",\
                            "links", "SettingsResult", "Attributes", \
                            "@odata.context", "@odata.type", "@odata.id",\
                            "@odata.etag", "Links", "Actions", \
                            "AvailableActions", "BiosVersion"]
            #Attributes removed and readded later as a validation workaround
            currdict = self.iterateandclear(currdict, templist)
            iloversion = self.getiloversion()
            if not iloversion:
                return currdict
            _ = self.get_validation_manager(iloversion)
            self.validationmanager.validatedict(currdict, currtype=currtype, \
                   monolith=self.monolith, unique=removeunique, searchtype=None)
            if oridict.get("Attributes", None):
                currdict["Attributes"] = oridict["Attributes"]
            return currdict
        except:
            if emptyraise is True:
                raise EmptyRaiseForEAFP()
            elif emptyraise == 'pass':
                pass
            else:
                raise

    def iterateandclear(self, dictbody, proplist):
        """Iterate over a dictionary and remove listed properties

        :param dictbody: json body
        :type dictbody: dictionary or list
        :param proplist: property list
        :type proplist: list
        """
        if isinstance(dictbody, dict):
            _ = [dictbody.pop(key) for key in proplist if key in dictbody]
            for key in dictbody:
                dictbody[key] = self.iterateandclear(dictbody[key], proplist)
        if isinstance(dictbody, list):
            for ind, val in enumerate(dictbody):
                dictbody[ind] = self.iterateandclear(val, proplist)
        return dictbody

    def getinstances(self, selector=None, rel=False, crawl=False):
        """Main function to get instances of particular type and reload

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param setenable: flag to determine if registry should also be returned.
        :type setenable: boolean.
        :param setenable: flag to determine if registry should also be returned.
        :type setenable: boolean.
        :param rel: flag to reload the selected instances.
        :type rel: boolean.
        :returns: returns a list of selected items

        """
        monolith = self.monolith
        instances = list()
        selector = self.current_client.selector if not selector else selector
        if selector:
            selector = ".".join(selector.split('#')[-1].split(".")[:2])
            self.updatemono(currtype=selector, crawl=crawl, rel=rel)
        if not selector:
            return instances
        selector = None if selector == '"*"' else selector
        instances = [inst for inst in monolith.iter(selector) \
                            if inst.maj_type not in ['object', 'string']]
        _ = [setattr(inst, 'patches', []) for inst in instances if rel]
        return instances

    def skipnonsettingsinst(self, instances):
        """helper function for save helper to remove non /settings section

        :param instances: current retrieved instances.
        :type instances: dict.
        :returns: returns instances

        """
        instpaths = [inst.path.lower() for inst in instances]
        cond = list(itertools.ifilter(lambda x: x.endswith(("/settings", \
                                                    "settings/")), instpaths))
        paths = [path.split('settings/')[0].split('/settings')[0] \
                                                    for path in cond]
        newinst = [inst for inst in instances if inst.path.lower() not in paths]
        return newinst

    def getattributeregistry(self, instances, adict=None):
        #add try except return {} after test
        """Get attriute registry in given instances

        :param instances: list of instances to be checked for attribute.
        :type instances: list.
        :return: return dictionary
        """
        if adict:
            return adict.get("AttributeRegistry", None)
        return {inst.maj_type:inst.resp.obj["AttributeRegistry"]\
                for inst in instances if 'AttributeRegistry' in inst.resp.dict}

    def select(self, selector=None, fltrvals=(None, None), rel=False):
        """Function for set/filter with select and reload

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param fltsvals: the filter values of selection for the select operation (Key,Val).
        :type fltrvals: tuple.
        :param rel: flag to reload the selected instances.
        :type rel: boolean.
        :returns: returns a list of selected items
        """
        if selector:
            selector = self.modifyselectorforgen(selector)
            instances = self.getinstances(selector=selector, rel=rel)
            val = fltrvals[1].strip('\'\"') if isinstance(fltrvals[1], \
                                            six.string_types) else fltrvals[1]
            instances = [inst for inst in instances if not fltrvals[0] or self.\
                        navigatejson(fltrvals[0].split('/'), copy.deepcopy(inst.dict), val)]
            if any(instances):
                self.current_client.selector = selector
                self.save()
                return instances

        errmsg = "Unable to locate instance for '{0}' and filter '{1}={2}'". \
                    format(selector, fltrvals[0], fltrvals[1]) if fltrvals[0] \
                    and fltrvals[1] else "Unable to locate instance for {}".format(selector)

        raise InstanceNotFoundError(errmsg)

    def modifyselectorforgen(self, sel):
        """Changes the query to match the Generation's HP string.

        :param sel: query to be changed to match Generation's HP string
        :type sel: str
        :returns: returns a modified sel matching the Generation's HP string.

        """
        sel = sel.lower()
        returnval = sel

        if sel.startswith(("hpeeskm", "#hpeeskm", "hpeskm", "#hpeskm")):
            returnval = self.typepath.defs.hpeskmtype
        elif 'bios.' in sel[:9].lower():
            returnval = self.typepath.defs.biostype
        elif sel.startswith(("hpe", "#hpe")) and self.typepath.defs.isgen9:
            returnval = sel[:4].replace("hpe", "hp")+sel[4:]
        elif not sel.startswith(("hpe", "#hpe")) and self.typepath.defs.isgen10:
            returnval = sel[:3].replace("hp", "hpe")+sel[3:]

        return returnval

    def navigatejson(self, selector, currdict, val=None):
        """Function for navigating the json dictinary

        :param selector: the property required from current dictionary.
        :type selector: list.
        :param val: value to be filtered by.
        :type val: str or int or bool.
        :param currdict: json dictionary of list to be filtered
        :type currdict: json dictionary/list.
        :returns: returns a dictionary of selected items
        """
        #TODO: Check for val of different types(bool, int, etc)
        temp_dict = dict()
        createdict = lambda y, x: {x:y}
        getkey = lambda cdict, sel: next((item for item in six.iterkeys(cdict) \
                                          if sel.lower() == item.lower()), sel)
        getval = lambda cdict, sele: [cdict[sel] if sel in \
                                cdict else '~!@#$%^&*)()' for sel in [getkey(cdict, sele)]][0]
        fullbreak = False
        seldict = copy.deepcopy(currdict)
        for ind, sel in enumerate(selector):
            if isinstance(seldict, dict):
                selector[ind] = getkey(seldict, sel)
                seldict = getval(seldict, sel)
                if seldict == '~!@#$%^&*)()':
                    return None
                if val and ind == len(selector)-1:
                    cval = ",".join(seldict) if isinstance(seldict, (list, tuple)) else seldict
                    if not ((val[-1] == '*' and str(cval).lower().startswith(val[:-1].lower())) or \
                                                            str(cval).lower() == val.lower()):
                        fullbreak = True
            elif isinstance(seldict, (list, tuple)):
                returndict = []
                for items in seldict:
                    correctcase = selector[ind:]
                    returnseldict = self.navigatejson(correctcase, items)
                    selector[ind:] = correctcase
                    if returnseldict is not None:
                        returndict.append(returnseldict)
                if returndict:
                    seldict = returndict
                else:
                    fullbreak = True
                if seldict:
                    seldict = {selector[ind-1]:seldict}
                    selsdict = reduce(createdict, [seldict]+selector[:ind-1][::-1])
                    self.merge_dict(temp_dict, selsdict)
                    return temp_dict
                else:
                    break
            else:
                fullbreak = True
                break
        if fullbreak:
            return None
        else:
            selsdict = reduce(createdict, [seldict]+selector[::-1])
            self.merge_dict(temp_dict, selsdict)
        return temp_dict

    def info(self, selector=None, ignorelist=None, dumpjson=False, latestschema=False):
        """Main function for info command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param ignorelist: list that contains keys to be removed from output.
        :type ignorelist: list.
        :param dumpjson: flag to determine if output should be printed out.
        :type dumpjson: boolean.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :returns: returns a list of keys from current dict that are not ignored

        """
        model = None
        outdata = ''
        nokey = False
        results = set()
        typestring = self.typepath.defs.typestring
        iloversion = self.getiloversion()
        if not iloversion:
            return results
        _ = self.get_validation_manager(iloversion)
        instances = self.getinstances()
        attributeregistry = self.getattributeregistry(instances)
        instances = self.skipnonsettingsinst(instances)

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for inst in instances:
            bsmodel = None
            currdict = inst.resp.dict
            proppath = inst.resp.getheader('Link').split(';')[0].strip('<>') \
                    if inst.resp.getheader('Link') else None
            seldict = {}
            if not selector:
                currdict = currdict['Attributes'] if inst.maj_type.\
                    startswith(self.typepath.defs.biostype) and currdict.get('Attributes'\
                                                     , None) else currdict
                results.update([key for key in currdict if key not in \
                                ignorelist and not '@odata' in key.lower()])
                continue
            if isinstance(selector, six.string_types):
                selector = selector.split('/') if '/' in selector else selector
                selector = [selector] if not isinstance(selector, (list, tuple)) else selector
                seldict = self.navigatejson(selector, copy.deepcopy(currdict))
                if seldict is None:
                    nokey = True
                    continue
            if self.current_client.monolith._typestring in currdict:
                seldict[typestring] = currdict[typestring]
                model, bsmodel = self.get_model(currdict, \
                                  attributeregistry, latestschema, newarg= \
                                  selector[:-1], proppath=proppath)
            if not model and not bsmodel:
                errmsg = "/".join(selector)
                self.warning_handler("Unable to locate registry model or "\
                    "No data available for entry: {}\n".format(errmsg))
                continue
            found = model.get_validator(selector[-1]) if model else None
            found = bsmodel.get_validator(selector[-1]) if not found and bsmodel else found
            outdata = found if found and dumpjson else found.print_help(selector[-1]) \
                                                                            if found else outdata

        if outdata or results:
            return outdata if outdata else results

        errmsg = "Entry {} not found in current selection\n".format("/".\
            join(selector)) if nokey else "Entry {} not found in current"\
            " selection\n".format("/".join(selector))
        self.warning_handler(errmsg)

    def validate_headers(self, instance, verbose=False):
        """Module to check read-only property before patching.

        :param instance: instace of the property to check
        :type instance: Rest response object.
        :param verbose: enable to print more operations
        :type verbose: bool
        """

        skip = False
        try:
            headervals = instance.resp.getheaders()
            for kii, val in headervals.items():
                if kii.lower() == 'allow':
                    if not "PATCH" in val:
                        if verbose:
                            self.warning_handler('Skipping read-only path: %s\n' % \
                                                 instance.resp.request.path)
                        skip = True
        except:
            pass
        return skip

    def loadset(self, seldict=None, fltrvals=(None, None), latestschema=False, \
                                                                            uniqueoverride=False):
        """Validate and patch multiple properties

        :param seldict: current selection dictionary with required changes.
        :type seldict: dict.
        :param fltsvals: the filter values of selection for the set operation
                        (Key,Val).
        :type fltrvals: tuple.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :param uniqueoverride: flag to determine override for unique properties.
        :type uniqueoverride: str.
        :returns: returns a status or a list of set properties

        """
        results = list()
        nochangesmade = False
        settingskipped = [False]

        instances = self.select(selector=self.get_selector(), fltrvals=fltrvals)
        attributeregistry = self.getattributeregistry(instances=instances)
        instances = self.skipnonsettingsinst(instances=instances)

        if not instances or len(instances) == 0:
            raise NothingSelectedSetError()

        for instance in instances:
            if self.validate_headers(instance):
                continue
            else:
                nochangesmade = True

            currdict = instance.resp.dict
            diffdict = self.diffdict(newdict=copy.deepcopy(seldict),\
                 oridict=copy.deepcopy(currdict), settingskipped=settingskipped)

            iloversion = self.getiloversion()
            if iloversion:
                proppath = instance.resp.getheader('Link').split(';')[0].\
                            strip('<>') if instance.resp.getheader('Link') \
                            else None
                validation_manager = self.get_validation_manager(iloversion)
                self.validatechanges(validation_manager=validation_manager, \
                        instance=instance, attributeregistry=attributeregistry,\
                        newdict=diffdict, oridict=currdict, \
                        unique=uniqueoverride, latestschema=latestschema, \
                        proppath=proppath)

            patches = jsonpatch.make_patch(currdict, diffdict)

            if patches:
                torem = []
                _ = [torem.append(patch) for patch in patches.patch if patch["op"] == "remove"]
                _ = [patches.patch.remove(patch) for patch in torem]

            for ind, item in enumerate(instance.patches):
                ppath = item.patch[0]["path"] if hasattr(item, "patch") else item[0]["path"]
                jpath = jsonpointer.JsonPointer(ppath.lower())
                jval = jpath.resolve(seldict, default='kasjdk?!')
                if not jval == 'kasjdk?!':
                    del instance.patches[ind]

            if patches:
                for patch in patches.patch:
                    forprint = patch["value"] if "value" in patch\
                                    else (patch["op"] + " " + patch["from"])
                    results.append({patch["path"][1:]:forprint})
                instance.patches.append(patches)
            else:
                nochangesmade = True

        if not nochangesmade:
            return results
        elif settingskipped[0] is True:
            raise LoadSkipSettingError()
        else:
            return results

    def diffdict(self, newdict=None, oridict=None, settingskipped=[False]):
        """Diff's two dicts, returning the value differences

        :param newdict: selection dictionary with required changes.
        :type newdict: dict.
        :param oridict: selection dictionary with current state.
        :type oridict: dict.
        :param settingskipped: flag to determine if any settings was missing
        :type settingskipped: list.
        :returns: dictionary with only the properties that have changed.

        """
        try:
            if newdict == oridict:
                return {}
        except:
            try:
                if set(newdict) == set(oridict):
                    return {}
            except:
                pass

        newdictkeys = list(newdict.keys())
        oridictkeys = list(oridict.keys())
        newdictkeyslower = [ki.lower() for ki in newdictkeys]
        oridictkeyslower = [ki.lower() for ki in list(oridict.keys())]
        missingkeys = list(set(newdictkeyslower)-set(oridictkeyslower))
        for kis in missingkeys:
            del newdict[newdictkeys[newdictkeyslower.index(kis)]]
            self.warning_handler("Skipping property {0}, not " \
                             "found in current server.\n".format(kis))
            settingskipped = [True]
        for key, val in list(newdict.items()):
            if key not in oridict:
                keycase = oridictkeys[oridictkeyslower.index(key.lower())]
                del newdict[key]
                key = keycase
                newdict[key] = val
            if isinstance(val, dict):
                res = self.diffdict(newdict[key], oridict[key])
                if res:
                    newdict[key] = res
                else:
                    del newdict[key]
            elif isinstance(val, list):
                if len(val) == 1 and isinstance(val[0], dict):
                    res = self.diffdict(newdict[key][0], oridict[key][0], settingskipped)
                    if res:
                        newdict[key][0] = res
                    else:
                        del newdict[key]
                if [li for li in val if not isinstance(li, six.string_types)]:
                    continue
                else:
                    if [va.lower() for va in val] == [va.lower() if va else va \
                                                      for va in oridict[key]]:
                        del newdict[key]
            #TODO: check if lowercase is correct or buggy for string types
            elif isinstance(val, (six.string_types, int, type(None))):
                if newdict[key] == oridict[key]:
                    del newdict[key]

        return newdict

    def validatechanges(self, validation_manager=None, instance=None, \
            attributeregistry=None, latestschema=None, proppath=None, \
                                newdict=None, oridict=None, unique=False):
        """Validate the changes that are requested by the user.

        :param newdict: dictionary with only the properties that have changed
        :type newdict: dict.
        :param oridict: selection dictionary with current state.
        :type oridict: dict.
        :param unique: flag to determine override for unique properties.
        :type unique: str.
        :param iloversion: current iLO version.
        :type iloversion: float.
        :param instance: current selection instance.
        :type instance: RisMonolithMemberv100.
        :param validation_manager: validation manager object.
        :type validation_manager: validation object.
        :param attrreg: Registry entry of the given attribute.
        :type attrreg: RepoRegistryEntry.

        """
        entrymono = self.current_client.monolith
        currtype = oridict[entrymono._typestring]

        validation_manager.validatedict(newdict, \
            currtype=attributeregistry[instance.maj_type]\
            if attributeregistry else currtype, monolith=entrymono, \
            unique=unique, searchtype=self.typepath.defs.attributeregtype\
            if attributeregistry else None, latestschema=latestschema, \
            proppath=proppath)

        validation_errors = validation_manager.get_errors()
        for warninngs in validation_manager.get_warnings():
            self.warning_handler(warninngs)
        if validation_errors and len(validation_errors) > 0:
            raise ValidationError(validation_errors)
        self.checkallowablevalues(newdict=newdict, oridict=oridict)

    def checkallowablevalues(self, newdict=None, oridict=None):
        """Validate the changes with allowable values overwritten from schema

        :param newdict: dictionary with only the properties that have changed
        :type newdict: dict.
        :param oridict: selection dictionary with current state.
        :type oridict: dict.

        """
        for strmatch in re.finditer('@Redfish.AllowableValues', str(oridict)):
            propname = str(oridict)[:strmatch.start()].split("'")[-1]
            strtomatch = "$..'{0}@Redfish.AllowableValues'".format(propname)
            jsonpath_expr = jsonpath_rw.parse(strtomatch)
            matches = jsonpath_expr.find(oridict)
            if matches:
                for match in matches:
                    fullpath = str(match.full_path)
                    if 'Actions' in fullpath:
                        continue
                    checkpath = fullpath.split('@Redfish.AllowableValues')[0]
                    jexpr2 = jsonpath_rw.parse(checkpath)
                    valmatches = jexpr2.find(newdict)
                    if valmatches:
                        for mat in valmatches:
                            res = [val for val in match.value \
                                   if mat.value.lower() == val.lower()]
                            if not res:
                                raise IncorrectPropValue("Incorrect Value "\
                                    "entered. Please enter one of the below "\
                                    "values for {0}:\n{1}".format \
                                    ('/'.join(checkpath.split('.')), \
                                     str(match.value)[1:-1]))

    def getcollectionmembers(self, path, fullresp=False):
        """Returns collection/item lists of the provided path
        :param path: path to return.
        :type path: string.
        :param fullresp: Return full json data instead of only members.
        :type path: bool.
        :returns: returns collection list
        """
        if self.typepath.defs.isgen10 and self.typepath.gencompany \
                                            and '?$expand=.' not in path:
            path += '?$expand=.' if path.endswith('/') else '/?$expand=.'

        members = self.get_handler(path, service=True, silent=True)
        if members and not fullresp:
            try:
                members = members.dict['Members'] if self.typepath.defs.\
                                                                isgen10 else members.dict['Items']
            except KeyError:
                members = []
        elif fullresp:
            members = [members.dict]

        return members

    def getbiosfamilyandversion(self):
        """Function that returns the current BIOS family"""
        monolith = self.current_client.monolith
        self.updatemono(currtype="ComputerSystem.")

        try:
            for inst in monolith.iter("ComputerSystem."):
                if "Current" in inst.resp.obj["Bios"]:
                    oemjson = inst.resp.obj["Bios"]["Current"]
                    parts = oemjson["VersionString"].split(" ")
                    return (parts[0], parts[1][1:])
                else:
                    parts = inst.resp.obj["BiosVersion"].split(" ")
                    return (parts[0], parts[1][1:])
        except Exception:
            pass

        return (None, None)

    def getiloversion(self, skipschemas=False):
        """Function that returns the current iLO version

        :param skipschemas: flag to determine whether to skip schema download.
        :type skipschemas: boolean.
        :returns: returns current iLO version

        """

        iloversion = self._iloversion = self._iloversion if self._iloversion \
                                        else self.typepath.iloversion

        if self.typepath.gencompany and not self._iloversion and not self.typepath.noschemas:
            self.monolith.load(self.typepath.defs.managerpath, crawl=False)
            results = next(iter(self.getprops('Manager.', ['FirmwareVersion', \
                                                           'Firmware'])))

            def quickdrill(_dict, key):
                """ function to find key in nested dictionary """
                return _dict[key]

            model = self.getprops('Manager.', ['Model'])
            if model:
                if next(iter(model))['Model'] == "iLO CM":
                    # Assume iLO 4 types in Moonshot
                    iloversion = None
            else:
                while isinstance(results, dict):
                    results = quickdrill(results, next(iter(results.keys())))
                iloversionlist = results.replace('v', '').replace('.', '').split(' ')
                iloversion = float('.'.join(iloversionlist[1:3]))

            self._iloversion = iloversion
        elif not self.typepath.gencompany:#Assume schemas are available somewhere in non-hpe redfish
            self._iloversion = iloversion = 4.210

        conf = None if not skipschemas else True
        if not skipschemas:
            if iloversion and iloversion >= 4.210:
                conf = self.verifyschemasdownloaded(self.current_client.monolith)
            elif iloversion and iloversion < 4.210:
                self.warning_handler("Please upgrade to iLO 4 "\
                                    "version 2.1 or above for schema support.")
            else:
                self.warning_handler("Schema support unavailable "\
                                        "on the currently logged in system.")

        return iloversion if iloversion and iloversion >= 4.210 and conf else None

    def status(self):
        """Main function for status command"""
        iloversion = self.getiloversion()
        _ = self.get_validation_manager(iloversion)

        finalresults = list()
        monolith = self.current_client.monolith
        (_, _) = self.get_selection(setenable=True)
        attrreg = self.getattributeregistry([ele for ele in monolith.iter() if ele])
        for instance in monolith.iter():
            results = list()

            if not(instance.patches and len(instance.patches) > 0):
                continue
            for item in instance.patches:
                if isinstance(item, list):
                    results.extend(jsonpatch.JsonPatch(item))
                else:
                    results.extend(item)

            currdict = instance.resp.dict
            itemholder = list()
            for mainitem in results:
                item = copy.deepcopy(mainitem)

                if iloversion:
                    _, bsmodel = self.get_model(currdict, attrreg)
                    if bsmodel:
                        prop = item["path"][1:].split('/')[-1]
                        validator = bsmodel.get_validator(prop)
                        if validator:
                            if isinstance(validator, redfish.ris.\
                                      validation.PasswordValidator):
                                item["value"] = "******"

                itemholder.append(item)
            if itemholder:
                finalresults.append({instance.maj_type+'('+instance.path+')': itemholder})

        return finalresults

    def capture(self, redmono=False):
        """Build and return the entire monolith"""
        self.monolith.load(includelogs=True, crawl=True, loadcomplete=True, \
                           reload=True, init=True)
        return self.monolith.to_dict() if not redmono else \
            {x:{"Headers":v.resp.getheaders(), "Response":v.resp.dict}\
                 for x, v in list(self.monolith.paths.items()) if v}

    def commit(self, verbose=False):
        """Main function for commit command

        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :yields: Two strings: 1. Path being PATCHed 2. Result of the PATCH
                True:Success, False:Fail

        """

        instances = [inst for inst in self.monolith.iter() if inst.patches]

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if self.validate_headers(instance, verbose=verbose):
                continue

            currdict = dict()
            oridict = instance.resp.dict
            totpayload = dict()
            # apply patches to represent current edits
            for patches in instance.patches:
                if self._iloversion < 5.130:
                    self.checkforetagchange(instance=instance)
                fulldict = jsonpatch.apply_patch(oridict, patches)
                for patch in patches:
                    currdict = copy.deepcopy(fulldict)
                    patchpath = patch["path"]
                    pobj = jsonpointer.JsonPointer(patchpath)
                    indpayloadcount = 0
                    for item in pobj.parts:
                        payload = pobj.walk(currdict, item)
                        indpayloadcount = indpayloadcount+1
                        if isinstance(payload, list):
                            break
                        else:
                            if not isinstance(payload, dict):
                                break
                            currdict = copy.deepcopy(payload)
                    indices = pobj.parts[:indpayloadcount]
                    createdict = lambda x, y: {x:y}
                    while len(indices):
                        payload = createdict(indices.pop(), payload)
                    self.merge_dict(totpayload, payload)
                currdict = copy.deepcopy(totpayload)

            if currdict:
                yield instance.resp.request.path

                put_path = instance.resp.request.path
                etag = self.monolith.paths[put_path].etag
                headers = dict([('If-Match', etag)]) if self._iloversion\
                                                            > 5.130 else None
                try:
                    self.patch_handler(put_path, currdict, optionalpassword=\
                            self.current_client.get_biospassword(), headers=headers)
                except IloResponseError:
                    yield True #Failure
                else:
                    yield False #Success

    def merge_dict(self, currdict, newdict):
        """Helper function to merge dictionaries

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param currdict: new selection dictionary.
        :type currdict: dict.

        """
        for k, itemv2 in list(newdict.items()):
            itemv1 = currdict.get(k)

            if isinstance(itemv1, Mapping) and\
                 isinstance(itemv2, Mapping):
                self.merge_dict(itemv1, itemv2)
            else:
                currdict[k] = itemv2

    def get_errmsg_type(self, results):
        """Return the registry type of a response
        :param resuts: rest response.
        :type results: RestResponse.
        :returns: returns a Registry Id type string, None if not match is found, or no_id if the
                  response is not an error message
        """

        message_type = None
        try:
            jsonpath_expr = jsonpath_rw.parse('$..MessageId')
            messageid = [match.value for match \
                         in jsonpath_expr.find(results.dict)]
            if not messageid:
                jsonpath_expr = jsonpath_rw.parse('$..MessageID')
                messageid = [match.value for match \
                             in jsonpath_expr.find(results.dict)]
            if messageid:
                message_type = messageid[0].split('.')[0]
            else:
                message_type = 'no_id'
        except:
            pass

        return message_type

    def get_error_messages(self, regtype=None):
        """Handler of error messages from iLO

        :param regtype: registry type to add to list.
        :type regtype: str.

        :returns: returns a list of error messages
        """

        LOGGER.info("Entering validation...")
        errmessages = {}
        reglist = []
        iloversion = self.getiloversion()
        if not iloversion or regtype == 'no_id':
            return errmessages

        validation_manager = self.get_validation_manager(iloversion)

        if not validation_manager._classes:
            return None
        for reg in validation_manager.iterregmems():
            if regtype:
                if reg and 'Id' in reg and reg['Id'] == regtype:
                    try:
                        reglist.append(reg['Registry'])
                    except KeyError:
                        reglist.append(reg['Schema'])
                    break
                else:
                    continue

            regval = [reg.get(arg, None) for arg in ['Registry', 'Schema', 'Id']]
            regval = next((val for val in regval if val and \
                                    'biosattributeregistry' not in val), None)
            if not regval and reg:
                reg = reg['@odata.id'].split('/')
                reg = reg[len(reg)-2]
                if not 'biosattributeregistry' in reg.lower():
                    reglist.append(reg)
            elif regval:
                reglist.append(regval)

        for reg in reglist:
            reg = reg.replace("%23", "#")
            messages = validation_manager.get_registry_model(\
                                    getmsg=True, currtype=reg, \
                                    searchtype=self.typepath.defs.\
                                    messageregistrytype)
            if messages:
                errmessages.update(messages)

        return errmessages

    def invalid_return_handler(self, results, verbose=False, errmessages=None):
        """Main worker function for handling all error messages

        :param results: dict of the results.
        :type results: sict.
        :param errmessages: dict of lists containing the systems error messages.
        :type errmessages: dict.
        :param verbose: flag to enable additional verbosity.
        :type verbose: boolean.

        """
        output = ''
        try:
            contents = results.dict["Messages"][0]["MessageID"].split('.')
        except Exception:
            try:
                contents = results.dict["error"]["@Message.ExtendedInfo"][0]\
                                                        ["MessageId"].split('.')
            except Exception:
                if results.status == 200 or results.status == 201:
                    if verbose:
                        self.warning_handler("[%d] The operation completed " \
                                            "successfully.\n" % results.status)
                    else:
                        self.warning_handler("[%d] The operation completed " \
                                            "successfully.\n" % results.status)
                elif results.status == 412:
                    self.warning_handler("The property you are trying to " \
                                         "change has been updated. Please " \
                                         "check entry again before " \
                                         "manipulating it.\n")
                    raise ValueChangedError("")
                elif results.status == 403:
                    raise IdTokenError()
                else:
                    self.warning_handler("[%d] No message returned by iLO.\n" %\
                                                                results.status)

                    raise IloResponseError("")
                return

        if results.status == 401 and not contents[-1].lower() == 'insufficientprivilege':
            raise SessionExpired()
        elif results.status == 403:
            raise IdTokenError()
        elif results.status == 412:
            self.warning_handler("The property you are trying to change " \
                                 "has been updated. Please check entry again " \
                                 " before manipulating it.\n")
            raise ValueChangedError()
        elif errmessages:
            for messagetype in list(errmessages.keys()):
                if contents[0] == messagetype:
                    try:
                        if errmessages[messagetype][contents[-1]]["NumberOfArgs"] == 0:
                            output = errmessages[messagetype][contents[-1]]["Message"]
                        else:
                            output = errmessages[messagetype][contents[-1]]["Description"]

                        if verbose:
                            self.warning_handler("[%d] %s\n" % (results.status, output))
                        if results.status == 200 or results.status == 201:
                            self.warning_handler("{0}\n".format(output))
                        if not results.status == 200 and not results.status == 201:
                            self.warning_handler("iLO response with code [%d]:"\
                                                 " %s\n" % (results.status, output))
                            raise IloResponseError("")
                        break

                    except IloResponseError as excp:
                        raise excp
                    except Exception:
                        pass
            if not output:
                if results.status == 200 or results.status == 201:
                    self.warning_handler("[%d] The operation completed " \
                                            "successfully.\n" % results.status)
                else:
                    self.warning_handler("[{0}] iLO error response: {1}\n".\
                                         format(results.status, contents))
                    raise IloResponseError("")
        else:
            if results.status == 200 or results.status == 201:
                if verbose:
                    self.warning_handler("[%d] The operation completed " \
                                            "successfully.\n" % results.status)
                else:
                    self.warning_handler("The operation completed successfully.\n")
            elif contents:
                self.warning_handler("iLO response with code [{0}]: {1}\n".\
                                     format(results.status, contents))
                raise IloResponseError("")
            else:
                self.warning_handler("[%d] No message returned.\n" % results.status)

    def patch_handler(self, put_path, body, verbose=False, url=None, \
                  sessionid=None, headers=None, response=False, silent=False, \
                  optionalpassword=None, providerheader=None, service=False,\
                  username=None, password=None, proxy=None, is_redfish=False):
        """Main worker function for raw patch command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :param optionalpassword: provide password for authentication.
        :type optionalpassword: str.
        :param provideheader: provider id for the header.
        :type providerheader: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns RestResponse object containing response data
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type is_redfish: boolean.

        """
        errmessages = None

        if sessionid:
            if url is None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url, username=username, password=password, \
                                                    proxy=proxy, isredfish=is_redfish)

        (put_path, body) = self.checkpostpatch(body=body, path=put_path, \
                    service=False, url=None, sessionid=None, \
                    headers=None, iloresponse=False, silent=True, patch=True)

        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                self.updatedefinesflag(), typepath=self.typepath, \
                                    username=username, \
                                    password=password, proxy=proxy).\
                                    set(put_path, body=body, headers=headers, \
                                           optionalpassword=optionalpassword, \
                                           providerheader=providerheader)
            service = True
        else:
            results = self.current_client.set(put_path, body=body, \
                        headers=headers, optionalpassword=optionalpassword, \
                        providerheader=providerheader)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()

        self.modifiedpath(results, replace=True)

        if not silent and not service and results.read:
            errmsgtype = self.get_errmsg_type(results)
            errmessages = self.get_error_messages(regtype=errmsgtype)

        if results and hasattr(results, "status") and results.status == 412:
            self.updatemono(path=put_path, rel=True)
        if not silent:
            self.invalid_return_handler(results, verbose=verbose, \
                                        errmessages=errmessages)

        if response:
            return results

    def get_handler(self, put_path, silent=False, verbose=False, url=None, \
                                sessionid=None, uncache=False, headers=None, \
                                response=False, service=False, username=None, \
                                password=None, proxy=None, is_redfish=False):
        """main worker function for raw get command

        :param put_path: the URL path.
        :type put_path: str.
        :param silent: flag to determine if no output should be done.
        :type silent: boolean.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param uncache: flag to not store the data downloaded into cache.
        :type uncache: boolean.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse object from client's get command
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type is_redfish: boolean.

        """
        errmessages = None

        if sessionid:
            if url is None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url, username=username, password=password, \
                                                    proxy=proxy, isredfish=is_redfish)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                self.updatedefinesflag(), proxy=proxy, typepath=self.typepath, \
                                        username=username, password=password).\
                                                get(put_path, headers=headers)
            service = True
        else:
            results = self.current_client.get(put_path, headers=headers)

        if not uncache and results.status == 200:
            self.current_client.monolith.update_member(resp=results, path=\
                                                       put_path, init=False)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()
        if not silent and not service and results.read:
            if not results.status == 200:
                errmsgtype = self.get_errmsg_type(results)
                errmessages = self.get_error_messages(regtype=errmsgtype)

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, \
                                                        errmessages=errmessages)

        if results.status == 200 or response:
            return results

        return None

    def post_handler(self, put_path, body, verbose=False, url=None, \
                             sessionid=None, headers=None, response=False, \
                             silent=False, providerheader=None, service=False, \
                             username=None, password=None, proxy=None, is_redfish=False):
        """Main worker function for raw post command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :param provideheader: provider id for the header.
        :type providerheader: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse from client's Post command
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type is_redfish: boolean.

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url, username=username, password=password, \
                                                    proxy=proxy, isredfish=is_redfish)

        (put_path, body) = self.checkpostpatch(body=body, path=put_path, \
                    service=False, url=None, sessionid=None,\
                    headers=None, iloresponse=False, silent=True)

        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                self.updatedefinesflag(), username=username, proxy=proxy, \
                 password=password, typepath=self.typepath).toolpost(put_path, \
                                     body=body, headers=headers, \
                                     providerheader=providerheader)
            service = True
        else:
            results = self.current_client.toolpost(put_path, body=body, \
                    headers=headers, providerheader=providerheader)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()
        self.modifiedpath(results)

        if not silent and not service and results.read:
            errmsgtype = self.get_errmsg_type(results)
            errmessages = self.get_error_messages(regtype=errmsgtype)

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, \
                                        errmessages=errmessages)

        if response:
            return results

    def put_handler(self, put_path, body, verbose=False, url=None, \
                sessionid=None, headers=None, response=False, silent=False, \
                optionalpassword=None, providerheader=None, service=False, \
                username=None, password=None, proxy=None, is_redfish=False):
        """Main worker function for raw put command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :param optionalpassword: provide password for authentication.
        :type optionalpassword: str.
        :param provideheader: provider id for the header.
        :type providerheader: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse object from client's Put command
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type is_redfish: boolean.

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url, username=username, password=password, \
                                                    proxy=proxy, isredfish=is_redfish)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                self.updatedefinesflag(), username=username, typepath=self.typepath,\
                            password=password, proxy=proxy).toolput(put_path, \
                                                    body=body, headers=headers, \
                                       optionalpassword=optionalpassword, \
                                       providerheader=providerheader)
            service = True
        else:
            results = self.current_client.toolput(put_path, body=body, \
                          headers=headers, optionalpassword=optionalpassword, \
                          providerheader=providerheader)
        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()
        self.modifiedpath(results, replace=True)

        if not silent and not service and results.read:
            errmsgtype = self.get_errmsg_type(results)
            errmessages = self.get_error_messages(regtype=errmsgtype)

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, \
                                        errmessages=errmessages)

        if response:
            return results

    def delete_handler(self, put_path, verbose=False, url=None, \
                                    sessionid=None, headers=None, silent=False,\
                                    providerheader=None, service=False, is_redfish=False, \
                                    username=None, password=None, proxy=None):
        """Main worker function for raw delete command

        :param put_path: the URL path.
        :type put_path: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param silent: flag to disable output.
        :type silent: boolean.
        :param provideheader: provider id for the header.
        :type providerheader: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse object from client's Delete command
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type is_redfish: boolean.

        """
        errmessages = None

        if sessionid:
            if url is None:
                url = 'blobstore://'
            if not self.typepath.defs:
                rflag = None
                self.getgen(url=url, username=username, password=password, \
                                                    proxy=proxy, isredfish=is_redfish)
                rflag = self.updatedefinesflag(redfishflag=rflag)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                self.updatedefinesflag(), proxy=proxy, typepath=self.typepath,\
                                        username=username, password=password).\
                                        tooldelete(put_path, headers=headers, \
                                                   providerheader=providerheader)
            service = True
        else:
            results = self.current_client.tooldelete(put_path, \
                                 headers=headers, providerheader=providerheader)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()
        self.modifiedpath(results, delete=True)

        if not silent and not service and results.read:
            errmsgtype = self.get_errmsg_type(results)
            errmessages = self.get_error_messages(regtype=errmsgtype)

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, \
                                        errmessages=errmessages)

        return results

    def head_handler(self, put_path, verbose=False, url=None, sessionid=None, \
                                    silent=False, service=False, is_redfish=False, \
                                    username=None, password=None, proxy=None):
        """Main worker function for raw head command

        :param put_path: the URL path.
        :type put_path: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse object from client's Head command
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type is_redfish: boolean.

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url, username=username, password=password, \
                                                    proxy=proxy, isredfish=is_redfish)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                self.updatedefinesflag(), proxy=proxy, typepath=self.typepath, \
                                        username=username, password=password).\
                                                                head(put_path)
            service = True
        else:
            results = self.current_client.head(put_path)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()
        if not silent and not service and results.read:
            errmsgtype = self.get_errmsg_type(results)
            errmessages = self.get_error_messages(regtype=errmsgtype)

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, \
                                        errmessages=errmessages)
        if results.status == 200:
            return results
        else:
            return None

    def filter_output(self, output, sel, val):
        """Filters a list of dictionaries based on a key:value pair

        :param output: output list.
        :type output: list.
        :param sel: the key for the property to be filtered by.
        :type sel: str.
        :param val: value for the property be filtered by.
        :type val: str.
        :returns: returns an filtered list from output parameter

        """
        newoutput = []
        if isinstance(output, list):
            for entry in output:
                if isinstance(entry, dict):
                    if '/' in sel:
                        sellist = sel.split('/')
                        newentry = copy.copy(entry)

                        for item in sellist:
                            if item in list(newentry.keys()):
                                if item == sellist[-1] and str(newentry[item])\
                                                                    == str(val):
                                    newoutput.append(entry)
                                else:
                                    newentry = newentry[item]
                    else:
                        if sel in list(entry.keys()) and entry[sel] == val:
                            newoutput.append(entry)
                else:
                    return output

        return newoutput

    def types(self, fulltypes=False):
        """Main function for types command

        :param fulltypes: flag to determine if types return full name.
        :type fulltypes: boolean.
        :returns: returns a list of type strings

        """
        instances = list()
        monolith = self.current_client.monolith
        rdirtype = next(monolith.gettypename(self.typepath.defs.\
                                             resourcedirectorytype), None)

        if not rdirtype:
            for inst in monolith.iter():
                if not any([x for x in ['ExtendedError', 'object', 'string']\
                                             if x in inst.type]):
                    instances.append(inst.type)
        else:
            for instance in monolith.iter(rdirtype):
                for item in instance.resp.dict["Instances"]:
                    if item and instance._typestring in list(item.keys()) and \
                        not 'ExtendedError' in item[instance._typestring]:
                        if not fulltypes and instance._typestring == '@odata.type':
                            tval = item["@odata.type"].split('#')
                            tval = tval[-1].split('.')[:-1]
                            tval = '.'.join(tval)
                            instances.append(tval)
                        elif item:
                            instances.append(item[instance._typestring])
        return instances

    def gettypeswithetag(self):
        """Supporting function for set and commit command"""
        instancepath = dict()
        instances = dict()
        monolith = self.current_client.monolith

        for inst in monolith.iter():
            instancepath[inst.path] = inst.maj_type
            instances[inst.path] = inst.etag

        return [instances, instancepath]

    def reloadmonolith(self, path=None):
        """Helper function to reload new data into monolith

        :param path: path to initiate reload monolith from.
        :type path: str.
        :returns: returns True/False depending on if reload occurred

        """
        if path:
            self.current_client.monolith.load(path=path, init=False, \
                                                crawl=False, reload=True)
            return True
        return False

    def checkforetagchange(self, instance=None):
        """Function to check the status of the etag

        :param instance: retrieved instance to check etag for change.
        :type instance: dict.

        """
        if instance:
            path = instance.path
            (oldtag, _) = self.gettypeswithetag()
            self.updatemono(path=path, rel=True)
            (newtag, _) = self.gettypeswithetag()
            if (oldtag[path] != newtag[path]) and \
                        not self.typepath.defs.hpilodatetimetype in instance.maj_type:
                self.warning_handler("The property you are trying to change " \
                                 "has been updated. Please check entry again " \
                                 " before manipulating it.\n")
                raise ValueChangedError()

    def getidbytype(self, tpe):
        """ Return a list of URIs that correspond to the supplied type string
        :param tpe: type string to search for.
        :type tpe: string.
        """
        urls = list()
        val = next(self.monolith.gettypename(tpe), None)
        urls.extend(self.monolith.typesadded[val] if val else [])
        return urls

    def removeinstance(self, path=None, mono=None):
        """ Remove instance from monolith by path

        :param path: path to the instance to remove.
        :type path: string.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        """
        for inst in mono.iter():
            if path == inst.path:
                mono.typesadded[inst.maj_type].remove(path)
        del mono.paths[path]

    def verifyschemasdownloaded(self, monolith):
        """Function to verify that the schema has been downloaded

        :param monolith: full data model retrieved from server.
        :type monolith: dict.

        """

        schemaid = self.typepath.schemapath
        regid = self.typepath.regpath

        if not (schemaid and regid):
            self.warning_handler("Missing Schemas or registries.")
            raise

        schemacoll = next(monolith.gettypename(\
                        self.typepath.defs.schemafilecollectiontype), None)
        if not schemacoll or any(paths.lower() == schemaid and \
                                 monolith.paths[paths] \
               for paths in monolith.typesadded[schemacoll]):
            self.download_path([schemaid], monolith, crawl=False)
            schemacoll = next(monolith.gettypename(\
                        self.typepath.defs.schemafilecollectiontype), None)

        regcoll = next(monolith.gettypename(\
                        self.typepath.defs.regfilecollectiontype), None)
        if not regcoll or any(paths.lower() == regid and monolith.paths[paths] \
               for paths in monolith.typesadded[regcoll]):
            self.download_path([regid], monolith, crawl=False)
            regcoll = next(monolith.gettypename(\
                        self.typepath.defs.regfilecollectiontype), None)

        return any(paths.lower() in (schemaid.lower(), regid.lower()) and \
            monolith.paths[paths] for paths in monolith.paths)

    def download_path(self, paths, monolith, crawl=True, reload=False, loadtype='href'):
        """Check if type exists in current monolith

        :param paths: list of paths to download
        :type paths: list
        :param reload: flag to indicate if reload or not.
        :type reload: bool.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param crawl: flag to determine if load should traverse found links.
        :type crawl: boolean.

        """
        if not paths:
            return
        try:
            map(lambda x: monolith.load(path=x, init=False, reload=reload,\
                  crawl=crawl, includelogs=True, loadtype=loadtype), paths)
        except Exception as excp:
            try:
                if excp.errno == 10053:
                    raise SessionExpired()
            except:
                raise excp
            else:
                raise excp

    def updatemono(self, monolith=None, currtype=None, path=None, crawl=False, \
                                            loadtype='href', rel=False):
        """Check if type exists in current monolith

        :param entrytype: the found entry type.
        :type entrytype: str.
        :param currtype: the current entry type.
        :type currtype: str.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param crawl: flag to determine if load should traverse found links.
        :type crawl: boolean.

        """
        monolith = self.monolith if not monolith else monolith
        currtype = None if currtype == '"*"' else currtype
        paths = set()
        if currtype:
            for path, resp in monolith.paths.items():
                if currtype and currtype.lower() not in resp.maj_type.lower():
                    continue
                if rel or not resp:
                    paths.add(path)
                if resp.modified:
                    paths.add(path)
                    paths.update(monolith.checkmodified(path) if path in \
                                                    monolith.ctree else set())
        elif path:
            if monolith.paths and not monolith.paths.keys()[0][-1] == '/':
                path = path[:-1] if path[-1] == '/' else path
            if rel or not monolith.path(path):
                paths.add(path)
            if path in monolith.paths and monolith.paths[path].modified:
                paths.add(path)
                paths.update(monolith.checkmodified(path) if path in \
                                                    monolith.ctree else set())
        if paths:
            self.checkforchange(list(paths), crawl=crawl, loadtype=\
                                                                loadtype)

    def get_selection(self, selector=None, setenable=False, reloadpath=False):
        """Special main function for set/filter with select command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param sel: property(s) to be filtered by.
        :type sel: str.
        :param val: value to be filtered by.
        :type val: str.
        :param setenable: flag to determine if registry should also be returned.
        :type setenable: boolean.
        :param reloadpath: flag to reload the selected instances.
        :type reloadpath: boolean.
        :returns: returns a list of selected items

        """
        instances = self.getinstances(selector=selector, rel=reloadpath)
        if setenable:
            attributeregistryfound = \
                            self.getattributeregistry(instances=instances)
            instances = self.skipnonsettingsinst(instances=instances)
            return instances, attributeregistryfound
        return instances

    def create_save_header(self, selector=None, selectignore=False):
        """Adds save file headers to show what server the data came from

        :param selector: the type selection for the get save operation.
        :type selector: str.
        :param selectignore: ignore selection
        :type selectignore: boolean
        :returns: returns an header ordered dictionary

        """
        instances = OrderedDict()
        monolith = self.current_client.monolith
        selector = self.current_client.selector if not selector else selector
        if not selector and not selectignore:
            return instances

        self.updatemono(currtype="ComputerSystem.", crawl=False)
        self.updatemono(currtype=self.typepath.defs.biostype, crawl=False)
        self.updatemono(currtype="Manager.", crawl=False)

        instances["Comments"] = OrderedDict()
        try:
            for instance in monolith.iter("ComputerSystem."):
                if instance.resp.obj["Manufacturer"]:
                    instances["Comments"]["Manufacturer"] = \
                                instance.resp.obj["Manufacturer"]

                if instance.resp.obj["Model"]:
                    instances["Comments"]["Model"] = instance.resp.obj["Model"]

                if instance.resp.obj["Oem"][self.typepath.defs.oemhp]["Bios"]["Current"]:
                    oemjson = instance.resp.obj["Oem"][self.typepath.defs.oemhp]["Bios"]["Current"]
                    instances["Comments"]["BIOSFamily"] = oemjson["Family"]
                    instances["Comments"]["BIOSDate"] = oemjson["Date"]
            for instance in monolith.iter(self.typepath.defs.biostype):
                if "Attributes" in list(instance.resp.obj.keys()) and \
                    instance.resp.obj["Attributes"]["SerialNumber"]:
                    instances["Comments"]["SerialNumber"] = \
                                                    instance.resp.obj["Attributes"]["SerialNumber"]
                elif instance.resp.obj["SerialNumber"]:
                    instances["Comments"]["SerialNumber"] = instance.resp.obj["SerialNumber"]
            for instance in monolith.iter("Manager."):
                if instance.resp.obj["FirmwareVersion"]:
                    instances["Comments"]["iLOVersion"] = instance.resp.obj["FirmwareVersion"]
        except Exception:
            pass
        return instances

    def get_selector(self):
        """Helper function to return current select option"""
        if self.current_client:
            if self.current_client.selector:
                return self.current_client.selector
        return None

    def update_bios_password(self, value):
        """Helper function to set bios password

        :param value: value to be set as the new BIOS password.
        :type value: str.

        """
        if self.current_client:
            self.current_client.set_biospassword(value)

    def get_validation_manager(self, iloversion):
        """Get validation manager helper

        :param iloversion: current systems iLO versions.
        :type iloversion: str.
        :returns: returns a ValidationManager

        """
        if self._validationmanager:
            self._validationmanager._errors = list()
            self._validationmanager._warnings = list()
        else:
            monolith = self.current_client.monolith
            self._validationmanager = ValidationManager(monolith, \
                                                        defines=self.typepath)
        self._validationmanager.updatevalidationdata()
        return self._validationmanager

    def get_model(self, currdict, attributeregistry, latestschema=None, \
                  newarg=None, proppath=None):
        """Returns the model for the current instance's schema/registry

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param attributeregistry: current systems attribute registry.
        :type attributeregistry: dict.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param proppath: path of the schema you want to validate.
        :type proppath: str.
        :returns: returns model model, biosmode, bios model

        """
        type_str = self.current_client.monolith._typestring
        bsmodel = None
        valobj = self.validationmanager
        model = valobj.get_registry_model(currtype=currdict[type_str], \
                newarg=newarg, latestschema=latestschema, proppath=proppath)
        if not attributeregistry and model:
            return model, bsmodel
        if not model and not attributeregistry:
            self.warn("Unable to locate registry/schema for {0}".format( \
                                                            currdict[type_str]))
            return None, None
        attrval = currdict.get("AttributeRegistry", None)
        attrval = list(attributeregistry.values())[0] if not attrval and \
                                        attributeregistry else attrval
        bsmodel = valobj.get_registry_model(currtype=attrval if attrval else \
                                    currdict[type_str], newarg=newarg, \
                                    latestschema=latestschema, searchtype=\
                                    self.typepath.defs.attributeregtype)
        return model, bsmodel

    def getgen(self, gen=None, url=None, username=None, password=None, \
                                    proxy=None, isredfish=True):
        """Updates the defines object based on the iLO manager version

        :param isredfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type isredfish: boolean.

        """
        if self.typepath.adminpriv is False and url.startswith("blob"):
            raise UserNotAdminError("")
        self.typepath.getgen(gen=gen, url=url, username=username, \
                        password=password, logger=self.logger, proxy=proxy, isredfish=isredfish)

    def updatedefinesflag(self, redfishflag=None):
        """Updates the redfish and rest flag depending on system and
        user input

        :param redfishflag: flags if redfish is used
        :type redfishflag: bool
        :returns: boolean; is_redfish or redfishflag

        """
        if self.typepath.defs:
            is_redfish = redfishflag or self.typepath.defs.isgen10
            self.typepath.defs.flagforrest = not is_redfish
            if is_redfish:
                self.typepath.defs.redfishchange()

            return is_redfish
        else:
            return redfishflag

    def checkpostpatch(self, body=None, path=None,\
                        service=False, url=None, sessionid=None, headers=None, \
                        iloresponse=False, silent=False, patch=False):
        """Make the post file compatible with the system generation

        :param body: contents to be checked
        :type body: str.
        :param path: The URL location to check
        :type path: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :param url: originating url.
        :type url: str.
        :param sessionid: session id to be used instead of iLO credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param iloresponse: flag to return the iLO response.
        :type iloresponse: str.
        :param silent: flag to determine if no output should be done.
        :type silent: boolean.
        :param patch: flag to determine if a patch is being made
        :type patch: boolean.
        :returns: modified body and path parameter for target and action respectively

        """
        try:
            if self.typepath.defs.flagforrest:
                if "Target" not in body and not patch:
                    if "/Oem/Hp" in path:
                        body["Target"] = self.typepath.defs.oempath

                if path.startswith("/redfish/v1"):
                    path = path.replace("/redfish", "/rest", 1)

                if "/Actions/" in path:
                    ind = path.find("/Actions/")
                    path = path[:ind]

                if path.endswith('/'):
                    path = path[:-1]
            elif path.startswith("/rest/") and self.typepath.defs.isgen9:
                results = self.get_handler(put_path=path, service=service, \
                              url=url, sessionid=sessionid, headers=headers, \
                              response=iloresponse, silent=silent)
                if results and results.status == 200:
                    if results.dict:
                        if "Target" in body:
                            actions = results.dict["Oem"][self.typepath.defs.\
                                                            oemhp]["Actions"]
                        elif "Actions" in body:
                            actions = results.dict["Actions"]
                        else:
                            return (path, body)

                    allkeys = list(actions.keys())
                    targetkey = [x for x in allkeys if x.endswith(body\
                                                                  ["Action"])]

                    if targetkey[0].startswith("#"):
                        targetkey[0] = targetkey[0][1:]

                path = path.replace("/rest", "/redfish", 1)
                path = path+"/Actions"

                if "Target" in body:
                    path = path+self.typepath.defs.oempath
                    del body["Target"]

                if targetkey:
                    path = path + "/" + targetkey[0] + "/"

            return (path, body)
        except Exception as excp:
            raise excp

    def modifiedpath(self, results, delete=False, replace=False):
        """Check the path and set the modified flag

        :param results: Response for the path
        :type results: RestResponse
        """
        if not results or not results.status in (200, 201):
            return
        path = results.path
        path = path.split('/Actions')[0] if 'Actions' in path else path
        path = path + '/' if self.typepath.defs.isgen10 and path[-1] != '/' else path
        if not replace and path in self.monolith.paths:
            self.monolith.paths[path].modified = True
            _ = self.monolith.markmodified(path)
        if delete and path in self.monolith.paths:
            self.monolith.removepath(path)
        if replace and path in self.monolith.paths:
            self.monolith.paths[path].modified = True
            self.monolith.paths[path].patches = []

    def checkforchange(self, paths, crawl=True, loadtype='href'):
        """Check if the given paths have been modified

        :param paths: paths to be checked
        :type paths: list
        """
        (pathtoetag, _) = self.gettypeswithetag()
        mono = self.monolith
        self.download_path(list(paths), self.monolith, crawl=crawl, \
                                            reload=True, loadtype=loadtype)
        etags = [None if not path in mono.paths else mono.paths[path].etag\
                                                for path in paths]
        sametag = [path for ind, path in enumerate(paths) if path in pathtoetag\
            and path in self.monolith.paths and pathtoetag[path] != etags[ind]]
        for path in sametag:
            self.monolith.paths[path].patches = []
        if sametag:
            LOGGER.warning('The data in the following paths have been updated. '\
                    'Recheck the changes made to made. %s', ','.join([str(path) for \
                                                                                path in sametag]))
