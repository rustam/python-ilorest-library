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

from collections import OrderedDict, Mapping

import six
import jsonpatch
import jsonpath_rw
import jsonpointer
import redfish.ris.tpdefs
import redfish.ris.validation

from redfish.ris.ris import SessionExpiredRis
from redfish.ris.validation import ValidationManager, RepoRegistryEntry,\
                                                        Typepathforval,\
                                                        SchemaValidationError
from redfish.ris.rmc_helper import (UndefinedClientError, InstanceNotFoundError, \
                          CurrentlyLoggedInError, NothingSelectedError, \
                          InvalidSelectionError, IdTokenError, \
                          SessionExpired, ValidationError, \
                          RmcClient, RmcConfig, RmcFileCacheManager, \
                          NothingSelectedSetError, LoadSkipSettingError, \
                          InvalidCommandLineError, FailureDuringCommitError, \
                          InvalidPathError, ValueChangedError, IloResponseError, \
                          UserNotAdminError, EmptyRaiseForEAFP, \
                          IncompatibleiLOVersionError)

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class RmcApp(object):
    """Application level implementation of RMC"""
    def __init__(self, Args=None):
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

        if not "--showwarnings" in Args:
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

    def checkandupdate_rmc_client(self, url=None, username=None,
                                  password=None, biospassword=None, is_redfish=False):
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
                self._rmc_clients.set_bios_password(biospassword)
            return self._rmc_clients
        if self._rmc_clients and not url == self._rmc_clients.get_base_url():
            raise CurrentlyLoggedInError("Currently logged into another " \
                                         "server. \nPlease log out out first " \
                                         "before logging in to another.")
        self._rmc_clients = RmcClient(username=username, \
                    password=password, url=url, typepath=self.typepath, \
                    biospassword=biospassword, is_redfish=is_redfish)

    def get_current_client(self):
        """Get the current client"""
        if self._rmc_clients:
            return self._rmc_clients
        raise UndefinedClientError()
    current_client = property(get_current_client, None)

    def login(self, username=None, password=None, base_url='blobstore://.', \
              verbose=False, path=None, skipbuild=False, includelogs=False, \
              biospassword=None, is_redfish=False):
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
        self.checkandupdate_rmc_client(url=base_url, username=username,
                                       password=password, biospassword=biospassword,\
                                                is_redfish=is_redfish)
        self.current_client.login()
        if not skipbuild:
            self.build_monolith(verbose=verbose, path=path, \
                                                        includelogs=includelogs)
            self.save()

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
        monolith.load(path=path, includelogs=includelogs)
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

    def get(self, selector=None):
        """Main function for get command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :returns: returns a list from get operation

        """
        results = list()

        instances = self.get_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            currdict = instance.resp.dict

            # apply patches to represent current edits
            for patch in instance.patches:
                currdict = jsonpatch.apply_patch(currdict, patch)

            if selector:
                jsonpath_expr = jsonpath_rw.parse('%s' % selector)
                matches = jsonpath_expr.find(currdict)
                temp_dict = OrderedDict()

                for match in matches:
                    json_pstr = '/%s' % match.full_path
                    json_node = jsonpointer.resolve_pointer(currdict, json_pstr)
                    temp_dict[str(match.full_path)] = json_node
                    results.append(temp_dict)
            else:
                results.append(currdict)

        return results

    def get_save(self, selector=None, currentoverride=False, pluspath=False, \
                                            onlypath=None, remread=False):
        """Special main function for get in save command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param currentoverride: flag to override current selection.
        :type currentoverride: boolean.
        :param pluspath: flag to add path to the results.
        :type pluspath: boolean.
        :param onlypath: flag to enable only that path selection.
        :type onlypath: boolean.
        :returns: returns a list from the get command

        """
        results = list()

        instances = self.get_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if self.skipforsettings(instance.path, instances)\
                                                     and not currentoverride:
                continue
            elif onlypath:
                if not onlypath == instance.path:
                    continue

            currdict = instance.dict

            # apply patches to represent current edits
            for patch in instance.patches:
                currdict = jsonpatch.apply_patch(currdict, patch)

            if remread == True:
                try:
                    self.remove_readonly(currdict)
                except:
                    raise EmptyRaiseForEAFP()

            if selector:
                for item in six.iterkeys(currdict):
                    if selector.lower() == item.lower():
                        selector = item
                        break

                try:
                    jsonpath_expr = jsonpath_rw.parse('"%s"' % selector)
                except Exception as excp:
                    raise InvalidCommandLineError(excp)

                matches = jsonpath_expr.find(currdict)
                temp_dict = OrderedDict()

                for match in matches:
                    json_pstr = '/%s' % match.full_path
                    json_node = jsonpointer.resolve_pointer(currdict, json_pstr)
                    temp_dict[str(match.full_path)] = json_node

                results.append(temp_dict)
            else:
                if pluspath:
                    results.append({instance.path: currdict})
                else:
                    results.append(currdict)

        return results

    def skipforsettings(self, path, instances):
        """helper function for save helper to remove non /settings section

        :param path: originating path for the current instance.
        :type path: str.
        :param instances: current retrieved instances.
        :type instances: dict.
        :returns: returns skip boolean

        """
        instpaths = [inst.path.lower() for inst in instances]
        findpath = (path+"/settings", path+"settings/")
        if any(fpath.lower() in instpaths for fpath in findpath):
            return True
        return False

    def validate_headers(self, instance, verbose=False):
        """Module to check read-only property before patching.

        :param instance: instace of the property to check
        :type instance: Rest response object.
        :param verbose: enable to print more operations
        :type verbose: bool
        """

        skip = False
        try:
            headervals = list(instance.resp._http_response.headers.keys())
            if headervals is not None and len(headervals):
                allow = list([x for x in headervals if x.lower() == "allow"])
                if len(allow):
                    if not "PATCH" in instance.resp._http_response.headers\
                                                        [allow[0]]:
                        skip = True
                return skip
        except:
            pass
        try:
            if not any("PATCH" in x for x in instance.resp._http_response.msg.\
                                                                    headers):
                if verbose:
                    self.warning_handler('Skipping read-only path: %s\n' % \
                                                    instance.resp.request.path)
                skip = True
        except:
            try:
                for item in instance.resp._headers:
                    if list(item.keys())[0] == "allow":
                        if not "PATCH" in list(item.values())[0]:
                            if verbose:
                                self.warning_handler('Skipping read-only ' \
                                     'path: %s' % instance.resp.request.path)

                            skip = True
                            break
            except:
                if not ("allow" in instance.resp._headers and "PATCH" in \
                                            instance.resp._headers["allow"]):
                    if verbose:
                        self.warning_handler('Skipping read-only path: ' \
                                            '%s\n' % instance.resp.request.path)
                    skip = True
                elif not "allow" in instance.resp._headers:
                    if verbose:
                        self.warning_handler('Skipping read-only path: %s\n' \
                                                % instance.resp.request.path)
                    skip = True

        return skip

    def loadset(self, seldict=None, selector=None,\
                                    latestschema=False, uniqueoverride=False):
        """Optimized version of the old style of set properties

        :param seldict: current selection dictionary with required changes.
        :type seldict: dict.
        :param selector: the type selection for the set operation.
        :type selector: str.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :param uniqueoverride: flag to determine override for unique properties.
        :type uniqueoverride: str.
        :returns: returns a status or a list of set properties

        """
        results = list()

        nochangesmade = False
        patchremoved = False
        iloversion = self.getiloversion()
        settingskipped = [False]
        validation_manager = self.get_validation_manager(iloversion)
        (instances, _) = self.get_selection(setenable=True)

        if not instances or len(instances) == 0:
            raise NothingSelectedSetError()

        if selector:
            for instance in instances:
                self.checkforetagchange(instance=instance)
        (instances, attributeregistry) = self.get_selection(setenable=True)

        for instance in instances:
            if self.validate_headers(instance):
                continue
            else:
                nochangesmade = True

            currdict = instance.resp.dict

            self.get_model(currdict, validation_manager, \
                                instance, iloversion, attributeregistry, \
                                latestschema, nomodel=True)

            diffdict = self.diffdict(newdict=copy.deepcopy(seldict),\
                 oridict=copy.deepcopy(currdict), settingskipped=settingskipped)

            self.validatechanges(validation_manager=validation_manager, instance=instance,\
                iloversion=iloversion, attributeregistry=attributeregistry,\
                newdict=diffdict, oridict=currdict, unique=uniqueoverride)

            patches = jsonpatch.make_patch(currdict, diffdict)

            if patches:
                torem = []
                [torem.append(patch) for patch in patches.patch if patch["op"] == "remove" ]
                [patches.patch.remove(patch) for patch in torem]

            if patches:
                for patch in patches.patch:
                    for ind, item in enumerate(instance.patches):
                        try:
                            if item[0]["path"] == patch["path"]:
                                del instance.patches[ind]
                        except Exception:
                            if item.patch[0]["path"] == patch["path"]:
                                del instance.patches[ind]
                    forprint = patch["value"] if "value" in patch\
                                    else (patch["op"] + " " + patch["from"])
                    results.append({patch["path"][1:]:forprint})
                instance.patches.append(patches)
            if not results:
                for ind, item in enumerate(instance.patches):
                    ppath = item.patch[0]["path"] if hasattr(item, "patch") else item[0]["path"]
                    jpath = jsonpointer.JsonPointer(ppath.lower())
                    jval = jpath.resolve(seldict, default='kasjdk?!')
                    if not jval=='kasjdk?!':
                        del instance.patches[ind]
                        patchremoved = True
                nochangesmade = True

        if not nochangesmade:
            return results
        if patchremoved:
            return "reverting"
        elif settingskipped[0] is True:
            raise LoadSkipSettingError()
        else:
            return results

    def diffdict(self, newdict=None, oridict=None, settingskipped=[False]):
        """Optimized version of the old style of set properties

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
                    res = self.diffdict(newdict[key][0], oridict[key][0], \
                                                    settingskipped)
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

    def validatechanges(self, validation_manager=None, instance=None,\
                                iloversion=None, attributeregistry=None, \
                                newdict=None, oridict=None, unique=None):
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

        entrydict = None
        entrymono = None
        if float(iloversion) >= 4.210:
            entrydict = oridict
            entrymono = self.current_client.monolith

        try:
            if attributeregistry[instance.type]:
                validation_manager.bios_validate(newdict, \
                        attributeregistry[instance.type], \
                        currdict=entrydict, monolith=entrymono, unique=unique)
        except Exception:
            attregarg = validation_manager.find_prop(entrydict[entrymono._typestring])
            attrreg = validation_manager.validate(newdict, \
                currdict=entrydict, monolith=entrymono, attrreg=attregarg, unique=unique)
            if isinstance(attrreg, dict):
                attrreg = self.get_handler(attrreg[self.current_client.\
                        monolith._hrefstring], service=True, silent=True)
                attrreg = RepoRegistryEntry(attrreg.dict)
                validation_manager.validate(newdict, \
                                    currdict=entrydict, monolith=entrymono,\
                                    attrreg=attrreg, unique=unique)

        validation_errors = validation_manager.get_errors()
        for warninngs in validation_manager.get_warnings():
            self.warning_handler(warninngs)
        if validation_errors and len(validation_errors) > 0:
            raise ValidationError(validation_errors)

    def info(self, selector=None, ignorelist=None, dumpjson=False, \
                            autotest=False, newarg=None, latestschema=False):
        """Main function for info command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param ignorelist: list that contains keys to be removed from output.
        :type ignorelist: list.
        :param dumpjson: flag to determine if output should be printed out.
        :type dumpjson: boolean.
        :param autotest: flag to determine if this part of automatic testing.
        :type autotest: boolean.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :returns: returns a list of keys from current dict that are not ignored

        """
        model = None
        outdata = ''
        results = list()
        iloversion = self.getiloversion()
        validation_manager = self.get_validation_manager(iloversion)
        (instances, attributeregistry) = self.get_selection(setenable=True)

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if self.skipforsettings(instance.path, instances):
                continue

            bsmodel = None
            biosmode = False
            currdict = instance.resp.dict

            if selector:
                if newarg:
                    currdictcopy = currdict

                    for ind, elem in enumerate(newarg):
                        if isinstance(currdictcopy, dict):
                            for item in six.iterkeys(currdictcopy):
                                if elem.lower() == item.lower():
                                    selector = item
                                    newarg[ind] = item

                                    if not elem.lower() == newarg[-1].lower():
                                        currdictcopy = currdictcopy[item]
                                        break
                        else:
                            break
                else:
                    for item in six.iterkeys(currdict):
                        if selector.lower() == item.lower():
                            selector = item
                            break

            if self.current_client.monolith._typestring in currdict:
                model, biosmode, bsmodel = self.get_model(currdict, \
                                  validation_manager, instance, iloversion, \
                                  attributeregistry, latestschema, newarg, \
                                  autotest=autotest)

            if not model and not bsmodel:
                if newarg:
                    self.warning_handler("No data available for entry: '%s'\n" \
                                                            % "/".join(newarg))

                    if autotest:
                        return (True, [])
                    else:
                        break
                else:
                    self.warn("Unable to locate registry model for " \
                                                            ":'%s'" % selector)
                    continue

            if selector:
                if newarg:
                    currdict = currdictcopy

                jsonpath_expr = jsonpath_rw.parse('"%s"' % selector)
                matches = jsonpath_expr.find(currdict)

                if matches:
                    for match in matches:
                        json_pstr = '/%s' % match.full_path
                        jsonpointer.JsonPointer(json_pstr)

                        for key in currdict:
                            matchpath = '%s' % match.full_path
                            if not key.lower() == matchpath.lower():
                                continue

                            if biosmode:
                                found = model.get_validator_bios(key)

                                if not found and bsmodel:
                                    found = bsmodel.get_validator(key)
                            else:
                                found = model.get_validator(key)

                            if found:
                                if dumpjson:
                                    outdata = found
                                    results.append("Success")
                                elif autotest:
                                    return (True, [])
                                else:
                                    results.append("Success")
                                    outdata = found.print_help(selector)
                            else:
                                self.warning_handler("No data available for " \
                                         "entry: '%s'\n" % ("/".join(newarg) \
                                                    if newarg else selector))
                                results.append("none")
                else:
                    self.warning_handler("Entry '%s' not found in current" \
                                            " selection\n" % ("/".join(newarg) \
                                                      if newarg else selector))
                    results.append("none")

            else:
                if currdict[self.typepath.defs.typestring].startswith("#Bios."):
                    try:
                        currdict = currdict['Attributes']
                    except:
                        pass
                for key in currdict:
                    if key not in ignorelist and not '@odata' in key.lower():
                        results.append(key)

        return (results, outdata)

    def getcollectionmembers(self, path):
        """Returns collection/item lists of the provided path
        :param path: path to return .
        :type path: string.
        :returns: returns collection list
        """
        if self.typepath.defs.isgen10:
            if path.endswith('/'):
                path += '?$expand=.'
            else:
                path += '/?$expand=.'

        members = self.get_handler(path, service=True, silent=True)
        if members:
            try:
                if self.typepath.defs.isgen10:
                    members = members.dict['Members']
                else:
                    members = members.dict['Items']
            except:
                members = []

        return members

    def getbiosfamilyandversion(self):
        """Function that returns the current BIOS family"""
        monolith = self.current_client.monolith
        rdirtype = monolith.gettypename(self.typepath.defs.resourcedirectorytype)

        if rdirtype:
            self.check_types_exists(rdirtype, "ComputerSystem.", \
                                self.current_client.monolith, skipcrawl=True)

        try:
            for inst in monolith.itertype("ComputerSystem."):
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

        iloversion = self._iloversion

        if not self._iloversion:
            results = self.get_handler(self.current_client._rest_client.\
                                       default_prefix, silent=True, service=True)

            try:
                if results.dict["Oem"][self.typepath.defs.oemhp]["Manager"]:
                    oemjson = results.dict["Oem"][self.typepath.defs.\
                                                                oemhp]["Manager"]
                    ilogen = oemjson[0]["ManagerType"]
                    ilover = oemjson[0]["ManagerFirmwareVersion"]
                    iloversion = ilogen.split(' ')[-1] + '.' + \
                                                        ''.join(ilover.split('.'))
            except Exception:
                pass
            self._iloversion = iloversion

        if not skipschemas:
            if iloversion and float(iloversion) >= 4.210:
                self.verifyschemasdownloaded(self.current_client.monolith)
            elif iloversion and float(iloversion) < 4.210:
                raise IncompatibleiLOVersionError("Please upgrade to iLO 4 "\
                                    "version 2.1 or above for schema support.")
            else:
                raise IncompatibleiLOVersionError("Schema support unavailable "\
                                        "on the currently logged in system.")

        return iloversion

    def status(self):
        """Main function for status command"""
        iloversion = self.getiloversion()
        validation_manager = self.get_validation_manager(iloversion)

        finalresults = list()
        monolith = self.current_client.monolith
        (_, attributeregistry) = self.get_selection(setenable=True)

        for instance in monolith.iter():
            results = list()

            if instance.patches and len(instance.patches) > 0:
                if isinstance(instance.patches[0], list):
                    results.extend(instance.patches)
                else:
                    if instance.patches[0]:
                        for item in instance.patches:
                            results.extend(item)

            currdict = instance.resp.dict

            itemholder = list()
            for mainitem in results:
                item = copy.deepcopy(mainitem)
                regfound = None

                try:
                    if attributeregistry[instance.type]:
                        regfound = validation_manager.\
                                    find_prop(\
                                       attributeregistry[instance.type])
                except Exception:
                    pass

                if regfound:
                    model, _, _ = self.get_model(currdict, \
                                     validation_manager, instance, \
                                     iloversion, attributeregistry)

                    if model:
                        try:
                            validator = \
                                model.get_validator_bios(item[0]\
                                                        ["path"][1:])
                        except Exception:
                            validator = model.get_validator_bios(\
                                                     item["path"][1:])

                        if validator:
                            try:
                                if isinstance(validator, redfish.ris.\
                                          validation.PasswordValidator):
                                    item[0]["value"] = "******"
                            except Exception:
                                if isinstance(validator, redfish.ris.\
                                          validation.PasswordValidator):
                                    item["value"] = "******"

                itemholder.append(item)

            if itemholder:
                finalresults.append({instance.type: itemholder})

        return finalresults

    def capture(self):
        """Build and return the entire monolith"""
        monolith = self.current_client.monolith
        vistedurls = monolith.visited_urls

        monolith.visited_urls = list()
        monolith.load(includelogs=True, skipcrawl=False, loadcomplete=True)
        monolith.visited_urls = vistedurls

        results = list()
        instances = self.get_selection(selector='"*"')

        for instance in instances:
            currdict = instance.resp.dict
            results.append({instance.resp.request.path: currdict})

        return monolith.to_dict()

    def commit(self, out=sys.stdout, verbose=False):
        """Main function for commit command

        :param out: output type for verbosity.
        :type out: output type.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :returns: returns boolean of whether changes were made

        """
        changesmade = False
        instances = self.get_commit_selection()

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
                try:
                    self.checkforetagchange(instance=instance)
                except Exception as excp:
                    raise excp

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
                changesmade = True
                if verbose:
                    out.write('Changes are being made to path: %s\n' % \
                                                    instance.resp.request.path)

                put_path = instance.resp.request.path
                results = self.current_client.set(put_path, body=currdict, \
                          optionalpassword=self.current_client.bios_password)

                errmessages = self.get_error_messages()
                self.invalid_return_handler(results, errmessages=errmessages)

                if not results.status == 200:
                    raise FailureDuringCommitError("Failed to commit with " \
                                               "error code %d" % results.status)

        return changesmade

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

    def get_error_messages(self):
        """Handler of error messages from iLO"""
        LOGGER.info("Entering validation...")
        errmessages = {}
        reglist = []
        try:
            iloversion = self.getiloversion()
        except IncompatibleiLOVersionError:
            return errmessages

        typestr = self.current_client.monolith._typestring
        validation_manager = self.get_validation_manager(iloversion)

        if not validation_manager._classes:
            return None
        for reg in validation_manager.iterregmems():
            try:
                if reg and 'Registry' in reg and not 'biosattributeregistry' in \
                                                        reg['Registry'].lower():
                    reglist.append(reg['Registry'])
                elif reg and 'Id' in reg and not 'biosattributeregistry' in \
                                                            reg['Id'].lower():
                    reglist.append(reg['Id'])
                elif reg and 'Schema' in reg and not 'biosattributeregistry' in \
                                                        reg['Schema'].lower():
                    reglist.append(reg['Schema'])
            except:
                if reg:
                    reg = reg['@odata.id'].split('/')
                    reg = reg[len(reg)-2]
                    if not 'biosattributeregistry' in reg.lower():
                        reglist.append(reg)

        for reg in reglist:
            #added for smart storage differences in ids
            reg = reg.replace("%23", "#")
            regfound = validation_manager.find_prop(reg)

            if regfound and self.current_client.monolith.is_redfish\
                                 and not isinstance(regfound, RepoRegistryEntry):
                regfound = self.get_handler(regfound['@odata.id'], \
                                verbose=False, service=True, silent=True).obj
                regfound = RepoRegistryEntry(regfound)
            if not regfound:
                self.warn("Unable to locate registry for '%s'", reg)
            elif float(iloversion) >= 4.210:
                try:
                    locationdict = self.geturidict(regfound.Location[0])
                    self.check_type_and_download(self.current_client.monolith, \
                                     locationdict, skipcrawl=True, loadtype='ref')
                except Exception:
                    pass
            if regfound:
                messages = regfound.get_registry_model(\
                                skipcommit=True, currdict={typestr: reg}, \
                                monolith=self.current_client.monolith, \
                                searchtype=self.typepath.defs.messageregistrytype)
                if messages:
                    errmessages.update(messages)

        return errmessages

    def patch_handler(self, put_path, body, verbose=False, url=None, \
                  sessionid=None, headers=None, response=False, silent=False, \
                  optionalpassword=None, providerheader=None, service=False,\
                  username=None, password=None):
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

        """
        errmessages = None

        if sessionid:
            if url is None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url, username=username, password=password)

        (put_path, body) = self.checkpostpatch(body=body, path=put_path, \
                    service=False, url=None, sessionid=None, \
                    headers=None, iloresponse=False, silent=True, patch=True)

        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                                    self.updatedefinesflag(), username=username, \
                                    password=password).\
                                    set(put_path, body=body, headers=headers, \
                                           optionalpassword=optionalpassword, \
                                           providerheader=providerheader)
            service = True
        else:
            results = self.current_client.set(put_path, body=body, \
                        headers=headers, optionalpassword=optionalpassword, \
                        providerheader=providerheader)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if results and hasattr(results, "status") and results.status == 412:
            self.reloadmonolith(path=put_path)
        if not silent:
            self.invalid_return_handler(results, verbose=verbose, errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        if response:
            return results

    def get_handler(self, put_path, silent=False, verbose=False, url=None, \
                                sessionid=None, uncache=False, headers=None, \
                                response=False, service=False, username=None, \
                                password=None):
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

        """
        errmessages = None

        if sessionid:
            if url is None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url, username=username, password=password)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                                                    self.updatedefinesflag(),\
                                        username=username, password=password).\
                                                get(put_path, headers=headers)
            service = True
        else:
            results = self.current_client.get(put_path, uncache=uncache, \
                                                                headers=headers)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, \
                                                        errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        if results.status == 200 or response:
            return results

        return None

    def post_handler(self, put_path, body, verbose=False, url=None, \
                             sessionid=None, headers=None, response=False, \
                             silent=False, providerheader=None, service=False, \
                                     username=None, password=None):
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

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url, username=username, password=password)

        (put_path, body) = self.checkpostpatch(body=body, path=put_path, \
                    service=False, url=None, sessionid=None,\
                    headers=None, iloresponse=False, silent=True)

        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                                    self.updatedefinesflag(), username=username, \
                                     password=password).toolpost(put_path, \
                                     body=body, headers=headers, \
                                     providerheader=providerheader)
            service = True
        else:
            results = self.current_client.toolpost(put_path, body=body, \
                                headers=headers, providerheader=providerheader)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        if response:
            return results

    def put_handler(self, put_path, body, verbose=False, url=None, \
                sessionid=None, headers=None, response=False, silent=False, \
                optionalpassword=None, providerheader=None, service=False, \
                username=None, password=None):
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

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url, username=username, password=password)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                            self.updatedefinesflag(), username=username, \
                            password=password).toolput(put_path, \
                                       body=body, headers=headers, \
                                       optionalpassword=optionalpassword, \
                                       providerheader=providerheader)
            service = True
        else:
            results = self.current_client.toolput(put_path, body=body, \
                          headers=headers, optionalpassword=optionalpassword, \
                          providerheader=providerheader)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        if response:
            return results

    def delete_handler(self, put_path, verbose=False, url=None, \
                                    sessionid=None, headers=None, silent=False, \
                                    providerheader=None, service=False, \
                                    username=None, password=None):
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

        """
        errmessages = None

        if sessionid:
            if url is None:
                url = 'blobstore://'
            if not self.typepath.defs:
                rflag = None
                self.getgen(url=url, username=username, password=password)
                rflag = self.updatedefinesflag(redfishflag=rflag)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                                                    self.updatedefinesflag(),\
                                        username=username, password=password).\
                tooldelete(put_path, headers=headers, providerheader=providerheader)
            service = True
        else:
            results = self.current_client.tooldelete(put_path, \
                                 headers=headers, providerheader=providerheader)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        return results

    def head_handler(self, put_path, verbose=False, url=None, sessionid=None, \
                                                silent=False, service=False, \
                                                username=None, password=None):
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

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url, username=username, password=password)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                                                    self.updatedefinesflag(),\
                                        username=username, password=password).\
                                                                head(put_path)
            service = True
        else:
            results = self.current_client.head(put_path)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        if results.status == 200:
            return results
        else:
            return None

    _QUERY_PATTERN = re.compile(r'(?P<instance>[\w\.]+)(:(?P<xpath>.*))?')
    def _parse_query(self, querystr):
        """Parse query and return as a tuple. TODO probably need to move"""
        """ this into its own class if it gets too complicated

        :param querystr: query string.
        :type querystr: str.
        :returns: returns a dict of parsed query

        """
        qmatch = RmcApp._QUERY_PATTERN.search(querystr)
        if not qmatch:
            raise InvalidSelectionError("Unable to locate instance for " \
                                                            "'%s'" % querystr)
        qgroups = qmatch.groupdict()
        return (qgroups['instance'], qgroups.get('xpath', None))

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
                    self.warning_handler("The property you are trying to change "\
                                         "has been updated. Please check entry" \
                                         " again  before manipulating it.\n")
                    raise ValueChangedError("")
                else:
                    self.warning_handler("[%d] No message returned by iLO.\n" %\
                                                                results.status)

                    raise IloResponseError("")
                return

        if results.status == 401 and not contents[-1].lower() == \
                                                        'insufficientprivilege':
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
                            self.warning_handler("[%d] %s\n" % (results.status, \
                                                                        output))
                        if results.status == 200 or results.status == 201:
                            self.warning_handler("{0}\n".format(output))
                        if not results.status == 200 and not results.status == 201:
                            self.warning_handler("iLO response with code [%d]: %s\n"%(\
                                                        results.status, output))
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
                    self.warning_handler("[{0}] iLO error response: {1}\n".format( \
                                                results.status, contents))
                    raise IloResponseError("")
        else:
            if results.status == 200 or results.status == 201:
                if verbose:
                    self.warning_handler("[%d] The operation completed " \
                                            "successfully.\n" % results.status)
                else:
                    self.warning_handler("The operation completed "\
                                                            "successfully.\n")
            elif contents:
                self.warning_handler("iLO response with code [{0}]: {1}\n".format(\
                                                        results.status, contents))
                raise IloResponseError("")
            else:
                self.warning_handler("[%d] No message returned.\n" % \
                                                                results.status)

    def select(self, query, sel=None, val=None):
        """Main function for select command

        :param query: query string.
        :type query: str.
        :param sel: the type selection for the select operation.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :returns: returns a list of selected items

        """
        if query:
            if isinstance(query, list):
                if len(query) == 0:
                    raise InstanceNotFoundError("Unable to locate instance " \
                                                            "for '%s'" % query)
                else:
                    query = query[0]

            if val:
                if (str(val)[0] == str(val)[-1]) and \
                                                str(val).endswith(("'", '"')):
                    val = val[1:-1]

            query = self.checkselectforgen(query)
            selection = self.get_selection(selector=query, sel=sel, val=val)

            if selection and len(selection) > 0:
                self.current_client.selector = query

                if not sel is None and not val is None:
                    self.current_client.filter_attr = sel
                    self.current_client.filter_value = val
                else:
                    self.current_client.filter_attr = None
                    self.current_client.filter_value = None

                self.save()
                return selection

        if not sel is None and not val is None:
            raise InstanceNotFoundError("Unable to locate instance for" \
                                " '%s' and filter '%s=%s'" % (query, sel, val))
        else:
            raise InstanceNotFoundError("Unable to locate instance for" \
                                                                " '%s'" % query)

    def filter(self, query, sel, val):
        """Main function for filter command

        :param query: query string.
        :type query: str.
        :param sel: the type selection for the select operation.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :returns: returns a list of selected items

        """
        if query:
            if isinstance(query, list):
                if len(query) == 0:
                    raise InstanceNotFoundError("Unable to locate instance " \
                                                            "for '%s'" % query)
                else:
                    query = query[0]

            selection = self.get_selection(selector=query, sel=sel, val=val)

            if selection and len(selection) > 0:
                self.current_client.selector = query
                self.current_client.filter_attr = sel
                self.current_client.filter_value = val
                self.save()

            return selection

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
                                                                        == val:
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
        rdirtype = monolith.gettypename(self.typepath.defs.resourcedirectorytype)

        if not rdirtype:
            for inst in monolith.iter():
                if not any([x for x in ['ExtendedError', 'object', 'string']\
                                             if x in inst.type]):
                    instances.append(inst.type)
        else:
            for instance in monolith.itertype(rdirtype):
                for item in instance.resp.dict["Instances"]:
                    if item and instance._typestring in list(item.keys()) and \
                        not 'ExtendedError' in item[instance._typestring]:
                        if not fulltypes and instance._typestring == \
                                                            '@odata.type':
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
            instancepath[inst.path] = inst.type
            templist = inst.resp.getheaders()
            for ind, val in enumerate(templist):
                if val[0] in ['etag', 'ETag']:
                    tempindex = ind
            instances[inst.path] = templist[tempindex][1]

        return [instances, instancepath]

    def reloadmonolith(self, path=None):
        """Helper function to reload new data into monolith

        :param path: path to initiate reload monolith from.
        :type path: str.
        :returns: returns True/False depending on if reload occurred

        """
        if path:
            self.current_client.monolith.reload = True
            self.current_client.monolith.load(path=path, skipinit=True, \
                                                                skipcrawl=True)
            self.current_client.monolith.reload = False
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
            self.reloadmonolith(path)
            (newtag, _) = self.gettypeswithetag()
            if (oldtag[path] != newtag[path]) and \
                        not self.typepath.defs.hpilodatetimetype in instance.type:
                self.warning_handler("The property you are trying to change " \
                                 "has been updated. Please check entry again " \
                                 " before manipulating it.\n")
                raise ValueChangedError()

    def verifyschemasdownloaded(self, monolith):
        """Function to verify that the schema has been downloaded

        :param monolith: full data model retrieved from server.
        :type monolith: dict.

        """
        schemasfound = False
        registriesfound = False

        if monolith.is_redfish:
            schemaid = "/redfish/v1/schemas/?$expand=."
            regid = "/redfish/v1/registries/?$expand=."
        else:
            schemaid = "/rest/v1/schemas"
            regid = "/rest/v1/registries"

        if monolith.gettypename("Collection."):

            collectionpaths = monolith.typesadded[monolith.gettypename("Collection.")]
            if any(paths.lower() == schemaid for paths in collectionpaths):
                schemasfound = True
            if any(paths.lower() == regid for paths in collectionpaths):
                registriesfound = True

        if not schemasfound:
            self.check_type_and_download(monolith, schemaid, skipcrawl=True)

        if not registriesfound:
            self.check_type_and_download(monolith, regid, skipcrawl=True)

    def check_type_and_download(self, monolith, foundhref, skipcrawl=False, \
                                                            loadtype='href'):
        """Check if type exist and download

        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param foundhref: href found to be used for comparision.
        :type foundhref: str.
        :param skipcrawl: flag to determine if load should traverse found links.
        :type skipcrawl: boolean.
        :param loadtype: object to determine the type of the structure found.
        :type loadtype: str.

        """
        findhref = foundhref[:-1] if foundhref[-1] == '/' else foundhref
        found = any(linkref in monolith.pathsadded for linkref in (findhref, foundhref))

        if not found:
            try:
                monolith.load(path=foundhref, skipinit=True, \
                      skipcrawl=skipcrawl, includelogs=True, loadtype=loadtype)
            except SessionExpiredRis:
                raise SessionExpired()
            except jsonpointer.JsonPointerException:
                raise SchemaValidationError()
            except Exception as excp:
                try:
                    if excp.errno == 10053:
                        raise SessionExpired()
                except:
                    raise excp
                else:
                    raise excp

    def check_types_exists(self, rdirtype, currtype, monolith, \
                                                            skipcrawl=False):
        """Check if type exists in current monolith

        :param entrytype: the found entry type.
        :type entrytype: str.
        :param currtype: the current entry type.
        :type currtype: str.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param skipcrawl: flag to determine if load should traverse found links.
        :type skipcrawl: boolean.

        """
        inst = None
        try:
            for inst in monolith.itertype(rdirtype):
                for item in inst.resp.dict["Instances"]:
                    if currtype == '"*"' or (item and monolith._typestring in \
                        list(item.keys()) and currtype.lower() in item[monolith.\
                                                        _typestring].lower()):
                        self.check_type_and_download(monolith, \
                             item[monolith._hrefstring], skipcrawl=skipcrawl)
        except:
            if inst:
                LOGGER.debug("Instance error, Instance contents: %s" % \
                                                            inst.resp.text)
            raise

    def get_selection(self, selector=None, sel=None, val=None, setenable=False):
        """Special main function for set/filter with select command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param sel: property to be modified.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :param setenable: flag to determine if registry should also be returned.
        :type setenable: boolean.
        :returns: returns a list of selected items

        """
        if not sel and not val:
            (sel, val) = self.get_filter_settings()

        attributeregistryfound = dict()
        monolith = self.current_client.monolith

        if selector:
            rdirtype = monolith.gettypename(self.typepath.defs.resourcedirectorytype)
            if rdirtype:
                skipcrawl = False if selector.lower().startswith("log") else True
                if not skipcrawl:
                    self.warning_handler("Full data retrieval enabled. You " \
                                    "may experience longer download times.\n")
                self.check_types_exists(rdirtype, selector, monolith, \
                                                            skipcrawl=skipcrawl)


        instances = list()
        if not selector:
            selector = self.current_client.selector

        if not selector:
            if setenable:
                return instances, attributeregistryfound
            return instances

        xpath = None

        if not selector == '"*"':
            (qinstance, xpath) = self._parse_query(selector)
        else:
            qinstance = selector

        for inst in monolith.iter():
            if qinstance.lower() in inst.type.lower() or qinstance == '"*"':
                if setenable:
                    try:
                        if inst.resp.obj["AttributeRegistry"]:
                            attributeregistryfound[inst.type] = \
                                inst.resp.obj["AttributeRegistry"]
                    except Exception:
                        pass
                    findpath = (inst.path+"/settings", inst.path+"settings/")
                    if any(fpath.lower() in monolith.typesadded[inst.maj_type]\
                            for fpath in findpath):
                        continue
                if not (sel is None or val is None):
                    currdict = inst.resp.dict
                    try:
                        if not "/" in sel:
                            for item in six.iterkeys(currdict):
                                if sel.lower() == item.lower():
                                    sel = item
                            if val[-1] == "*":
                                if not val[:-1] in str(currdict[sel]):
                                    continue
                            else:
                                #Changed from startswith to in
                                if not val in str(currdict[sel]):
                                    continue
                        else:
                            newargs = sel.split("/")
                            content = copy.deepcopy(currdict)

                            if self.filterworkerfunction(workdict=\
                                        content, sel=sel, val=val, \
                                        newargs=newargs, loopcount=0):
                                instances.append(inst)
                            continue
                    except Exception:
                        continue

                if xpath:
                    raise RuntimeError("Not implemented")
                else:
                    instances.append(inst)

        if setenable:
            return instances, attributeregistryfound

        return instances

    def filterworkerfunction(self, workdict=None, sel=None, val=None, \
                                                    newargs=None, loopcount=0):
        """Helper function for filter application

        :param workdict: working copy of current dictionary.
        :type workdict: dict.
        :param sel: property to be modified.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param loopcount: loop count tracker.
        :type loopcount: int.
        :returns: returns boolean based on val parameter being found in newargs

        """
        if workdict and sel and val and newargs:
            if isinstance(workdict, list):
                for item in workdict:
                    if self.filterworkerfunction(workdict=item, sel=sel, \
                                 val=val, newargs=newargs, loopcount=loopcount):
                        return True

                return False

            keys = list(workdict.keys())
            keyslow = [x.lower() for x in keys]

            if newargs[loopcount].lower() in keyslow:
                if loopcount == (len(newargs) - 1):
                    if val == str(workdict[newargs[loopcount]]):
                        return True

                    return False

                if not (isinstance(workdict[newargs[loopcount]], list) or \
                                isinstance(workdict[newargs[loopcount]], dict)):
                    return False

                workdict = workdict[newargs[loopcount]]
                loopcount += 1

                if self.filterworkerfunction(workdict=workdict, sel=sel, \
                                 val=val, newargs=newargs, loopcount=loopcount):
                    return True

        return False

    def get_commit_selection(self):
        """Special main function for commit command"""
        instances = list()
        monolith = self.current_client.monolith
        _ = [instances.append(inst) for inst in monolith.iter() if inst.patches]
        return instances

    def get_save_header(self, selector=None):
        """Special function for save file headers

        :param selector: the type selection for the get save operation.
        :type selector: str.
        :returns: returns an header ordered dictionary

        """
        instances = OrderedDict()
        monolith = self.current_client.monolith

        if not selector:
            selector = self.current_client.selector

        if not selector:
            return instances

        instances["Comments"] = OrderedDict()

        rdirtype = monolith.gettypename(self.typepath.defs.resourcedirectorytype)

        if rdirtype:
            self.check_types_exists(rdirtype, "ComputerSystem.", \
                                self.current_client.monolith, skipcrawl=True)
            self.check_types_exists(rdirtype, "Bios.", \
                                self.current_client.monolith, skipcrawl=True)


        try:
            for instance in monolith.itertype("ComputerSystem."):
                if instance.resp.obj["Manufacturer"]:
                    instances["Comments"]["Manufacturer"] = \
                                instance.resp.obj["Manufacturer"]

                if instance.resp.obj["Model"]:
                    instances["Comments"]["Model"] = \
                                        instance.resp.obj["Model"]

                if instance.resp.obj["Oem"][self.typepath.\
                                    defs.oemhp]["Bios"]["Current"]:
                    oemjson = instance.resp.obj["Oem"]\
                        [self.typepath.defs.oemhp]["Bios"]["Current"]
                    instances["Comments"]["BIOSFamily"] = \
                                                oemjson["Family"]
                    instances["Comments"]["BIOSDate"] = \
                                                    oemjson["Date"]
            for instance in monolith.itertype(self.typepath.defs.biostype):
                if "Attributes" in list(instance.resp.obj.keys()) and \
                    instance.resp.obj["Attributes"]["SerialNumber"]:
                    instances["Comments"]["SerialNumber"] = \
                        instance.resp.obj["Attributes"]["SerialNumber"]
                elif instance.resp.obj["SerialNumber"]:
                    instances["Comments"]["SerialNumber"] = \
                                    instance.resp.obj["SerialNumber"]
        except Exception:
            pass
        return instances

    def get_selector(self):
        """Helper function to return current select option"""
        if self.current_client:
            if self.current_client.selector:
                return self.current_client.selector
        return None

    def get_filter_settings(self):
        """Helper function to get current filter settings"""
        if self.current_client:
            if not self.current_client.filter_attr is None and not \
                                    self.current_client.filter_value is None:
                return (self.current_client.filter_attr, \
                                            self.current_client.filter_value)
        return (None, None)

    def erase_filter_settings(self):
        """Helper function to erase current filter settings"""
        if self.current_client:
            if not self.current_client.filter_attr is None or \
                                not self.current_client.filter_value is None:
                self.current_client.filter_attr = None
                self.current_client.filter_value = None

    def update_bios_password(self, value):
        """Helper function to set bios password

        :param value: value to be set as the new BIOS password.
        :type value: str.

        """
        if self.current_client:
            self.current_client.bios_password = value

    def get_validation_manager(self, iloversion):
        """Get validation manager helper

        :param iloversion: current systems iLO versions.
        :type iloversion: str.
        :returns: returns a ValidationManager

        """

        if self._validationmanager:
            self._validationmanager._errors = list()
            self._validationmanager._warnings = list()
            return self._validationmanager

        monolith = None

        if float(iloversion) >= 4.210:
            monolith = self.current_client.monolith

#         (romfamily, biosversion) = self.getbiosfamilyandversion()
        validation_manager = ValidationManager(monolith, \
                            defines=self.typepath)
        self._validationmanager = validation_manager

        return validation_manager

    def remove_readonly(self, body, removeunique=True):
        """Removes all readonly items from a dictionary

        :param body: the body to the sent.
        :type body: str.
        :returns: returns dictionary with readonly items removed

        """

        outdict = None
        biosmode = False
        iloversion = self.getiloversion()
        type_str = self.current_client.monolith._typestring
        isredfish = self.current_client.monolith.is_redfish

        (_, attributeregistry) = self.get_selection(selector=body[type_str], \
                                                                setenable=True)
        validation_manager = self.get_validation_manager(iloversion)

        schematype = body[type_str]

        try:
            regtype = attributeregistry[body[type_str]]
        except Exception:
            pass

        try:
            if attributeregistry[body[type_str]]:
                biosmode = True
                regfound = validation_manager.find_prop(regtype)
                biosschemafound = validation_manager.find_prop(schematype)

                if isredfish and not isinstance(biosschemafound, RepoRegistryEntry):
                    regfound = self.get_handler(regfound['@odata.id'], \
                                verbose=False, service=True, silent=True).obj
                    regfound = RepoRegistryEntry(regfound)
        except Exception:
            regfound = validation_manager.find_prop(schematype)

        if isredfish and not isinstance(regfound, RepoRegistryEntry):
            regfound = self.get_handler(regfound['@odata.id'], \
                                verbose=False, service=True, silent=True).obj
            regfound = RepoRegistryEntry(regfound)
        if not regfound:
            self.warn("Unable to locate registry/schema for '%s'", \
                                                                body[type_str])
            return None, None, None
        elif float(iloversion) >= 4.210:
            try:
                locationdict = self.geturidict(regfound.Location[0])
                self.check_type_and_download(self.current_client.monolith, \
                                        locationdict, \
                                        skipcrawl=True, loadtype='ref')
            except Exception as excp:
                raise excp

        if biosmode:
            if float(iloversion) >= 4.210:
                model = regfound.get_registry_model_bios_version(\
                        currdict=body, monolith=self.current_client.monolith)
        elif float(iloversion) >= 4.210:
            model = regfound.get_registry_model(currdict=body, \
                                        monolith=self.current_client.monolith)

        if model and biosmode:
            outdict = self.remove_readonly_helper_bios(body, model, removeunique)
        elif model:
            outdict = self.remove_readonly_helper(body, model)

        return outdict

    def remove_readonly_helper_bios(self, body, model, removeunique):
        """Helper function for remove readonly function for gen10 BIOS

        :param body: the body to the sent.
        :type body: str.
        :param model: model for the current type.
        :type model: str.
        :returns: returns body with read only items removed

        """
        if 'Attributes' in body:
            bodykeys = list(body['Attributes'].keys())
        else:
            bodykeys = list(body.keys())

        templist = ["Name", "Modified", "Type", "Description", \
                    "AttributeRegistry", "links", "SettingsResult", "Status", \
                    "@odata.context", "@odata.type", "@odata.id", "@odata.etag"]

        for item in model['Attributes']:
            if item['AttributeName'] in bodykeys:
                try:
                    if item['ReadOnly']:
                        templist.append(item['AttributeName'])
                    elif removeunique and item['IsSystemUniqueProperty']:
                        templist.append(item['AttributeName'])
                except:
                    continue

        if templist:
            for key in templist:
                if key in bodykeys:
                    if 'Attributes' in body:
                        body['Attributes'].pop(key)
                    else:
                        body.pop(key)
                elif key in list(body.keys()):
                    body.pop(key)

        return body

    def remove_readonly_helper(self, body, model):
        """Helper function for remove readonly function for gen10 iLO and others

        :param body: the body to the sent.
        :type body: str.
        :param model: model for the current type.
        :type model: str.
        :returns: returns body with readonly removed

        """
        templist = ["Links", "Actions"]

        for key in list(model.keys()):
            readonly = True
            try:
                if isinstance(model[key], dict):
                    try:
                        readonly = model[key].readonly
                        if readonly:
                            templist.append(key)
                            continue
                    except:
                        pass

                    if 'properties' in list(model[key].keys()):
                        if key in list(body.keys()):
                            newdict = self.remove_readonly_helper(body[key], \
                                                    model[key]['properties'])

                            if newdict:
                                body[key] = newdict
                            else:
                                del body[key]

                    elif 'items' in list(model[key].keys()):
                        try:
                            if model[key]['items'].readonly:
                                templist.append(key)
                        except:
                            pass
                        if key in list(body.keys()):
                            if isinstance(body[key], list):
                                for item in body[key]:
                                    self.remove_readonly_helper(item, \
                                            model[key]['items']['properties'])
                    elif readonly:
                        templist.append(key)
            except:
                continue

        if templist:
            for key in templist:
                if key in list(body.keys()):
                    body.pop(key)

        return body

    def get_model(self, currdict, validation_manager, instance, \
                  iloversion, attributeregistry, latestschema=None, \
                  newarg=None, autotest=False, nomodel=False):
        """Returns the model for the current instance's schema/registry

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param validation_manager: validation manager object.
        :type validation_manager: validation object.
        :param instances: current retrieved instances.
        :type instances: dict.
        :param iloversion: current systems iLO versions.
        :type iloversion: str.
        :param attributeregistry: current systems attribute registry.
        :type attributeregistry: dict.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param autotest: flag to determine if this part of automatic testing.
        :type autotest: boolean.
        :returns: returns model model, biosmode, bios model

        """
        biosschemafound = None
        bsmodel = None
        biosmode = False
        type_str = self.current_client.monolith._typestring
        isredfish = self.current_client.monolith.is_redfish

        if latestschema:
            schematype, regtype = self.latestschemahelper(currdict, \
                                                          validation_manager)

            if autotest and not isredfish:
                try:
                    if not regtype == attributeregistry[instance.type]:
                        self.warning_handler("Using latest registry.\nFound: " \
                                            "%s\nUsing: %s\n" % \
                                            (attributeregistry[instance.type], \
                                             regtype))
                except Exception:
                    if not schematype == currdict[type_str]:
                        self.warning_handler("Using latest schema.\nFound: " \
                                             "%s\nUsing: %s\n" % \
                                            (currdict[type_str], \
                                             schematype))
        else:
            schematype = currdict[type_str]
            try:
                regtype = attributeregistry[instance.type]
            except Exception:
                pass
        try:
            if attributeregistry[instance.type]:
                regfound = validation_manager.find_prop(regtype)
                biosmode = True
                biosschemafound = validation_manager.find_prop(schematype)

                if biosschemafound and isredfish and not \
                                isinstance(biosschemafound, RepoRegistryEntry):
                    biosschemafound = self.get_handler(biosschemafound['@odata.id'], \
                                verbose=False, service=True, silent=True).obj
                    biosschemafound = RepoRegistryEntry(biosschemafound)

        except Exception:
            regfound = validation_manager.find_prop(schematype)

        if regfound and isredfish and not isinstance(regfound, RepoRegistryEntry):
            regfound = self.get_handler(regfound['@odata.id'], \
                                verbose=False, service=True, silent=True).obj
            regfound = RepoRegistryEntry(regfound)

        if not regfound:
            self.warn("Unable to locate registry/schema for '%s'", \
                                                            currdict[type_str])
            return None, None, None
        elif float(iloversion) >= 4.210:
            try:
                locationdict = self.geturidict(regfound.Location[0])
                self.check_type_and_download(self.current_client.monolith, \
                                locationdict, skipcrawl=True, loadtype='ref')

                if biosschemafound:
                    locationdict = self.geturidict(biosschemafound.Location[0])
                    self.check_type_and_download(self.current_client.monolith, \
                                 locationdict, skipcrawl=True, loadtype='ref')
            except Exception as excp:
                raise excp

        if not nomodel:
            if biosmode:
                if float(iloversion) >= 4.210:
                    model = regfound.get_registry_model_bios_version(\
                        currdict=currdict, monolith=self.current_client.monolith)

                if biosschemafound:
                    bsmodel = biosschemafound.get_registry_model(\
                        currdict=currdict, monolith=self.current_client.monolith, \
                        latestschema=latestschema)
                if not biosschemafound and not model:
                    model = regfound.get_registry_model_bios_version(currdict)
            else:
                if float(iloversion) >= 4.210:
                    model = regfound.get_registry_model(currdict=currdict, \
                                        monolith=self.current_client.monolith, \
                                        newarg=newarg, latestschema=latestschema)
                else:
                    model = regfound.get_registry_model(currdict)

            return model, biosmode, bsmodel

    def geturidict(self, locationobj):
        """Return the external reference link.

        :param locationobj: location of the dict
        :type locationobj: dict
        """
        if self.typepath.defs.isgen10:
            try:
                return locationobj["Uri"]
            except Exception:
                raise InvalidPathError("Error accessing Uri path!/n")
        elif self.typepath.defs.isgen9:
            try:
                return locationobj["Uri"]["extref"]
            except Exception:
                raise InvalidPathError("Error accessing extref path!/n")

    def getgen(self, gen=None, url=None, username=None, password=None):
        """Updates the defines object based on the iLO manager version"""
        if self.typepath.adminpriv is False and url.startswith("blob"):
            raise UserNotAdminError("")
        self.typepath.getgen(gen=gen, url=url, username=username, \
                                        password=password, logger=self.logger)

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

    #TODO: need to see if we do have a dependency on the verbose flag here
    def checkpostpatch(self, body=None, path=None,\
                        service=False, url=None, sessionid=None, headers=None, \
                        iloresponse=False, silent=False, patch=False):
        """Make the post file compatible with the system generation

        :param body: contents to be checked
        :type body: str.
        :param path: The URL location to check
        :type path: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
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

    def checkselectforgen(self, query):
        """Changes the query to match the Generation's HP string.

        :param query: query to be changed to match Generation's HP string
        :type query: str
        :returns: returns a modified query matching the Generation's HP string.

        """
        query = query.lower()
        returnval = query

        if self.typepath.defs.isgen9:
            if query.startswith(("hpeeskm", "#hpeeskm")) or \
                                    query.startswith(("hpeskm", "#hpeskm")):
                returnval = self.typepath.defs.hpeskmtype
            elif 'bios.' in query[:9].lower():
                returnval = self.typepath.defs.biostype
            elif query.startswith(("hpe", "#hpe")):
                returnval = query[:4].replace("hpe", "hp")+query[4:]
        else:
            if query.startswith(("hpeskm", "#hpeskm")) or \
                                    query.startswith(("hpeeskm", "#hpeeskm")):
                returnval = self.typepath.defs.hpeskmtype
            elif 'bios.' in query[:9].lower():
                returnval = self.typepath.defs.biostype
            elif not query.startswith(("hpe", "#hpe")):
                returnval = query[:3].replace("hp", "hpe")+query[3:]

        return returnval

    def latestschemahelper(self, currdict, validation_manager):
        """Finds the latestschema for a dictionary.

        :param currdict: dictionary of type to check for schema
        :type currdict: dict
        :param validation_manager: validation manager object.
        :type validation_manager: validation object.
        :returns: returns the schematype and regtype found for the dict.

        """
        regtype = None
        type_str = self.current_client.monolith._typestring
        isredfish = self.current_client.monolith.is_redfish
        href_str = self.current_client.monolith._hrefstring

        schematype = currdict[type_str].split('.')[0] + '.'
        reglist = list(validation_manager.iterregmems())

        if isredfish:
            schematype = schematype[1:-1]

            regs = [x[href_str] for x in reglist if\
                    'biosattributeregistry' in x[href_str].lower()]
            i = [reglist.index(x) for x in reglist if \
                            'biosattributeregistry' in x[href_str].lower()]
            regs = list(zip(regs, i))
        else:
            for item in list(validation_manager.itermems()):
                if item and item['Schema'].startswith(schematype):
                    schematype = item['Schema']
                    break

            regs = [x['Schema'] for x in reglist if x['Schema']\
                    .lower().startswith('hpbiosattributeregistry')]
            i = [reglist.index(x) for x in reglist if x['Schema']\
                 .lower().startswith('hpbiosattributeregistry')]
            regs = list(zip(regs, i))

        for item in sorted(regs, reverse=True):
            if isredfish:
                reg = self.get_handler(reglist[item[1]][href_str], \
                            verbose=False, service=True, silent=True).dict
            else:
                reg = reglist[item[1]]
            locationdict = self.geturidict(reg['Location'][0])
            extref = self.get_handler(locationdict, verbose=False, \
                                                service=True, silent=True)

            if extref:
                if isredfish:
                    regtype = item[0].split('/')
                    regtype = regtype[len(regtype)-2]
                else:
                    regtype = item[0]
                break
        return schematype, regtype
