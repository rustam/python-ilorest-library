###
# Copyright 2019 Hewlett Packard Enterprise, Inc. All rights reserved.
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
import sys
import time
import copy
import shutil
import logging

from collections import OrderedDict

import six
import jsonpatch
import jsonpointer
import redfish.ris.gen_compat
import redfish.ris.validation

from redfish.rest.v1 import RestClient
from redfish.ris.ris import SessionExpired, RisMonolith
from redfish.ris.validation import ValidationManager, Typepathforval
from redfish.ris.resp_handler import ResponseHandler
from redfish.ris.utils import merge_dict, getattributeregistry, diffdict, \
                        navigatejson, iterateandclear, skipnonsettingsinst, warning_handler, \
                        validate_headers, checkallowablevalues
from redfish.ris.rmc_helper import (UndefinedClientError, InstanceNotFoundError, \
                        NothingSelectedError, ValidationError, RmcConfig, RmcFileCacheManager, \
                         NothingSelectedSetError, LoadSkipSettingError, ValueChangedError, \
                         IloResponseError, EmptyRaiseForEAFP)

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
        self.logger = LOGGER
        self.redfishinst = None
        self._config = RmcConfig()
        self._cm = RmcFileCacheManager(self)
        self._monolith = None
        self._iloversion = None
        self._validationmanager = None
        self._selector = None
        self.verbose = False
        self.typepath = redfish.ris.gen_compat.Typesandpathdefines()
        Typepathforval(typepathobj=self.typepath)

        if "--showwarnings" not in Args:
            self.logger.setLevel(logging.WARNING)
            if self.logger.handlers and self.logger.handlers[0].name == 'lerr':
                self.logger.handlers.remove(self.logger.handlers[0])

        configfile = [Args[ind+1] for ind, arg in enumerate(Args) if arg in ('--config', '-c')]
        configfile = [arg.split("=", 1)[1] for arg in Args if \
                arg.startswith("--config=")] if not configfile else configfile
        self.config_file = [os.path.join(os.path.dirname(sys.executable), \
             'redfish.conf') if os.name == 'nt' else '/etc/ilorest/redfish.conf'][0] \
             if not configfile else configfile[0]
        if not os.path.isfile(self.config_file):
            LOGGER.warning("Config file '%s' not found\n\n", self.config_file)
    @property
    def monolith(self):
        """Get the monolith from the current client"""
        return self._monolith
    @monolith.setter
    def monolith(self, monolith):
        """Set the monolith"""
        self._monolith = monolith
    @property
    def current_client(self):
        """Get the current client"""
        if self.redfishinst:
            return self.redfishinst
        raise UndefinedClientError()
    @property
    def validationmanager(self):
        """Get the valdation manager"""
        if self.getiloversion():
            if self._validationmanager:
                self._validationmanager.reset_errors_warnings()
            else:
                monolith = self.monolith
                self._validationmanager = ValidationManager(monolith, defines=self.typepath)
            self._validationmanager.updatevalidationdata()
        else:
            self._validationmanager = None
        return self._validationmanager
    @property
    def selector(self):
        """Get the selector"""
        return self._selector
    @selector.setter
    def selector(self, sel):
        """Set the selector"""
        self._selector = sel
    @property
    def config(self):
        """Return config"""
        return self._config
    @property
    def cache(self):
        """Return config"""
        return self._config.get_cache()

    def restore(self, creds=None, enc=False):
        """Restore monolith from cache"""
        self._cm.uncache_rmc(creds=creds, enc=enc)

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

    def config_from_file(self, filename):
        """Get config from file

        :param filename: The config file name.
        :type filename: str.
        """
        self._config = RmcConfig(filename=filename)
        self._config.load()

    def login(self, username=None, password=None, base_url='blobstore://.', \
              path=None, skipbuild=False, includelogs=False, \
              biospassword=None, is_redfish=False, proxy=None, ssl_cert=None):
        """Main worker function for login command

        :param username: user name required to login to server.
        :type: str.
        :param password: password credentials required to login.
        :type password: str.
        :param base_url: redfish host name or ip address.
        :type base_url: str.
        :param path: path to initiate login to.
        :type path: str.
        :param proxy: any proxy required for connection.
        :type proxy: str.
        :param ssl_cert: path to the CA bundle or SSL certificate to use with connection.
        :type ssl_cert: str.
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

        self.typepath.getgen(url=base_url, username=username, password=password, \
                                            proxy=proxy, isredfish=is_redfish, ca_certs=ssl_cert)
        is_redfish = self.typepath.updatedefinesflag(redfishflag=is_redfish)

        if self.redfishinst and self.redfishinst.session_key:
            self.logout()

        self.redfishinst = RestClient(base_url=base_url, username=username, password=password, \
            default_prefix=self.typepath.defs.startpath, biospassword=biospassword, \
            is_redfish=is_redfish, proxy=proxy, ca_certs=ssl_cert)

        self.current_client.login()

        inittime = time.time()
        self._build_monolith(path=path, includelogs=includelogs, skipbuild=skipbuild)
        endtime = time.time()

        if self.verbose:
            sys.stdout.write("Monolith build process time: %s\n" % (endtime - inittime))
        self.save()
        if not self.monolith:
            self.monolith.update_member(resp=self.current_client.root, \
                                        path=self.typepath.defs.startpath, init=False)

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
                self.delete_handler(session[0], silent=True, service=True)
            except:
                pass
        self.redfishinst = None

        cachedir = self.config.get_cachedir()
        if cachedir:
            try:
                shutil.rmtree(cachedir)
            except Exception:
                pass

    def select(self, selector=None, fltrvals=(None, None), rel=False):
        """Selects instances based on selector and filter values

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param fltsvals: the filter values for the select operation (Key,Val).
        :type fltrvals: tuple.
        :param rel: flag to reload the selected instances.
        :type rel: boolean.
        :returns: returns a list of selected items
        """
        if selector:
            selector = self.typepath.modifyselectorforgen(selector)
            instances = self._getinstances(selector=selector, rel=rel)
            val = fltrvals[1].strip('\'\"') if isinstance(fltrvals[1], \
                                            six.string_types) else fltrvals[1]
            instances = [inst for inst in instances if not fltrvals[0] or \
                        navigatejson(fltrvals[0].split('/'), copy.deepcopy(inst.dict), val)]
            if any(instances):
                self.selector = selector
                self.save()
                return instances

        errmsg = "Unable to locate instance for '{0}' and filter '{1}={2}'". \
                    format(selector, fltrvals[0], fltrvals[1]) if fltrvals[0] \
                    and fltrvals[1] else "Unable to locate instance for {}".format(selector)

        raise InstanceNotFoundError(errmsg)

    def types(self, fulltypes=False):
        """Main function for types command

        :param fulltypes: flag to determine if types return full name.
        :type fulltypes: boolean.
        :returns: returns a list of type strings
        """
        instances = list()
        monolith = self.monolith
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

    def getprops(self, selector=None, props=None, nocontent=None, \
                            skipnonsetting=True, remread=False, insts=None):
        """Gets properties from a specified selector

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
        if props:
            noprop = {prop:False for prop in props} if props else {}
        instances = insts if insts else self._getinstances(selector=selector)
        instances = skipnonsettingsinst(instances) if skipnonsetting else instances

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
                    propsdict = navigatejson(prop.split('/'), copydict)
                    if propsdict is None:
                        continue
                    noprop[prop] = True
                    merge_dict(temp_dict, propsdict)
                if temp_dict:
                    results.append(temp_dict)
            else:
                results.append(currdict)
        if props:
            _ = [nocontent.add(prop) for prop in props if not noprop[prop]]
        return results

    def info(self, selector=None, props=None, ignorelist=None, dumpjson=False, \
                            latestschema=False):
        """Main function for info command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param props: the type selection for the get operation.
        :type props: str.
        :param ignorelist: list that contains keys to be removed from output.
        :type ignorelist: list.
        :param dumpjson: flag to determine if output should be printed out.
        :type dumpjson: boolean.
        :param autotest: flag to determine if this part of automatic testing.
        :type autotest: boolean.
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
        instances = self._getinstances(selector)
        attributeregistry = getattributeregistry(instances)
        instances = skipnonsettingsinst(instances)

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for inst in instances:
            bsmodel = None
            currdict = inst.resp.dict
            proppath = inst.resp.getheader('Link').split(';')[0].strip('<>') \
                    if inst.resp.getheader('Link') else None
            seldict = {}
            if not props:
                currdict = currdict['Attributes'] if inst.maj_type.\
                    startswith(self.typepath.defs.biostype) and currdict.get('Attributes'\
                                                     , None) else currdict
                results.update([key for key in currdict if key not in \
                                ignorelist and not '@odata' in key.lower()])
                continue
            if isinstance(props, six.string_types):
                props = props.split('/') if '/' in props else props
                props = [props] if not isinstance(props, (list, \
                                                tuple)) else props
                seldict = navigatejson(props, copy.deepcopy(currdict))
                if seldict is None:
                    nokey = True
                    continue
            if self.typepath.defs.typestring in currdict:
                seldict[typestring] = currdict[typestring]
                model, bsmodel = self.get_model(currdict, \
                                  attributeregistry, latestschema, newarg= \
                                  props[:-1], proppath=proppath)
            if not model and not bsmodel:
                errmsg = "/".join(props)
                warning_handler("Unable to locate registry model or "\
                    "No data available for entry: {}\n".format(errmsg))
                continue
            found = model.get_validator(props[-1]) if model else None
            found = bsmodel.get_validator(props[-1]) if not found and \
                                                        bsmodel else found
            outdata = found if found and dumpjson else \
                        found.print_help(props[-1]) if found else outdata

        if outdata or results:
            return outdata if outdata else results

        errmsg = "Entry {} not found in current selection\n".format("/".\
            join(props)) if nokey else "Entry {} not found in current"\
            " selection\n".format("/".join(props))
        warning_handler(errmsg)

    def loadset(self, seldict=None, fltrvals=(None, None), diffonly=False,\
            latestschema=False, uniqueoverride=False, selector=None):
        """Optimized version of the old style of set properties

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param seldict: current selection dictionary with required changes.
        :type seldict: dict.
        :param fltsvals: the filter values of selection for the set operation
                        (Key,Val).
        :type fltrvals: tuple.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :param diffonly: flag to differentiate only existing properties.
        :type diffonly: bool.
        :param uniqueoverride: flag to determine override for unique properties.
        :type uniqueoverride: str.
        :returns: returns a status or a list of set properties
        """
        results = list()
        nochangesmade = False
        settingskipped = [False]

        selector = self.selector if not selector else selector
        instances = self.select(selector=selector, fltrvals=fltrvals)
        attributeregistry = getattributeregistry(instances=instances)
        instances = skipnonsettingsinst(instances=instances)

        if not instances or len(instances) == 0:
            raise NothingSelectedSetError()

        for instance in instances:
            if validate_headers(instance, verbose=self.verbose):
                continue
            else:
                nochangesmade = True

            currdict = instance.resp.dict
            diff_resp = diffdict(newdict=copy.deepcopy(seldict),\
                 oridict=copy.deepcopy(currdict), settingskipped=settingskipped)

            iloversion = self.getiloversion()
            if iloversion:
                proppath = instance.resp.getheader('Link').split(';')[0].\
                            strip('<>') if instance.resp.getheader('Link') \
                            else None
                self._validatechanges(instance=instance, attributeregistry=attributeregistry,\
                        newdict=diff_resp, oridict=currdict, \
                        unique=uniqueoverride, latestschema=latestschema, \
                        proppath=proppath)

            patches = jsonpatch.make_patch(currdict, diff_resp)

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

    def status(self):
        """Returns all pending changes that have not been committed yet"""
        iloversion = self.getiloversion()

        finalresults = list()
        monolith = self.monolith
        (_, _) = self.get_selection(setenable=True)
        attrreg = getattributeregistry([ele for ele in monolith.iter() if ele])
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

    def commit(self):
        """Applies all pending patches to the server

        :yields: Two strings: 1. Path being PATCHed 2. Result of the PATCH
                True:Success, False:Fail
        """

        instances = [inst for inst in self.monolith.iter() if inst.patches]

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if validate_headers(instance, verbose=self.verbose):
                continue

            currdict = dict()
            oridict = instance.resp.dict
            totpayload = dict()
            # apply patches to represent current edits
            for patches in instance.patches:
                if self._iloversion < 5.130:
                    self._checkforetagchange(instance=instance)
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
                    merge_dict(totpayload, payload)
                currdict = copy.deepcopy(totpayload)

            if currdict:
                yield instance.resp.request.path

                put_path = instance.resp.request.path
                etag = self.monolith.paths[put_path].etag
                headers = dict([('If-Match', etag)]) if self._iloversion > 5.130 else None
                try:
                    self.patch_handler(put_path, currdict, optionalpassword=\
                            self.current_client.bios_password, headers=headers)
                except IloResponseError:
                    yield True #Failure
                else:
                    yield False #Success

    def patch_handler(self, put_path, body, headers=None, response=False, silent=False, \
                  optionalpassword=None, service=False):
        """Main worker function for raw patch command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
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
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns RestResponse object containing response data
        """

        (put_path, body) = self._checkpostpatch(body=body, path=put_path, patch=True)

        if optionalpassword:
            self.current_client.bios_password = optionalpassword

        results = self.current_client.patch(put_path, body=body, headers=headers)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()

        self._modifiedpath(results, replace=True)

        # if results and getattr(results, "status", None) and results.status == 412:
        if results and hasattr(results, "status") and results.status == 412:
            self._updatemono(path=put_path, rel=True)

        if not silent:
            ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).\
                    output_resp(results, dl_reg=service, print_code=self.verbose)

        if response:
            return results

    def get_handler(self, put_path, silent=False, uncache=False, headers=None, \
                                response=False, service=False):
        """main worker function for raw get command

        :param put_path: the URL path.
        :type put_path: str.
        :param silent: flag to determine if no output should be done.
        :type silent: boolean.
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

        results = self.current_client.get(put_path, headers=headers)

        if not uncache and results.status == 200:
            self.monolith.update_member(resp=results, path=put_path, init=False)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()

        if results.status == 200:
            service = True
        if not silent:
            ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).\
                    output_resp(results, dl_reg=service, print_code=self.verbose)

        if results.status == 200 or response:
            return results

        return None

    def post_handler(self, put_path, body, headers=None, response=False, \
                             silent=False, service=False):
        """Main worker function for raw post command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse from client's Post command
        """

        (put_path, body) = self._checkpostpatch(body=body, path=put_path)

        results = self.current_client.post(put_path, body=body, headers=headers)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()

        self._modifiedpath(results)

        if not silent:
            ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).\
                    output_resp(results, dl_reg=service, print_code=self.verbose)

        if response:
            return results

    def put_handler(self, put_path, body, headers=None, response=False, silent=False, \
                optionalpassword=None, service=False):
        """Main worker function for raw put command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
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
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse object from client's Put command
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type is_redfish: boolean.
        """
        if optionalpassword:
            self.current_client.bios_password = optionalpassword
        results = self.current_client.put(put_path, body=body, headers=headers)
        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()

        self._modifiedpath(results, replace=True)

        if not silent:
            ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).\
                    output_resp(results, dl_reg=service, print_code=self.verbose)

        if response:
            return results

    def delete_handler(self, put_path, headers=None, silent=False, service=False):
        """Main worker function for raw delete command

        :param put_path: the URL path.
        :type put_path: str.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param silent: flag to disable output.
        :type silent: boolean.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse object from client's Delete command
        """

        results = self.current_client.delete(put_path, headers=headers)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()
        self._modifiedpath(results, delete=True)

        if not silent:
            ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).\
                    output_resp(results, dl_reg=service, print_code=self.verbose)

        return results

    def head_handler(self, put_path, silent=False, service=False):
        """Main worker function for raw head command

        :param put_path: the URL path.
        :type put_path: str.
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

        results = self.current_client.head(put_path)

        if results and getattr(results, "status", None) and results.status == 401:
            raise SessionExpired()

        if not silent:
            ResponseHandler(self.validationmanager, self.typepath.defs.messageregistrytype).\
                    output_resp(results, dl_reg=service, print_code=self.verbose)

        if results.status == 200:
            return results
        return None

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
            type_str = self.typepath.defs.typestring
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
            currdict = iterateandclear(currdict, templist)
            iloversion = self.getiloversion()
            if not iloversion:
                return currdict
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

    def getidbytype(self, tpe):
        """ Return a list of URIs that correspond to the supplied type string
        :param tpe: type string to search for.
        :type tpe: string.
        """
        urls = list()
        val = next(self.monolith.gettypename(tpe), None)
        urls.extend(self.monolith.typesadded[val] if val else [])
        return urls

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
        self._updatemono(currtype="ComputerSystem.", crawl=False)

        try:
            for inst in self.monolith.iter("ComputerSystem."):
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
            results = next(iter(self.getprops('Manager.', ['FirmwareVersion', 'Firmware'])))
            def quickdrill(_dict, key):
                """ function to find key in nested dictionary """
                return _dict[key]

            while isinstance(results, dict):
                results = quickdrill(results, next(iter(results.keys())))
            iloversionlist = results.replace('v', '').replace('.', '').split(' ')
            iloversion = float('.'.join(iloversionlist[1:3]))

            model = self.getprops('Manager.', ['Model'])
            if model:
                if next(iter(model))['Model'] == "iLO CM":
                    # Assume iLO 4 types in Moonshot
                    iloversion = None

            self._iloversion = iloversion
        elif not self.typepath.gencompany:#Assume schemas are available somewhere in non-hpe redfish
            self._iloversion = iloversion = 4.210

        conf = None if not skipschemas else True
        if not skipschemas:
            if iloversion and iloversion >= 4.210:
                conf = self._verifyschemasdownloaded(self.monolith)
            elif iloversion and iloversion < 4.210:
                warning_handler("Please upgrade to iLO 4 version 2.1 or above for schema support.")
            else:
                warning_handler("Schema support unavailable on the currently logged in system.")

        return iloversion if iloversion and iloversion >= 4.210 and conf else None

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
        instances = self._getinstances(selector=selector, rel=reloadpath)
        if setenable:
            attributeregistryfound = getattributeregistry(instances=instances)
            instances = skipnonsettingsinst(instances=instances)
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
        monolith = self.monolith
        selector = self.selector if not selector else selector
        if not selector and not selectignore:
            return instances

        self._updatemono(currtype="ComputerSystem.", crawl=False)
        self._updatemono(currtype=self.typepath.defs.biostype, crawl=False)
        self._updatemono(currtype="Manager.", crawl=False)

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

    def download_path(self, paths, crawl=True, rel=False):
        """Loads a path into monolith

        :param paths: list of paths to download
        :type paths: list
        :param rel: flag to reload the paths or not.
        :type rel: bool.
        :param crawl: flag to determine if load should traverse found links.
        :type crawl: boolean.
        """
        if not paths:
            return
        try:
            map(lambda x: self.monolith.load(path=x, init=False, rel=rel,\
                  crawl=crawl, includelogs=True), paths)
        except Exception as excp:
            try:
                if excp.errno == 10053:
                    raise SessionExpired()
            except:
                raise excp
            else:
                raise excp

    def get_model(self, currdict, attributeregistry, latestschema=None, newarg=None, proppath=None):
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
        :returns: returns model model, bios model
        """
        type_str = self.typepath.defs.typestring
        bsmodel = None
        valobj = self.validationmanager
        model = valobj.get_registry_model(currtype=currdict[type_str], \
                newarg=newarg, latestschema=latestschema, proppath=proppath)
        if not attributeregistry and model:
            return model, bsmodel
        if not model and not attributeregistry:
            LOGGER.warning("Unable to locate registry/schema for %s", currdict[type_str])
            return None, None
        attrval = currdict.get("AttributeRegistry", None)
        attrval = list(attributeregistry.values())[0] if not attrval and \
                                        attributeregistry else attrval
        bsmodel = valobj.get_registry_model(currtype=attrval if attrval else \
                                    currdict[type_str], newarg=newarg, \
                                    latestschema=latestschema, searchtype=\
                                    self.typepath.defs.attributeregtype)
        return model, bsmodel

    def _build_monolith(self, path=None, includelogs=False, skipbuild=False):
        """Run through the RIS tree to build monolith

        :param path: path to initiate login to.
        :type path: str.
        :param includelogs: flag to determine id logs should be downloaded.
        :type includelogs: boolean.
        :param skipbuild: if true, skip build of monolith (initialize empty)
        :type skipbuild: True
        """
        self.monolith = RisMonolith(self.current_client, self.typepath)
        if not skipbuild:
            self.monolith.load(path=path, includelogs=includelogs, init=True)
            self.monolith.populatecollections()
        else:
            self.monolith.update_member(resp=self.current_client.root, \
                                        path=self.current_client.default_prefix,\
                                        init=False)

    def _modifiedpath(self, results, delete=False, replace=False):
        """Check the path and set the modified flag

        :param delete: Flag to delete the path in the results
        :type delete: bool
        :param replace: Flag to replace the path from the results
        :type replace: bool
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

    def _checkforchange(self, paths, crawl=True):
        """Check if the given paths have been modified and updates monolith if it has

        :param paths: paths to be checked
        :type paths: list
        """
        (pathtoetag, _) = self._gettypeswithetag()
        mono = self.monolith
        self.download_path(list(paths), crawl=crawl, rel=True)
        etags = [None if not path in mono.paths else mono.paths[path].etag for path in paths]
        sametag = [path for ind, path in enumerate(paths) if path in pathtoetag\
            and path in self.monolith.paths and pathtoetag[path] != etags[ind]]
        for path in sametag:
            self.monolith.paths[path].patches = []
        if sametag:
            LOGGER.warning('The data in the following paths have been updated. '\
                    'Recheck the changes made to made. %s', ','.join([str(path) for \
                                                                                path in sametag]))

    def _updatemono(self, currtype=None, path=None, crawl=False, rel=False):
        """Check if type/path exists in current monolith

        :param entrytype: the found entry type.
        :type entrytype: str.
        :param currtype: the current entry type.
        :type currtype: str.
        :param crawl: flag to determine if load should traverse found links.
        :type crawl: boolean.
        """
        monolith = self.monolith
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
                    paths.update(monolith.checkmodified(path) if path in monolith.ctree else set())
        elif path:
            if monolith.paths and not monolith.paths.keys()[0][-1] == '/':
                path = path[:-1] if path[-1] == '/' else path
            if rel or not monolith.path(path):
                paths.add(path)
            if path in monolith.paths and monolith.paths[path].modified:
                paths.add(path)
                paths.update(monolith.checkmodified(path) if path in monolith.ctree else set())
        if paths:
            self._checkforchange(list(paths), crawl=crawl)

    def _verifyschemasdownloaded(self, monolith):
        """Function to verify that the schema has been downloaded

        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        """

        schemaid = self.typepath.schemapath
        regid = self.typepath.regpath

        if not (schemaid and regid):
            warning_handler("Missing Schemas or registries.")
            return None

        schemacoll = next(monolith.gettypename(self.typepath.defs.schemafilecollectiontype), None)
        if not schemacoll or any(paths.lower() == schemaid and \
                                 monolith.paths[paths] \
               for paths in monolith.typesadded[schemacoll]):
            self.download_path([schemaid], crawl=False)
            schemacoll = next(monolith.gettypename(\
                        self.typepath.defs.schemafilecollectiontype), None)

        regcoll = next(monolith.gettypename(self.typepath.defs.regfilecollectiontype), None)
        if not regcoll or any(paths.lower() == regid and monolith.paths[paths] \
               for paths in monolith.typesadded[regcoll]):
            self.download_path([regid], crawl=False)
            regcoll = next(monolith.gettypename(self.typepath.defs.regfilecollectiontype), None)

        return any(paths.lower() in (schemaid.lower(), regid.lower()) and \
            monolith.paths[paths] for paths in monolith.paths)

    def _validatechanges(self, instance=None, attributeregistry=None, latestschema=None, \
                        proppath=None, newdict=None, oridict=None, unique=False):
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
        :param attrreg: Registry entry of the given attribute.
        :type attrreg: RepoRegistryEntry.
        """
        entrymono = self.monolith
        currtype = oridict[self.typepath.defs.typestring]
        validation_manager = self.validationmanager
        validation_manager.validatedict(newdict, \
            currtype=attributeregistry[instance.maj_type]\
            if attributeregistry else currtype, monolith=entrymono, \
            unique=unique, searchtype=self.typepath.defs.attributeregtype\
            if attributeregistry else None, latestschema=latestschema, \
            proppath=proppath)

        validation_errors = validation_manager.errors
        for warninngs in validation_manager.warnings:
            warning_handler(warninngs)
        if validation_errors and len(validation_errors) > 0:
            raise ValidationError(validation_errors)
        checkallowablevalues(newdict=newdict, oridict=oridict)

    def _getinstances(self, selector=None, rel=False, crawl=False):
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
        instances = list()
        selector = self.selector if not selector else selector
        if selector:
            selector = ".".join(selector.split('#')[-1].split(".")[:2])
            self._updatemono(currtype=selector, crawl=crawl, rel=rel)
        if not selector:
            return instances
        selector = None if selector == '"*"' else selector
        instances = [inst for inst in self.monolith.iter(selector) \
                            if inst.maj_type not in ['object', 'string']]
        _ = [setattr(inst, 'patches', []) for inst in instances if rel]
        return instances

    def _checkpostpatch(self, body=None, path=None, patch=False):
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
                results = self.get_handler(put_path=path, service=True, silent=True)
                if results and results.status == 200:
                    if results.dict:
                        if "Target" in body:
                            actions = results.dict["Oem"][self.typepath.defs.oemhp]["Actions"]
                        elif "Actions" in body:
                            actions = results.dict["Actions"]
                        else:
                            return (path, body)

                    allkeys = list(actions.keys())
                    targetkey = [x for x in allkeys if x.endswith(body["Action"])]

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

    def _checkforetagchange(self, instance=None):
        """Function to check the status of the etag

        :param instance: retrieved instance to check etag for change.
        :type instance: dict.
        """
        if instance:
            path = instance.path
            (oldtag, _) = self._gettypeswithetag()
            self._updatemono(path=path, rel=True)
            (newtag, _) = self._gettypeswithetag()
            if (oldtag[path] != newtag[path]) and \
                        not self.typepath.defs.hpilodatetimetype in instance.maj_type:
                warning_handler("The property you are trying to change " \
                                 "has been updated. Please check entry again " \
                                 " before manipulating it.\n")
                raise ValueChangedError()

    def _gettypeswithetag(self):
        """Gathers etags of all paths in monolith and their type associations"""
        instancepath = dict()
        instances = dict()

        for inst in self.monolith.iter():
            instancepath[inst.path] = inst.maj_type
            instances[inst.path] = inst.etag

        return [instances, instancepath]
