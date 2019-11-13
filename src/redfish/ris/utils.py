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
"""Utility functions for internal and external use."""
import re
import sys
import copy
import logging
import itertools

from collections import Mapping

import jsonpath_rw

from six import iterkeys, string_types

from redfish.ris.rmc_helper import IncorrectPropValue

#---------Debug logger---------

LOGGER = logging.getLogger()

#---------End of debug logger---------

def warning_handler(msg):
    """Helper function for handling warning messages appropriately

    :param msg: The warning message.
    :type msg: str.

    """
    if LOGGER.getEffectiveLevel() == 40:
        sys.stderr.write(msg)
    else:
        LOGGER.warning(msg)

def validate_headers(instance, verbose=False):
    """Validates an instance is patchable

    :param instance: instance of the property to check
    :type instance: RisMonolithMemberv100
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
                        warning_handler('Skipping read-only path: %s\n' % \
                                             instance.resp.request.path)
                    skip = True
    except:
        pass
    return skip

def merge_dict(currdict, newdict):
    """Merges dictionaries together

    :param currdict: current selection dictionary.
    :type currdict: dict.
    :param newdict: new selection dictionary.
    :type newdict: dict.

    """
    for k, itemv2 in list(newdict.items()):
        itemv1 = currdict.get(k)

        if isinstance(itemv1, Mapping) and isinstance(itemv2, Mapping):
            merge_dict(itemv1, itemv2)
        else:
            currdict[k] = itemv2

def get_errmsg_type(results):
    """Return the registry type of a response
    :param resuts: rest response.
    :type results: RestResponse.
    :returns: returns a Registry Id type string, None if not match is found, or no_id if the
              response is not an error message
    """

    message_type = None
    try:
        jsonpath_expr = jsonpath_rw.parse('$..MessageId')
        messageid = [match.value for match in jsonpath_expr.find(results.dict)]
        if not messageid:
            jsonpath_expr = jsonpath_rw.parse('$..MessageID')
            messageid = [match.value for match in jsonpath_expr.find(results.dict)]
        if messageid:
            message_type = messageid[0].split('.')[0]
    except:
        pass

    return message_type

def filter_output(output, sel, val):
    """Filters a list of dictionaries based on a key:value pair

    :param output: output list.
    :type output: list.
    :param sel: the key for the property to be filtered by.
    :type sel: str.
    :param val: value for the property be filtered by.
    :type val: str.
    :returns: returns an filtered list from output parameter

    """
    #TODO: check if this can be replaced by navigatejson
    newoutput = []
    if isinstance(output, list):
        for entry in output:
            if isinstance(entry, dict):
                if '/' in sel:
                    sellist = sel.split('/')
                    newentry = copy.copy(entry)

                    for item in sellist:
                        if item in list(newentry.keys()):
                            if item == sellist[-1] and str(newentry[item]) == str(val):
                                newoutput.append(entry)
                            else:
                                newentry = newentry[item]
                else:
                    if sel in list(entry.keys()) and entry[sel] == val:
                        newoutput.append(entry)
            else:
                return output

    return newoutput

def checkallowablevalues(newdict=None, oridict=None):
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
                        res = [val for val in match.value if mat.value.lower() == val.lower()]
                        if not res:
                            raise IncorrectPropValue("Incorrect Value "\
                                "entered. Please enter one of the below "\
                                "values for {0}:\n{1}".format \
                                ('/'.join(checkpath.split('.')), str(match.value)[1:-1]))

def navigatejson(selector, currdict, val=None):
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
    getkey = lambda cdict, sel: next((item for item in iterkeys(cdict) \
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
                returnseldict = navigatejson(correctcase, items)
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
                merge_dict(temp_dict, selsdict)
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
        merge_dict(temp_dict, selsdict)
    return temp_dict

def iterateandclear(dictbody, proplist):
    """Iterate over a dictionary and remove listed properties

    :param dictbody: json body
    :type dictbody: dictionary or list
    :param proplist: property list
    :type proplist: list
    """
    if isinstance(dictbody, dict):
        _ = [dictbody.pop(key) for key in proplist if key in dictbody]
        for key in dictbody:
            dictbody[key] = iterateandclear(dictbody[key], proplist)
    if isinstance(dictbody, list):
        for ind, val in enumerate(dictbody):
            dictbody[ind] = iterateandclear(val, proplist)
    return dictbody

def skipnonsettingsinst(instances):
    """helper function to remove non /settings section

    :param instances: list of RisMonolithMemberv100 instances to check for settings paths.
    :type instances: list.
    :returns: returns list of RisMonolithMemberv100 setting instances
    """
    instpaths = [inst.path.lower() for inst in instances]
    cond = list(itertools.ifilter(lambda x: x.endswith(("/settings", \
                                                "settings/")), instpaths))
    paths = [path.split('settings/')[0].split('/settings')[0] \
                                                for path in cond]
    newinst = [inst for inst in instances if inst.path.lower() not in paths]
    return newinst

def getattributeregistry(instances, adict=None):
    #add try except return {} after test
    """Get attribute registry in given instances

    :param instances: list of RisMonolithMemberv100 instances to be checked for attribute.
    :type instances: list.
    :param adict: A dictionary containing an AttributeRegistry
    :type adict: dict.
    :return: returns a dictionary containing the attribute registry string(s)
    """
    if adict:
        return adict.get("AttributeRegistry", None)
    return {inst.maj_type:inst.resp.obj["AttributeRegistry"]\
            for inst in instances if 'AttributeRegistry' in inst.resp.dict}

def diffdict(newdict=None, oridict=None, settingskipped=[False]):
    """Diff's two dicts, returning the value differences

    :param newdict: selection dictionary with required changes.
    :type newdict: dict.
    :param oridict: selection dictionary with current state.
    :type oridict: dict.
    :param settingskipped: flag to determine if any settings were missing
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
        warning_handler("Skipping property {0}, not " \
                         "found in current server.\n".format(kis))
        settingskipped = [True]
    for key, val in list(newdict.items()):
        if key not in oridict:
            keycase = oridictkeys[oridictkeyslower.index(key.lower())]
            del newdict[key]
            key = keycase
            newdict[key] = val
        if isinstance(val, dict):
            res = diffdict(newdict[key], oridict[key])
            if res:
                newdict[key] = res
            else:
                del newdict[key]
        elif isinstance(val, list):
            if len(val) == 1 and isinstance(val[0], dict):
                res = diffdict(newdict[key][0], oridict[key][0], settingskipped)
                if res:
                    newdict[key][0] = res
                else:
                    del newdict[key]
            if [li for li in val if not isinstance(li, string_types)]:
                continue
            else:
                if [va.lower() for va in val] == [va.lower() if va else va \
                                                  for va in oridict[key]]:
                    del newdict[key]
        #TODO: check if lowercase is correct or buggy for string types
        elif isinstance(val, (string_types, int, type(None))):
            if newdict[key] == oridict[key]:
                del newdict[key]

    return newdict
