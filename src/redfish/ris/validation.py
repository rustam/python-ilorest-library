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
"""RIS Schema classes"""

# ---------Imports---------

import re
import json
import locale
import logging
import textwrap

import six

from redfish.rest.v1 import (RisObject)
from .sharedtypes import JSONEncoder

# ---------End of imports---------


# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)

# ---------End of debug logger---------


class SchemaValidationError(Exception):
    """Schema Validation Class Error"""
    pass

class RegistryValidationError(Exception):
    """Registration Validation Class Error"""
    def __init__(self, msg, regentry=None, selector=None):
        super(RegistryValidationError, self).__init__(msg)
        self.reg = regentry
        self.sel = selector

class UnknownValidatorError(Exception):
    """Raised when we find an attribute type that we don't know how to
    validate. """
    pass

class ValidationManager(object):
    """Keep track of all the schemas and registries and provides helpers
    to simplify validation """
    def __init__(self, monolith, defines=None):
        super(ValidationManager, self).__init__()

        if monolith.is_redfish:
            self._schemaid = ["/redfish/v1/schemas/?$expand=.", "Members"]
            self._regid = ["/redfish/v1/registries/?$expand=.", "Members"]
        else:
            self._schemaid = ["/rest/v1/schemas", "Items"]
            self._regid = ["/rest/v1/registries", "Items"]

        self._classes = list()
        #type and path defines object
        self.defines = defines
        self.monolith = monolith
        # error
        self._errors = list()
        self._warnings = list()
        self.new_load_file(monolith)

    def new_load_file(self, monolith):
        """Loads the types from monolith.

        :param monolith: full data model retrieved from server.
        :type monolith: dict.

        """
        classesdataholders = []

        for instance in monolith.iter():
            if instance.type.startswith(self.defines.defs.schemafilecollectiontype)\
                or instance.type.startswith(self.defines.defs.regfilecollectiontype)\
                                or instance.type.startswith("Collection."):
                if self._schemaid[0] in instance.path.lower() \
                                    or self._regid[0] in instance.path.lower():
                    classesdataholders.append(instance.resp.dict)

        try:
            for classesdataholder in classesdataholders:
                if monolith._typestring in classesdataholder and ('Collection.' in \
                                        classesdataholder[monolith._typestring] or \
                                        (self.defines.defs.schemafilecollectiontype\
                                        in classesdataholder[monolith._typestring] \
                                        and monolith.is_redfish)):
                    newclass = RepoRegistryEntry.parse(classesdataholder)

                    self._classes.append(newclass)
        except BaseException:
            pass

    def validate(self, item, currdict=None, monolith=None, \
                                regloc=None, attrreg=None, unique=None):
        """Search for matching schemas and attribute registries and
        ensure that item is valid.

        :param item: the item to be validated.
        :type item: str.
        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param unique: flag to determine override for unique properties.
        :type unique: str.
        :param attrreg: Registry entry of the given attribute.
        :type attrreg: RepoRegistryEntry.
        :param regloc: path to registry location.
        :type regloc: str.

        """
        if regloc and not attrreg:
            attrreg = RepoRegistryEntry(regloc)
        elif not attrreg:
            attrreg = self.find_prop(item[monolith._typestring])

        if attrreg:
            try:
                (self._errors, self._warnings) = attrreg.validate(item, self._errors,\
                                        currdict=currdict, monolith=monolith, \
                                        unique=unique, warnings=self._warnings)
            except:
                return attrreg

    def bios_validate(self, item, regname, currdict=None, \
                                                monolith=None, unique=None):
        """BIOS Search for matching schemas and attribute registries and
        ensure that item is valid

        :param item: the item to be validated.
        :type item: str.
        :param regname: string containing the registry name.
        :type regname: str.
        :param unique: flag to determine override for unique properties.
        :type unique: str.
        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.

        """
        attrreg = self.find_prop(regname)
        try:
            attrreg = RepoRegistryEntry(attrreg)
        except:
            pass
        if attrreg:
            (self._errors, self._warnings) = attrreg.validate_bios_version(item, \
                                self._errors, currdict=currdict, unique=unique,\
                                monolith=monolith, warnings=self._warnings)


    def find_prop(self, propname):
        """Searches through all locations and returns the first schema
        found for the provided type

        :param propname: string containing the schema name.
        :type propname: str.

        """
        for cls in self._classes:
            found = cls.find_property(propname)
            if found:
                return found
        return None

    def get_errors(self):
        """Return a list of errors encountered"""
        return self._errors

    def get_warnings(self):
        """Return a list of warnings encountered"""
        return self._warnings

    def itermems(self, membername=None):
        """Searches through all locations and yields each entry

        :param membername: string containing the schema/registry name.
        :type membername: str.

        """
        if not membername:
            membername = self.defines.defs.collectionstring
        for items in self._classes:
            for item in items[membername]:
                yield item

    def iterregmems(self, membername=None):
        """Searches through all locations and yields each entry

        :param membername: string containing the registry name.
        :type membername: str.

        """
        if not membername:
            membername = self.defines.defs.collectionstring
        for items in self._classes:
            if items[self.monolith._typestring].startswith((\
                self.defines.defs.regfilecollectiontype, 'Collection.1.0.0')):
                for item in items[membername]:
                    yield item

    def iterschemamems(self, membername=None):
        """Searches through all locations and yields each entry

        :param membername: string containing the schema name.
        :type membername: str.

        """
        if not membername:
            membername = self.defines.defs.collectionstring
        for items in self._classes:
            if items[self.monolith._typestring].startswith((\
                self.defines.defs.schemafilecollectiontype, 'Collection.1.0.0')):
                for item in items[membername]:
                    yield item

class RepoRegistryEntry(RisObject):
    """Represents an entry in the registry"""
    def __init__(self, d):
        super(RepoRegistryEntry, self).__init__(d)

    def find_property(self, propname):
        """Returns iLO/BIOS registries/schemas

        :param propname: string containing the registry name.
        :type propname: str.
        :returns: returns iLO/BIOS registries/schemas

        """
        result = None
        if checkattr(self, 'Items') and isinstance(self.Items, list):
            for entry in self.Items:
                #equal/in was changed to startswith for propname comparision.
                if entry and 'Schema' in entry and \
                        entry['Schema'].lower().startswith(propname.lower()):
                    regentry = RepoRegistryEntry.parse(entry)
                    result = regentry
                    break
        elif checkattr(self, 'Members') and isinstance(self.Members, list):
            splitname = propname.split('.')[-1]
            for entry in self.Members:
                if 'Schema' in entry:
                    if entry and 'Schema' in entry and \
                            propname.lower() in entry['Schema'].lower():
                        regentry = RepoRegistryEntry.parse(entry)
                        result = regentry
                        break
                #This is only for registry.
                elif 'Registry' in entry:
                    if entry and 'Registry' in entry and entry['Registry'].lower()\
                                            == propname.lower():
                        regentry = RepoRegistryEntry.parse(entry)
                        result = regentry
                        break
                else:
                    if entry and '@odata.id' in entry:
                        reglink = entry['@odata.id'].split('/')
                        reglink = reglink[len(reglink)-2]
                        if splitname.lower() == reglink.lower():
                            result = entry
                            break

        return result

    def validate(self, tdict, errlist=None, currdict=None, \
                        warnings=None, monolith=None, reg=None, unique=None):
        """Load the schema file and validate tdict against it

        :param tdict: the dictionary to test against.
        :type tdict: dict.
        :param errlist: list containing found errors.
        :type errlist: list.
        :param warnings: list containing found warnings.
        :type warnings: list.
        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param unique: flag to determine override for unique properties.
        :type unique: str.
        :param reg: Registry entry of the given attribute.
        :type reg: dict.
        :returns: returns an error list.

        """
        if not reg:
            reg = self.get_registry_model(errlist=errlist, currdict=currdict, \
                                                            monolith=monolith)

        if reg:
            list(map(lambda x: self.checkreadunique(tdict, x, reg=reg, \
                                warnings=warnings, unique=unique), list(tdict.keys())))
            orireg = reg.copy()
            ttdict = {ki:val for ki, val in list(tdict.items()) if not isinstance(val, (dict, list))}
            results = reg.validate_attribute_values(ttdict)
            errlist.extend(results)

            for ki, val in list(tdict.items()):
                if ki in ttdict:
                    tdict[ki] = ttdict[ki]
                    continue
                reg = orireg.copy()
                valexists = False
                if val and isinstance(val, list):
                    valexists = True
                    #TODO: only validates if its a single dict within list
                    if len(val) == 1 and isinstance(val[0], dict):
                        treg = self.nestedreg(reg=reg, args=[ki])
                        self.validate(val, errlist=errlist, unique=unique,\
                              warnings=warnings, monolith=monolith, reg=treg)
                    else:
                        continue
                elif val and isinstance(val, dict):
                    valexists = True
                    treg = self.nestedreg(reg=reg, args=[ki])
                    self.validate(val, errlist=errlist, warnings=warnings,\
                                  monolith=monolith, reg=treg, unique=unique)
                if not val and valexists:
                    del tdict[ki]
        else:
            errlist.append(RegistryValidationError('Unable to locate ' \
                                                            'registry model'))

        return (errlist, warnings)

    def checkreadunique(self, tdict, tkey, reg=None, warnings=None, unique=None):
        """Check for and remove the readonly and unique attributes if required.

        :param tdict: the dictionary to test against.
        :type tdict: dict.
        :param tkey: The attribute key value to be tested.
        :type tkey: str.
        :param warnings: list containing found warnings.
        :type warnings: list.
        :param unique: flag to determine override for unique properties.
        :type unique: str.
        :param reg: Registry entry of the given attribute.
        :type reg: dict.
        :returns: returns boolean.

        """
        try:
            if reg[tkey].readonly:
                warnings.append("Property is read-only "   \
                                    "skipping '%s'\n" % str(tkey))
                del tdict[tkey]
                return True
        except:
            pass
        try:
            if reg["ReadOnly"] is True:
                warnings.append("Property is read-only "   \
                                "skipping '%s'\n" % str(tkey))
                del tdict[tkey]
                return True
        except:
            pass
        try:
            if reg["IsSystemUniqueProperty"] is True and not unique:
                warnings.append("Property is unique to " \
                     "the system skipping '%s'\n" % str(tkey))
                del tdict[tkey]
                return True
        except BaseException:
            pass

    def validate_bios_version(self, tdict, errlist=None,\
                  currdict=None, monolith=None, unique=None, warnings=None):
        """BIOS VERSION. Load the schema file and validate tdict against it

        :param tdict: the dictionary to test against.
        :type tdict: dict.
        :param errlist: list containing found errors.
        :type errlist: list.
        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param warnings: list containing found warnings.
        :type warnings: list.
        :param unique: flag to determine override for unique properties.
        :type unique: str.
        :returns: returns an error list

        """
        reg = self.get_registry_model_bios_version(errlist=errlist, \
                                           currdict=currdict, monolith=monolith)

        if reg:
            list(map(lambda x: self.checkreadunique(tdict, x, reg=reg, \
                                warnings=warnings, unique=unique), list(tdict.keys())))
            results = reg.validate_att_val_bios(tdict)
            errlist.extend(results)
        else:
            errlist.append(RegistryValidationError('Unable to locate ' \
                                                            'registry model'))

        return (errlist, warnings)

    def get_registry_model(self, currdict=None, monolith=None, errlist=None, \
           skipcommit=False, searchtype=None, newarg=None, latestschema=None):
        """Load the schema file and find the registry model if available

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param errlist: list containing found errors.
        :type errlist: list.
        :param skipcommit: flag to determine if commit should be skipped.
        :type skipcommit: boolean.
        :param searchtype: classifier for the current search.
        :type searchtype: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :returns: returns registry model

        """
        if not errlist:
            errlist = list()

        if not checkattr(self, 'Location'):
            errlist.append(RegistryValidationError(
                'Location property does not exist'))
            return None

        currloc = None
        defloc = "en"
        langcode = list(locale.getdefaultlocale())

        if not langcode[0]:
            langcode[0] = "en"

        for loc in self.Location:
            locationlanguage = loc["Language"].lower()
            locationlanguage = locationlanguage.replace("-", "_")

            if locationlanguage in langcode[0].lower():
                currloc = loc
                break

        if not currloc:
            # use default location if lang doesn't match
            currloc = defloc

        if not currloc:
            errlist.append(RegistryValidationError('Unable to determine ' \
                                                                    'location'))
            return None

        if not searchtype:
            searchtype = "object"

        location_file = None
        if currdict and monolith:
            itemtype = monolith.gettypename(searchtype.lower())
            if itemtype:
                for instance in monolith.itertype(itemtype):
                    try:
                        if monolith.is_redfish and 'title' in instance.\
                                    resp.dict and not instance.resp.dict\
                                                ["title"].startswith('#'):
                            currtype = currdict[instance._typestring].\
                                                            split('#')[-1]
                            currtype = currtype.split('.')[0] + '.'
                        else:
                            currtype = currdict[instance._typestring]

                        if latestschema:
                            if monolith.is_redfish and 'title' in instance.\
                                    resp.dict and not instance.resp.dict\
                                                ["title"].startswith('#'):
                                currtype = currdict[instance._typestring].\
                                                            split('#')[-1]
                                currtype = currtype.split('.')[0]
                            else:
                                currtype = currdict[instance._typestring].\
                                                            split('.')[0]
                            insttype = instance.resp.dict["title"].split('.')[0]

                            if currtype == insttype or currtype == \
                                                instance.resp.dict[\
                                               "oldtitle"].split('.')[0]:
                                location_file = instance.resp.dict
                                break
                        elif searchtype == "object" and instance.resp.dict[\
                                   "title"].startswith(currtype) or \
                                   "oldtitle" in list(instance.resp.dict.\
                                   keys()) and currdict[instance._typestring\
                                       ] == instance.resp.dict["oldtitle"]:
                            location_file = instance.resp.dict
                            break
                        elif searchtype != "object":
                            #added for smart storage differences in ids
                            tname = currdict[instance._typestring].split('.')[0]
                            if tname[0] == '#':
                                tname = tname[1:]
                            if tname == instance.resp.dict["RegistryPrefix"]:
                                location_file = instance.resp.dict
                                break
                    except BaseException:
                        pass
                    else:
                        pass

                    if location_file:
                        break

        if not location_file:
            errlist.append(RegistryValidationError('Location data is empty'))
        else:
            if currdict and monolith:
                jsonreg = json.loads(json.dumps(location_file, indent=2, \
                                                            cls=JSONEncoder))
            else:
                jsonreg = json.loads(location_file)

            if skipcommit:
                return {jsonreg['RegistryPrefix']:jsonreg["Messages"]}

            if 'properties' in jsonreg:
                regitem = jsonreg['properties']
                if 'Properties' in regitem:
                    regitem.update(regitem['Properties'])
                    del regitem['Properties']
                reg = HpPropertiesRegistry.parse(regitem)

                if newarg:
                    regcopy = reg
                    for arg in newarg[:-1]:
                        try:
                            arg = next(key for key in list(regcopy.keys()) if \
                                                    key.lower() == arg.lower())
                            if 'properties' in six.iterkeys(regcopy[arg]) \
                                                and ('patternProperties' in \
                                                    six.iterkeys(regcopy[arg])):
                                regcopy[arg]['properties'].update(\
                                              regcopy[arg]['patternProperties'])
                                regcopy = regcopy[arg]["properties"]

                                for pattern in six.iterkeys(regcopy):
                                    test = re.compile(pattern)
                                    nextarg = newarg[newarg.index(arg)+1]
                                    match = test.match(nextarg)

                                    if match:
                                        regcopy[nextarg] = regcopy.pop(pattern)
                                        break
                            elif 'oneOf' in regcopy[arg]:
                                oneof = regcopy[arg]['oneOf']
                                for item in oneof:
                                    regcopy = item['properties']

                                    if not arg == newarg[-1]:
                                        try:
                                            nextitem = newarg[newarg.index(arg)+1]
                                            regcopy[nextitem]
                                            break
                                        except Exception:
                                            continue
                            else:
                                regcopy = regcopy[arg]["properties"]
                        except Exception:
                            try:
                                regcopy = regcopy[arg]['patternProperties']
                                for pattern in six.iterkeys(regcopy):
                                    test = re.compile(pattern)
                                    nextarg = newarg[newarg.index(arg)+1]
                                    match = test.match(nextarg)

                                    if match:
                                        patterninfo = regcopy.pop(pattern)
                                        regcopy[nextarg] = patterninfo
                            except BaseException:
                                return None

                    reg = regcopy

            return reg
        return None

    def get_registry_model_bios_version(self, currdict=None, monolith=None, \
                                                                errlist=None):
        """BIOS VERSION Load the schema file and find the registry model
        if available.

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param errlist: list containing found errors.
        :type errlist: list.
        :returns: returns the registry model

        """
        attregtype = Typepathforval.typepath.defs.attributeregtype
        if not errlist:
            errlist = list()

        if not checkattr(self, 'Location'):
            errlist.append(RegistryValidationError(
                'Location property does not exist'))
            return None

        currloc = None
        defloc = "en"
        langcode = list(locale.getdefaultlocale())

        if not langcode[0]:
            langcode[0] = "en"

        for loc in self.Location:
            locationlanguage = loc["Language"].lower()
            locationlanguage = locationlanguage.replace("-", "_")
            if locationlanguage in langcode[0].lower():
                currloc = loc
                break

        if not currloc:
            # use default location if lang doesn't match
            currloc = defloc

        location_file = None
        if currdict and monolith:
            itemtype = monolith.gettypename(attregtype)
            if itemtype:
                for instance in monolith.itertype(itemtype):
                    location_file = instance.resp.dict
                    break

        if not location_file:
            errlist.append(RegistryValidationError('Location data is empty'))
        else:
            if currdict and monolith:
                jsonreg = json.loads(json.dumps(location_file, indent=2, \
                                                            cls=JSONEncoder))
            else:
                jsonreg = json.loads(location_file)

            if 'RegistryEntries' in jsonreg:
                regitem = jsonreg['RegistryEntries']
                reg = HpPropertiesRegistry.parse(regitem)
                return reg

        return None

    def nestedreg(self, reg=None, args=None):
        """Go through the registry entry to find the required nested attribute

        :param reg: Registry entry of the given attribute.
        :type reg: dict.
        :param args: list of multi level properties to be modified.
        :type args: list.
        :returns: dict of Registry entry

        """
        for arg in args:
            try:
                arg = next(key for key in list(reg.keys()) if \
                                        key.lower() == arg.lower())
                if 'properties' in six.iterkeys(reg[arg]) \
                                    and ('patternProperties' in \
                                        six.iterkeys(reg[arg])):
                    reg[arg]['properties'].update(\
                                  reg[arg]['patternProperties'])
                    reg = reg[arg]["properties"]
                elif 'oneOf' in reg[arg]:
                    oneof = reg[arg]['oneOf']
                    for item in oneof:
                        reg = item['properties']
                elif 'type' in reg[arg] and reg[arg]['type'] == 'array' and \
                    'items' in reg[arg] and "properties" in reg[arg]["items"]:
                    reg = reg[arg]["items"]["properties"]
                else:
                    reg = reg[arg]["properties"]
            except:
                try:
                    reg = reg[arg]['patternProperties']
                except:
                    return None
        return reg

class HpPropertiesRegistry(RisObject):
    """Models the HpPropertiesRegistry file"""
    def __init__(self, d):
        super(HpPropertiesRegistry, self).__init__(d)

    def validate_attribute_values(self, tdict):
        """Look for tdict in attribute list and attempt to validate its value

        :param tdict: the dictionary to test against.
        :type tdict: list.
        :returns: returns a validated list

        """
        result = list()

        for tkey in tdict:
            try:
                if self[tkey] and checkattr(self[tkey], "type"):
                    keyval = list()
                    keyval.append(tdict[tkey])
                    temp = self.validate_attribute(self[tkey], keyval, tkey)
                    tdict[tkey] = keyval[0]

                    for err in temp:
                        if isinstance(err, RegistryValidationError):
                            if err.reg:
                                err.sel = tkey

                    result.extend(temp)
            except Exception:
                pass

        return result

    def validate_att_val_bios(self, tdict):
        """Look for tdict in attribute list and attempt to validate its value

        :param tdict: the dictionary to test against.
        :type tdict: list.
        :returns: returns a validated list

        """
        result = list()

        attdict = tdict['Attributes'] if 'Attributes' in list(tdict.keys()) else tdict
        for tkey in attdict:
            for item in self.Attributes:
                try:
                    if item[Typepathforval.typepath.defs.attributenametype] \
                            == tkey and checkattr(item, "Type"):
                        keyval = list()
                        keyval.append(attdict[tkey])
                        temp = self.validate_attribute(item, keyval, tkey)
                        attdict[tkey] = keyval[0]

                        for err in temp:
                            if isinstance(err, RegistryValidationError):
                                if err.reg:
                                    err.sel = tkey

                        result.extend(temp)
                        break
                except Exception:
                    pass

        tdict = attdict if 'Attributes' not in list(tdict.keys()) else tdict['Attributes']
        return result

    def get_validator(self, attrname, newargs=None, oneof=None):
        """Returns attribute validator type

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param oneof: special string for "oneof" options within validation.
        :type oneof: list.
        :returns: returns attribute validator type

        """
        if oneof:
            self = oneof

        if newargs:
            for arg in newargs:
                try:
                    self = self['properties']
                except Exception:
                    pass

                if not checkattr(self, arg):
                    return None
                elif not arg == newargs[-1]:
                    self = self[arg]

        if not checkattr(self, attrname):
            return None

        validator = None
        if EnumValidator.is_type(self[attrname]):
            validator = EnumValidator.parse(self[attrname])
        elif StringValidator.is_type(self[attrname]):
            validator = StringValidator.parse(self[attrname])
        elif ObjectValidator.is_type(self[attrname]):
            validator = ObjectValidator.parse(self[attrname])
        elif IntegerValidator.is_type(self[attrname]):
            validator = IntegerValidator.parse(self[attrname])
        elif BoolValidator.is_type(self[attrname]):
            validator = BoolValidator.parse(self[attrname])
        elif PasswordValidator.is_type(self[attrname]):
            validator = PasswordValidator.parse(self[attrname])
        elif 'oneOf' in list(self[attrname].keys()):
            for item in self[attrname]['oneOf']:
                validator = self.get_validator(attrname, newargs, \
                                        HpPropertiesRegistry({attrname:item}))
                if validator:
                    break
        return validator

    def get_validator_bios(self, attrname):
        """Returns attribute validator type

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :returns: returns attribute validator type

        """

        for item in self.Attributes:
            name = Typepathforval.typepath.defs.attributenametype
            if name not in list(item.keys()):
                return None
            if item[name] == attrname:
                validator = None
                if EnumValidator.is_type(item):
                    validator = EnumValidator.parse(item)
                elif StringValidator.is_type(item):
                    validator = StringValidator.parse(item)
                elif IntegerValidator.is_type(item):
                    validator = IntegerValidator.parse(item)
                elif BoolValidator.is_type(item):
                    validator = BoolValidator.parse(item)
                elif ObjectValidator.is_type(item):
                    validator = ObjectValidator.parse(item)
                elif PasswordValidator.is_type(item):
                    validator = PasswordValidator.parse(item)

                return validator

        return None

    def validate_attribute(self, attrentry, attrvallist, name):
        """Function to validate attribute against iLO schema

        :param attrentry: attribute entry to be used for validation.
        :type attrentry: str.
        :param attrval: attribute value to be used for validation.
        :type attrval: str.
        :param name: clean name for outputting.
        :type name: str.
        :returns: returns list with validated attribute

        """
        result = list()
        validator = None
        attrval = attrvallist[0]
        if self.nulltypevalidationcheck(attrval=attrval, attrentry=attrentry):
            return result

        if EnumValidator.is_type(attrentry):
            validator = EnumValidator.parse(attrentry)
            attrval = attrvallist
        elif StringValidator.is_type(attrentry):
            validator = StringValidator.parse(attrentry)
        elif IntegerValidator.is_type(attrentry):
            validator = IntegerValidator.parse(attrentry)
        elif BoolValidator.is_type(attrentry):
            validator = BoolValidator.parse(attrentry)
        elif ObjectValidator.is_type(attrentry):
            validator = ObjectValidator.parse(attrentry)
        elif PasswordValidator.is_type(attrentry):
            validator = PasswordValidator.parse(attrentry)
        else:
            raise UnknownValidatorError(attrentry)

        if validator:
            result.extend(validator.validate(attrval, name))
        return result

    def nulltypevalidationcheck(self, attrval=None, attrentry=None):
        """Function to validate attribute against iLO schema

        :param attrentry: attribute entry to be used for validation.
        :type attrentry: str.
        :param attrval: attribute value to be used for validation.
        :type attrval: str.
        :returns: returns boolean

        """
        if 'type' in attrentry and attrval is None:
            if isinstance(attrentry['type'], list):
                for item in attrentry['type']:
                    if item.lower() == 'null':
                        return True

class BaseValidator(RisObject):
    """Base validator class"""
    def __init__(self, d):
        super(BaseValidator, self).__init__(d)

    def validate(self):
        """Overridable function for validation """
        raise RuntimeError('You must override this method in your derived ' \
                                                                        'class')

    def common_print_help(self, name):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :returns: str

        """
        outdata = ''
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent = ' ' * 4
        wrapper.subsequent_indent = ' ' * 4

        outdata += '\nNAME\n'
        outdata += '%s\n' % wrapper.fill('%s' % name)
        outdata += '\n'

        if 'DisplayName' in self:
            outdata += '\nDISPLAY NAME\n'
            outdata += '%s\n' % wrapper.fill('%(DisplayName)s' % self)
            outdata += '\n'

        if 'description' in self:
            outdata += '\nDESCRIPTION\n'
            outdata += '%s\n' % wrapper.fill('%(description)s' % self)
            outdata += '\n'

        if 'HelpText' in self:
            outdata += '\nHELP TEXT\n'
            outdata += '%s\n' % wrapper.fill('%(HelpText)s' % self)
            outdata += '\n'

        if 'WarningText' in self:
            outdata += '\n************************************************\n'
            outdata += '\nWARNING\n'
            outdata += '%s\n' % wrapper.fill('%(WarningText)s' % self)
            outdata += '\n\n**********************************************\n'
            outdata += '\n'

        if 'type' in self and isinstance(self['type'], list):
            outdata += '\nTYPE\n'
            for item in self['type']:
                outdata += '%s\n' % wrapper.fill('%s' % item)
            outdata += '\n'
        elif 'type' in self:
            outdata += '\nTYPE\n'
            outdata += '%s\n' % wrapper.fill('%(type)s' % self)
            outdata += '\n'
        elif 'Type' in self:
            outdata += '\nTYPE\n'
            outdata += '%s\n' % wrapper.fill('%(Type)s' % self)
            outdata += '\n'

        if 'ReadOnly' in self:
            outdata += '\nREAD-ONLY\n'
            outdata += '%s\n' % wrapper.fill('%(ReadOnly)s' % self)
            outdata += '\n'
        elif 'readonly' in self:
            outdata += '\nREAD-ONLY\n'
            outdata += '%s\n' % wrapper.fill('%(readonly)s' % self)
            outdata += '\n'
        return outdata

class EnumValidator(BaseValidator):
    """Enum validator class"""
    def __init__(self, d):
        super(EnumValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is enumeration

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :returns: returns a boolean based on whether type is eneumeration

        """
        if 'type' in attrentry:
            if isinstance(attrentry['type'], list):
                for item in attrentry['type']:
                    if item.lower() == 'enumeration':
                        return True
                    elif 'enum' in attrentry and item.lower() == 'string':
                        return True
            elif 'enum' in attrentry and attrentry['type'] == "array":
                for key, value in six.iteritems(attrentry['items']):
                    if key.lower() == "type" and value.lower() == 'string':
                        return True
            else:
                if attrentry['type'].lower() == 'enumeration':
                    return True
                elif 'enum' in attrentry and attrentry['type'].lower() == \
                                                                    'string':
                    return True
        elif 'Type' in attrentry:
            if attrentry['Type'].lower() == 'enumeration':
                return True

        return False

    def validate(self, keyval, name):
        """Validate against iLO schema

        :param keyval: new value to be used for validation.
        :type keyval: str.
        :param name: clean name for outputting.
        :type name: str.
        :returns: returns an error if fails

        """
        result = list()
        newval = keyval[0]

        try:
            for possibleval in self.enum:
                if possibleval and possibleval.lower() == newval.lower():
                    keyval[0] = possibleval
                    return result
        except Exception:
            for possibleval in self.Value:
                if possibleval.ValueName.lower() == str(newval).lower():
                    keyval[0] = possibleval.ValueName
                    return result

        result.append(RegistryValidationError("'%s' is not a valid setting " \
                                  "for '%s'" % (newval, name), regentry=self))

        return result

    def print_help(self, name):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :returns: str.

        """
        outdata = self.common_print_help(name)
        outdata += '\nPOSSIBLE VALUES\n'
        try:
            for possibleval in self.enum:
                outdata += '    %s\n' % possibleval
        except Exception:
            for possibleval in self.Value:
                outdata += '    %(ValueName)s\n' % possibleval
        outdata += '\n'
        return outdata

class BoolValidator(BaseValidator):
    """Bool validator class"""
    def __init__(self, d):
        super(BoolValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is boolean

        :param attrentry: attribute entry containing data to be validated.
        :type attrentry: str.
        :returns: returns boolean on whether type is boolean

        """
        if 'type' in attrentry:
            if isinstance(attrentry['type'], list):
                for item in attrentry['type']:
                    if item.lower() == 'boolean':
                        return True
            elif attrentry['type'] == "array":
                for key, value in six.iteritems(attrentry['items']):
                    if key.lower() == "type" and value.lower() == 'boolean':
                        return True
            else:
                if attrentry['type'].lower() == 'boolean':
                    return True
        elif 'Type' in attrentry:
            if attrentry['Type'].lower() == 'boolean':
                return True

        return False

    def validate(self, newval, name):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: str.
        :param name: clean name for outputting.
        :type name: str.
        :returns: returns an error if no validation value

        """
        result = list()
        if newval is False or newval is True:
            return result

        result.append(
            RegistryValidationError("'%s' is not a valid setting for '%s'" % \
                                                (newval, name), regentry=self))

        return result

    def print_help(self, name):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :returns: str.

        """
        outdata = self.common_print_help(name)
        outdata += '\nPOSSIBLE VALUES\n'
        outdata += '    True or False\n'
        outdata += '\n'
        return outdata

class StringValidator(BaseValidator):
    """Constructor """
    def __init__(self, d):
        super(StringValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is string

        :param attrentry: attribute entry containing data to be validated.
        :type attrentry: str.
        :returns: returns boolean based on whether type to validate is string

        """
        if 'type' in attrentry:
            if isinstance(attrentry['type'], list):
                for item in attrentry['type']:
                    if item.lower() == 'string':
                        return True
            elif attrentry['type'] == "array":
                for key, value in six.iteritems(attrentry['items']):
                    if key.lower() == "type" and 'string' in value:
                        return True
            else:
                if attrentry['type'].lower() == 'string':
                    return True
        elif 'Type' in attrentry:
            if attrentry['Type'].lower() == 'string':
                return True

        return False

    def validate(self, newval, _):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: str.
        :returns: returns an error if validation fails criteria

        """
        result = list()
        namestr = Typepathforval.typepath.defs.attributenametype
        if 'MinLength' in self:
            if len(newval) < int(self['MinLength']):
                result.append(RegistryValidationError(
                    "'%s' must be at least '%s' characters long" %
                    (self[namestr], int(self['MinLength'])), regentry=self))

        if 'MaxLength' in self:
            if len(newval) > int(self['MaxLength']):
                result.append(RegistryValidationError(
                    "'%s' must be less than '%s' characters long" %
                    (self[namestr], int(self['MaxLength'])), regentry=self))

        if 'ValueExpression' in self:
            if self['ValueExpression']:
                pat = re.compile(self['ValueExpression'])
                if newval and not pat.match(newval):
                    result.append(RegistryValidationError(
                        "'%(Name)s' must match the regular expression "
                        "'%(ValueExpression)s'" % (self), regentry=self))

        return result

    def print_help(self, name):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :returns: str.

        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent = ' ' * 4
        wrapper.subsequent_indent = ' ' * 4
        outdata = self.common_print_help(name)
        if 'MinLength' in self:
            outdata += '\nMIN LENGTH\n'
            outdata += '%s' % wrapper.fill('%(MinLength)s' % self)
            outdata += '\n'

        if 'MaxLength' in self:
            outdata += '\nMAX LENGTH\n'
            outdata += '%s' % wrapper.fill('%(MaxLength)s' % self)
            outdata += '\n'
        return outdata

class IntegerValidator(BaseValidator):
    """Interger validator class"""
    def __init__(self, d):
        super(IntegerValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is integer

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :returns: returns boolean based on type being an integer

        """
        if 'type' in attrentry:
            if isinstance(attrentry['type'], list):
                for item in attrentry['type']:
                    if item.lower() == 'integer' or item.lower() == 'number':
                        return True
            elif attrentry['type'] == "array":
                for key, value in six.iteritems(attrentry['items']):
                    if key.lower() == "type":
                        if value.lower() == 'interger' or value.lower() == \
                                                                    'number':
                            return True
            else:
                if attrentry['type'].lower() == 'integer' or \
                            attrentry['type'].lower().lower() == 'number':
                    return True
        elif 'Type' in attrentry:
            if attrentry['Type'].lower() == 'integer':
                return True

        return False

    def validate(self, newval, _):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: str.
        :returns: list.

        """
        result = list()
        intval = int(newval)

        pat = re.compile(r'0-9+')
        if newval and not pat.match(intval):
            result.append(
                RegistryValidationError(
                    "'%(Name)s' must be an integer value'" % (self),
                    regentry=self
                )
            )
            return result

        if 'LowerBound' in self:
            if intval < int(self['LowerBound']):
                result.append(RegistryValidationError("'%s' must be greater" \
                                      " than or equal to '%s'" % (self.Name, \
                                      int(self['LowerBound'])), regentry=self))

        if 'UpperBound' in self:
            if intval > int(self['UpperBound']):
                result.append(RegistryValidationError("'%s' must be less " \
                                      "than or equal to '%s'" % (self.Name, \
                                     int(self['LowerBound'])), regentry=self))

        return result

    def print_help(self, name):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :returns: str.

        """
        outdata = self.common_print_help(name)
        return outdata

class ObjectValidator(BaseValidator):
    """Object validator class"""
    def __init__(self, d):
        super(ObjectValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is object

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :returns: returns boolean based on whether type is an object

        """
        if 'type' in attrentry:
            if isinstance(attrentry['type'], list):
                for item in attrentry['type']:
                    if item.lower() == 'object':
                        return True
            elif attrentry['type'] == "array":
                for key, value in six.iteritems(attrentry['items']):
                    if key.lower() == "type" and value.lower() == 'object':
                        return True
                    elif key.lower() == "anyof":
                        try:
                            if value[0]['type'] == 'object':
                                return True
                        except Exception:
                            continue
            else:
                if attrentry['type'].lower() == 'object':
                    return True
        elif 'Type' in attrentry:
            if attrentry['Type'].lower() == 'object':
                return True

        return False

    def validate(self, _, __):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: str.
        :returns: list.

        """
        #TODO need to add so logic for objects class?
        result = list()
        return result

    def print_help(self, name):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :returns: str.

        """
        outdata = self.common_print_help(name)
        return outdata

class PasswordValidator(BaseValidator):
    """Password validator class"""
    def __init__(self, d):
        super(PasswordValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is password

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :returns: returns boolean whether type is password

        """
        if 'type' in attrentry:
            if isinstance(attrentry['type'], list):
                for item in attrentry['type']:
                    if item.lower() == 'password':
                        return True
            elif attrentry['type'] == "array":
                for key, value in six.iteritems(attrentry['items']):
                    if key.lower() == "type" and value.lower() == 'password':
                        return True
            else:
                if attrentry['type'].lower() == 'password':
                    return True
        elif 'Type' in attrentry:
            if attrentry['Type'].lower() == 'password':
                return True

        return False

    def validate(self, newval, _):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: str.
        :returns: returns an validation error if criteria not met

        """
        result = list()

        if newval is None:
            return result

        if 'MinLength' in self:
            if len(newval) < int(self['MinLength']):
                result.append(RegistryValidationError("'%s' must be at least" \
                                      " '%s' characters long" % (self.Name, \
                                     int(self['MinLength'])), regentry=self))

        if 'MaxLength' in self:
            if len(newval) > int(self['MaxLength']):
                result.append(RegistryValidationError("'%s' must be less " \
                                  "than '%s' characters long" % (self.Name, \
                                     int(self['MaxLength'])), regentry=self))

        if 'ValueExpression' in self:
            if self['ValueExpression']:
                pat = re.compile(self['ValueExpression'])
                if newval and not pat.match(newval):
                    result.append(RegistryValidationError("'%(Name)s' must " \
                                      "match the regular expression '%(Value" \
                                      "Expression)s'" % (self), regentry=self))

        return result

    def print_help(self, name):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :returns: str.

        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent = ' ' * 4
        wrapper.subsequent_indent = ' ' * 4
        outdata = self.common_print_help(name)
        if 'MinLength' in self:
            outdata += '\nMIN LENGTH\n'
            outdata += '%s' % wrapper.fill('%(MinLength)s' % self)
            outdata += '\n'

        if 'MaxLength' in self:
            outdata += '\nMAX LENGTH\n'
            outdata += '%s' % wrapper.fill('%(MaxLength)s' % self)
            outdata += '\n'
        return outdata

class Typepathforval(object):
    """Way to store the typepath defines object."""
    typepath = None
    def __new__(cls, typepathobj):
        if typepathobj:
            Typepathforval.typepath = typepathobj

def checkattr(aobj, prop):
    """Check attribute function"""
    try:
        if hasattr(aobj, prop):
            return True
    except:
        pass
    return False
