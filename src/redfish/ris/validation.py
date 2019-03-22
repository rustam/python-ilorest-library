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
import logging
import textwrap

import six

from redfish.rest.v1 import (RisObject)
from .sharedtypes import JSONEncoder

# ---------End of imports---------


# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)

# ---------End of debug logger---------


class InvalidPathsError(Exception):
    """Raised when requested path is not found"""
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

        self._schemaid = Typepathforval.typepath.schemapath
        self._regid = Typepathforval.typepath.regpath

        self._classes = list()
        self._classpaths = list()
        #type and path defines object
        self.defines = defines
        self.monolith = monolith
        # error
        self._errors = list()
        self._warnings = list()
        self.updatevalidationdata()

    def updatevalidationdata(self):
        """Loads the types from monolith.
        """
        monolith = self.monolith
        for instance in monolith.iter():
            if (x.lower() in instance.maj_type.lower() for x in (self.defines.defs.\
                schemafilecollectiontype,\
                "Collection.", self.defines.defs.regfilecollectiontype)) and any(x.lower() in \
                    instance.path.lower() for x in (self._schemaid, self._regid))\
                    and instance and instance.path not in self._classpaths:
                self._classpaths.append(instance.path)
                self._classes.append(instance.resp.dict)

    def find_prop(self, propname, latestschema=False, proppath=None):
        """Searches through all locations and returns the first schema
        found for the provided type

        :param propname: string containing the schema name.
        :type propname: str.

        """
        if proppath:
            self.monolith.load(path=proppath, crawl=False, loadtype='ref')
            return True
        for cls in self._classes:
            found = self.find_property(propname, cls=cls, latestschema=latestschema)
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
            if 'registr' in items["Name"].lower():#For Gen9 type/name issue
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
            if 'schema' in items["Name"].lower():#For Gen9 type/name issue
                for item in items[membername]:
                    yield item

    def find_property(self, propname, cls=None, latestschema=False):
        """Returns iLO/BIOS registries/schemas

        :param propname: string containing the registry name.
        :type propname: str.
        :param cls: self._classes list of dictionaries.
        :type cls: list.
        :param latestschema: flag to drop the versioning in the type string.
        :type latestschema: bool.

        :returns: returns iLO/BIOS registries/schemas

        """
        result = []
        dataloc = cls.get('Items', None)
        dataloc = cls.get('Members', None) if not dataloc else dataloc
        keyword = 'Schema'
        if dataloc and isinstance(dataloc, list):
            splitname = propname.split('.')[0].strip('#')
            propname = propname.split('.')[0].strip('#') if latestschema else propname
            for entry in dataloc:
                if entry:
                    if 'Schema' in entry:
                        if propname.lower() in entry['Schema'].lower():
                            result.append(entry)
                    elif 'Registry' in entry:
                        if propname.lower() in entry['Registry'].lower():
                            result.append(entry)
                            keyword = 'Registry'
                    else:
                        if '@odata.id' in entry:
                            reglink = entry['@odata.id'].split('/')
                            reglink = reglink[len(reglink)-2]
                            if reglink.lower().startswith(splitname.lower()):
                                self.monolith.load(path=entry['@odata.id'], crawl=False)
                                result.append(self.monolith.paths[entry['@odata.id']].dict)

        if result:
            result = max(result, key=lambda res: res[self.monolith._hrefstring] if res.\
                        get(self.monolith._hrefstring, None) else res[keyword])
            schemapath = self.geturidict(result['Location'][0])
            self.monolith.load(path=schemapath, crawl=False, loadtype='ref')
            return result

    def geturidict(self, locationobj):
        """Return the external reference link.

        :param locationobj: location of the dict
        :type locationobj: dict
        """
        if Typepathforval.typepath.defs.isgen10:
            try:
                return locationobj["Uri"]
            except Exception:
                raise InvalidPathsError("Error accessing Uri path!/n")
        elif Typepathforval.typepath.defs.isgen9:
            try:
                return locationobj["Uri"]["extref"]
            except Exception:
                raise InvalidPathsError("Error accessing extref path!/n")

    def validatedict(self, tdict, currtype=None, proppath=None, latestschema=False, \
            searchtype=None, monolith=None, reg=None, unique=None):
        """Load the schema file and validate tdict against it

        :param tdict: the dictionary to test against.
        :type tdict: dict.
        :param errlist: list containing found errors.
        :type errlist: list.
        :param warnings: list containing found warnings.
        :type warnings: list.
        :param currtype: current selection dictionary type.
        :type currtype: str.
        :param searchtype: classifier for the current search.
        :type searchtype: str.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param unique: flag to determine override for unique properties.
        :type unique: bool
        :param reg: Registry entry of the given attribute.
        :type reg: dict.
        :returns: returns an error list.

        """
        if not reg:
            reg = self.get_registry_model(currtype=currtype, searchtype=searchtype, \
                                    proppath=proppath, latestschema=latestschema)

        if reg:
            list(map(lambda x: self.checkreadunique(tdict, x, reg=reg, searchtype=searchtype, \
                            warnings=self._warnings, unique=unique), list(tdict.keys())))
            orireg = reg.copy()
            ttdict = {ki:val for ki, val in list(tdict.items()) \
                      if not isinstance(val, (dict, list))}
            results = reg.validate_attribute_values(ttdict)
            self._errors.extend(results)

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
                        self.validatedict(val[0], unique=unique, monolith=monolith, reg=treg,\
                              currtype=currtype, searchtype=searchtype)
                    else:
                        continue
                elif val and isinstance(val, dict):
                    valexists = True
                    treg = self.nestedreg(reg=reg, args=[ki])
                    self.validatedict(val, monolith=monolith, reg=treg, unique=unique, \
                                  searchtype=searchtype)
                if not val and valexists:
                    del tdict[ki]
        else:
            self._errors.append(RegistryValidationError('Unable to locate registry model'))

    def checkreadunique(self, tdict, tkey, searchtype=None, \
                        reg=None, warnings=None, unique=None):
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
        if reg.get("ReadOnly", None) == False or (reg.get(tkey, None)\
                             and reg[tkey].get("readonly", None) == False):
            if unique or not reg.get("IsSystemUniqueProperty", None):
                return
        if not searchtype or (reg.get("ReadOnly", None) == True \
                or (reg.get(tkey, None) and reg[tkey].get("readonly", None) == True)):
            warnings.append("Property is read-only skipping '%s'\n" % str(tkey))
            del tdict[tkey]
            return True

    def get_registry_model(self, currtype=None, proppath=None, \
           getmsg=False, searchtype=None, newarg=None, latestschema=False):
        """Load the schema file and find the registry model if available

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param errlist: list containing found errors.
        :type errlist: list.
        :param getmsg: flag to determine if commit should be skipped.
        :type getmsg: boolean.
        :param searchtype: classifier for the current search.
        :type searchtype: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :returns: returns registry model

        """
        regdict = None
        monolith = self.monolith
        currtype = currtype.split('#')[-1].split('.')[0] +\
                '.' if currtype and latestschema else currtype
        if (not currtype or not self.find_prop(currtype, latestschema=latestschema, \
               proppath=proppath if not searchtype else None)) and (not searchtype):
            self._errors.append(RegistryValidationError('Location info is missing.'))
            return None
        if not searchtype:
            searchtype = "object"

        try:
            for instance in monolith.iter(searchtype):
                if (searchtype == Typepathforval.typepath.defs.attributeregtype) or\
                    (searchtype == "object" and any(currtype in \
                       xtitle for xtitle in (instance.resp.dict.get("title", ""), \
                                   instance.resp.dict.get("oldtitle", "")))) \
                   or (searchtype != "object" and currtype.split('#')[-1].split('.')[0] \
                            == instance.dict.get("RegistryPrefix", "")):
                    regdict = instance.resp.dict
                    break
        except BaseException:
            pass

        if not regdict:
            self._errors.append(RegistryValidationError('Location data is empty'))
            return None

        jsonreg = json.loads(json.dumps(regdict, indent=2, cls=JSONEncoder))

        if getmsg:
            return {jsonreg['RegistryPrefix']:jsonreg["Messages"]}

        #This was done for bios registry model compatibility
        if 'RegistryEntries' in jsonreg:
            regitem = jsonreg['RegistryEntries']
            if 'Attributes' in regitem:
                newitem = {item[Typepathforval.typepath.defs.\
                            attributenametype]:item for item in regitem['Attributes']}
                regitem['Attributes'] = newitem
                if not Typepathforval.typepath.flagiften:
                    del regitem['Attributes']
                    newitem.update(regitem)
                    regitem = newitem
                reg = HpPropertiesRegistry.parse(regitem)
            return self.nestedreg(reg=reg, args=newarg) if newarg else reg

        if 'properties' in jsonreg:
            regitem = jsonreg['properties']
            if 'Properties' in regitem:
                regitem.update(regitem['Properties'])
                del regitem['Properties']
            reg = HpPropertiesRegistry.parse(regitem)

            return self.nestedreg(reg=reg, args=newarg) if newarg else reg

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
                arg = next((key for key in list(reg.keys()) if \
                                        key.lower() == arg.lower()), None)
                if not arg:
                    return None
                if 'properties' in six.iterkeys(reg[arg]) and ('patternProperties' in \
                                        six.iterkeys(reg[arg])):
                    reg[arg]['properties'].update(reg[arg]['patternProperties'])
                    reg = reg[arg]["properties"]
                elif 'oneOf' in reg[arg]:
                    oneof = reg[arg]['oneOf']
                    for item in oneof:
                        reg = item['properties']
                elif 'type' in reg[arg] and reg[arg]['type'] == 'array' and \
                    'items' in reg[arg] and "properties" in reg[arg]["items"]:
                    reg = reg[arg]["items"]["properties"]
                elif not ('properties' in six.iterkeys(reg[arg]) \
                    or 'patternProperties' in six.iterkeys(reg[arg])):
                    reg = reg[arg]
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
            if not tkey in self:
                #Added for Gen 9 Bios properties not in registry
                continue
            elif self[tkey] and (checkattr(self[tkey], "type") or checkattr(self[tkey], "Type")):
                keyval = list()
                keyval.append(tdict[tkey])
                temp = self.validate_attribute(self[tkey], keyval, tkey)
                tdict[tkey] = keyval[0]

                for err in temp:
                    if isinstance(err, RegistryValidationError):
                        if err.reg:
                            err.sel = tkey

                result.extend(temp)

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
        if self.nulltypevalidationcheck(attrval=attrvallist[0], attrentry=attrentry):
            return result

        if EnumValidator.is_type(attrentry):
            validator = EnumValidator.parse(attrentry)
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
            result.extend(validator.is_array(attrentry, attrvallist, name))
            result.extend(validator.validate(attrvallist, name))
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
        raise RuntimeError('You must override this method in your derived class')

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

    def is_arrtype(self, attrentry):
        """Validate that the type is array

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :returns: returns a boolean based on whether type is array

        """
        if 'type' in attrentry and attrentry['type'] == "array":
            return True
        return False

    def is_array(self, attrentry, arrval, name):
        """Validate that the given value is an array type

        :param arrval: attribute name to be used for validation.
        :type arrval: unknown type.
        :returns: returns a boolean based on whether type is array

        """
        result = []

        if self.is_arrtype(attrentry):
            if isinstance(arrval[0], (frozenset, list, set, tuple,)):
                return []
            else:
                result.append(RegistryValidationError("'%s' is not a valid setting " \
                      "for '%s', expecting an array" % (arrval[0], name), regentry=self))
        return result

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
                elif 'enum' in attrentry and attrentry['type'].lower() == 'string':
                    return True
        elif 'Type' in attrentry:
            if attrentry['Type'].lower() == 'enumeration':
                return True

        return False

    def validate(self, keyval, name):
        """Validate against iLO schema

        :param keyval: new value to be used for validation.
        :type keyval: list.
        :param name: clean name for outputting.
        :type name: str.
        :returns: returns an error if fails

        """
        result = list()
        newval = keyval[0]

        try:
            for possibleval in self.enum:
                if possibleval and isinstance(possibleval, type(newval)) or \
                            (isinstance(possibleval, six.string_types) and \
                             isinstance(newval, six.string_types)) and \
                             possibleval.lower() == str(newval).lower():
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
        if newval[0] is False or newval[0] is True:
            return result

        result.append(
            RegistryValidationError("'%s' is not a valid setting for '%s'" % \
                                                (newval[0], name), regentry=self))

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

    def validate(self, newvallist, _):
        """Validate against iLO schema

        :param newvallist: new value to be used for validation.
        :type newvallist: list.
        :returns: returns an error if validation fails criteria

        """
        newval = newvallist[0]
        result = list()
        namestr = Typepathforval.typepath.defs.attributenametype
        if not isinstance(newval, basestring):
            result.append(RegistryValidationError("Given value must be a string"))
            return result
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
                        if value.lower() == 'interger' or value.lower() == 'number':
                            return True
            else:
                if attrentry['type'].lower() == 'integer' or \
                            attrentry['type'].lower().lower() == 'number':
                    return True
        elif 'Type' in attrentry:
            if attrentry['Type'].lower() == 'integer':
                return True

        return False

    def validate(self, newvallist, _):
        """Validate against iLO schema

        :param newvallist: new value to be used for validation.
        :type newvallist: str.
        :returns: list.

        """
        result = list()
        try:
            intval = int(newvallist[0])
            newvallist[0] = intval
        except:
            result.append(RegistryValidationError("'%(Name)s' must "\
                "be an integer value'" % (self), regentry=self))
            return result

        if newvallist[0] and not str(intval).isdigit():
            result.append(RegistryValidationError("'%(Name)s' must "\
                "be an integer value'" % (self), regentry=self))
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

    def validate(self, newval, name):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: list.
        :returns: list.

        """
        #TODO: need to add logic for true postive and false negatives.
        result = list()
        if isinstance(newval[0], (dict, six.string_types, int)):
            result.append(\
                    RegistryValidationError("'%s' is not a valid setting for '%s'" % \
                                                                (newval[0], name), regentry=self))
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
        if 'properties' in self:
            outdata += '\nSUB-PROPERTIES\n'
            propdata = ', '.join(list(six.iterkeys(self.properties)))
            outdata += '%s' % wrapper.fill('%s' % propdata)
            outdata += '\n'
        elif 'items' in self:
            outdata += '\nSUB-PROPERTIES\n'
            propdata = ', '.join(list(six.iterkeys(self['items'].properties)))
            outdata += '%s' % wrapper.fill('%s' % propdata)
            outdata += '\n'

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

    def validate(self, newvallist, _):
        """Validate against iLO schema

        :param newvallist: new value to be used for validation.
        :type newvallist: list.
        :returns: returns an validation error if criteria not met

        """
        result = list()
        newval = newvallist[0]

        if newval is None:
            return result

        if not isinstance(newval, basestring):
            result.append(RegistryValidationError("Given value must be a string"))
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
