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
"""RIS implementation"""

#---------Imports---------

import re
import sys
import logging

from collections import (OrderedDict)

#Added for py3 compatibility
import six

from six.moves.urllib.parse import urlparse, urlunparse

import jsonpath_rw
import jsonpointer

from jsonpointer import set_pointer

import redfish.rest.v1

from redfish.ris.sharedtypes import Dictable

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class BiosUnregisteredError(Exception):
    """Raised when BIOS has not been registered correctly in iLO"""
    pass

class SessionExpiredRis(Exception):
    """Raised when session has expired"""
    pass

class RisMonolithMemberBase(Dictable):
    """RIS monolith member base class"""
    pass

class RisInstanceNotFoundError(Exception):
    """Raised when attempting to select an instance that does not exist"""
    pass

class RisMonolithMemberv100(RisMonolithMemberBase):
    """Wrapper around RestResponse that adds the monolith data"""
    def __init__(self, restresp, isredfish):
        self._resp = restresp
        self._patches = list()
        self._type = None
        if isredfish:
            self._typestring = '@odata.type'
        else:
            self._typestring = 'Type'

    @property
    def type(self):
        """Return type from monolith"""
        if self._typestring in self._resp.dict:
            return self._resp.dict[self._typestring]
        #Added for object type
        elif 'type' in self._resp.dict:
            return self._resp.dict['type']
        return None

    @property
    def maj_type(self):
        """Return maj type from monolith"""
        if self.type:
            if '.' in self.type:
                types = ".".join(self.type.split(".", 2)[:2])
                retval = types[1:] if types.startswith('#') else types
            else:
                retval = self.type
            return retval
        return None

    @property
    def resp(self):
        """Return resp from monolith"""
        return self._resp

    @property
    def path(self):
        """Return path from monolith"""
        return self._resp.request.path

    @property
    def patches(self):
        """Return patches from monolith"""
        return self._patches

    @property
    def dict(self):
        """Return dict from monolith"""
        return self._resp.dict

    def to_dict(self):
        """Convert monolith to dict"""
        result = OrderedDict()
        if self.type:
            result['Type'] = self.type

            if self.maj_type == 'Collection.1' and \
                                            'MemberType' in self._resp.dict:
                result['MemberType'] = self._resp.dict['MemberType']

            result['links'] = OrderedDict()
            result['links']['href'] = ''
            headers = dict()

            for header in self._resp.getheaders():
                headers[header[0]] = header[1]

            result['Headers'] = headers

            if 'etag' in headers:
                result['ETag'] = headers['etag']

            result['OriginalUri'] = self._resp.request.path
            result['Content'] = self._resp.dict
            result['Patches'] = self._patches

        return result

    def load_from_dict(self, src):
        """Load variables from dict monolith

        :param src: source to load from
        :type src: dict
        """
        if 'Type' in src:
            self._type = src['Type']
            restreq = redfish.rest.v1.RestRequest(method='GET', \
                                                    path=src['OriginalUri'])

            src['restreq'] = restreq
            self._resp = redfish.rest.v1.StaticRestResponse(**src)
            self._patches = src['Patches']

class RisMonolithv100(Dictable):
    """Monolithic cache of RIS data"""
    def __init__(self, client):
        """Initialize RisMonolith

        :param client: client to utilize
        :type client: RmcClient object

        """
        self._client = client
        self.name = "Monolithic output of RIS Service"
        self._visited_urls = list()
        self._current_location = '/'
        self._type = None
        self._name = None
        self.progress = 0
        self.reload = False
        self.is_redfish = client._rest_client.is_redfish
        self.typesadded = dict()
        self.pathsadded = dict()

        if self.is_redfish:
            self._resourcedir = '/redfish/v1/ResourceDirectory/'
            self._typestring = '@odata.type'
            self._hrefstring = '@odata.id'
        else:
            self._resourcedir = '/rest/v1/ResourceDirectory'
            self._typestring = 'Type'
            self._hrefstring = 'href'

    @property
    def type(self):
        """Return monolith version type"""
        return "Monolith.1.0.0"

    @property
    def visited_urls(self):
        """Return the visited URLS"""
        return self._visited_urls

    @visited_urls.setter
    def visited_urls(self, visited_urls):
        """Set visited URLS to given list."""
        self._visited_urls = visited_urls

    @property
    def types(self):
        """Returns list of types of members in monolith
        :rtype: list
        """
        return list(self.typesadded.keys())

    @types.setter
    def types(self, member):
        """Adds a member to monolith

        :param member: Member created based on response.
        :type member: RisMonolithMemberv100.
        """
        if member.maj_type in list(self.typesadded.keys()):
            if member.path not in self.typesadded[member.maj_type]:
                self.typesadded[member.maj_type].append(member.path)
        else:
            self.typesadded[member.maj_type] = [member.path]
        patches = []
        if member.path in list(self.pathsadded.keys()):
            patches = self.pathsadded[member.path].patches
        self.pathsadded[member.path] = member
        self.pathsadded[member.path].patches.extend([patch for patch in patches])

    def path(self, path):
        """Provide the response of requested path

        :param path: path of response requested
        :type path: str.
        :rtype: RestResponse
        """
        try:
            return self.pathsadded[path]
        except:
            return None

    def update_progress(self):
        """Simple function to increment the dot progress"""
        if self.progress % 6 == 0:
            sys.stdout.write('.')

    def load(self, path=None, includelogs=False, skipinit=False, \
                        skipcrawl=False, loadtype='href', loadcomplete=False):
        """Walk entire RIS model and cache all responses in self.

        :param path: path to start load from.
        :type path: str.
        :param includelogs: flag to determine if logs should be downloaded also.
        :type includelogs: boolean.
        :param skipinit: flag to determine if first run of load.
        :type skipinit: boolean.
        :param skipcrawl: flag to determine if load should traverse found links.
        :type skipcrawl: boolean.
        :param loadtype: flag to determine if load is meant for only href items.
        :type loadtype: str.
        :param loadcomplete: flag to download the entire monolith
        :type loadcomplete: boolean

        """
        if not skipinit:
            if LOGGER.getEffectiveLevel() == 40:
                sys.stdout.write("Discovering data...")
            else:
                LOGGER.info("Discovering data...")
            self.name = self.name + ' at %s' % self._client.base_url

        selectivepath = path
        if not selectivepath:
            selectivepath = self._client._rest_client.default_prefix

        self._load(selectivepath, skipcrawl=skipcrawl, includelogs=includelogs,\
             skipinit=skipinit, loadtype=loadtype, loadcomplete=loadcomplete)

        if not skipinit:
            if LOGGER.getEffectiveLevel() == 40:
                sys.stdout.write("Done\n")
            else:
                LOGGER.info("Done\n")

    def _load(self, path, skipcrawl=False, originaluri=None, includelogs=False,\
                        skipinit=False, loadtype='href', loadcomplete=False):
        """Helper function to main load function.

        :param path: path to start load from.
        :type path: str.
        :param skipcrawl: flag to determine if load should traverse found links.
        :type skipcrawl: boolean.
        :param originaluri: variable to assist in determining originating path.
        :type originaluri: str.
        :param includelogs: flag to determine if logs should be downloaded also.
        :type includelogs: boolean.
        :param skipinit: flag to determine if first run of load.
        :type skipinit: boolean.
        :param loadtype: flag to determine if load is meant for only href items.
        :type loadtype: str.
        :param loadcomplete: flag to download the entire monolith
        :type loadcomplete: boolean

        """
        if path.endswith("?page=1"):
            return
        elif not includelogs:
            if "/Logs/" in path:
                return

        #TODO: need to find a better way to support non ascii characters
        path = path.replace("|", "%7C")
        #remove fragments
        newpath = urlparse(path)
        newpath = list(newpath[:])
        newpath[-1] = ''
        path = urlunparse(tuple(newpath))

        LOGGER.debug('_loading %s', path)

        if not self.reload:
            if path.lower() in self._visited_urls:
                return

        resp = self._client.get(path)

        if resp.status != 200 and path.lower() == self._client.typepath.defs.\
                                                                    biospath:
            raise BiosUnregisteredError()
        elif resp.status != 200:
            path = path + '/'
            resp = self._client.get(path)

            if resp.status == 401:
                raise SessionExpiredRis("Invalid session. Please logout and "\
                                        "log back in or include credentials.")
            elif resp.status != 200:
                return

        if loadtype == "ref":
            self.parse_schema(resp)

        self.update_member(resp=resp, path=path, skipinit=skipinit)

        if loadtype == 'href':
            #follow all the href attributes
            if self.is_redfish:
                jsonpath_expr = jsonpath_rw.parse("$..'@odata.id'")
            else:
                jsonpath_expr = jsonpath_rw.parse('$..href')
            matches = jsonpath_expr.find(resp.dict)

            if 'links' in resp.dict and 'NextPage' in resp.dict['links']:
                if originaluri:
                    next_link_uri = originaluri + '?page=' + \
                                    str(resp.dict['links']['NextPage']['page'])
                    href = '%s' % next_link_uri

                    self._load(href, originaluri=originaluri, \
                               includelogs=includelogs, skipcrawl=skipcrawl, \
                               skipinit=skipinit)
                else:
                    next_link_uri = path + '?page=' + \
                                    str(resp.dict['links']['NextPage']['page'])

                    href = '%s' % next_link_uri
                    self._load(href, originaluri=path, includelogs=includelogs,\
                                        skipcrawl=skipcrawl, skipinit=skipinit)

            (newversion, dirmatch) = self.check_for_directory(matches)
            if not newversion and not skipcrawl:
                for match in matches:
                    if path == "/rest/v1":
                        if str(match.full_path) == "links.Schemas.href" or \
                                str(match.full_path) == "links.Registries.href":
                            continue
                    else:
                        if str(match.full_path) == "Registries.@odata.id" or \
                                str(match.full_path) == "JsonSchemas.@odata.id":
                            continue

                    if match.value == path:
                        continue

                    href = '%s' % match.value
                    self._load(href, skipcrawl=skipcrawl, \
                           originaluri=originaluri, includelogs=includelogs, \
                           skipinit=skipinit)
            elif not skipcrawl:
                href = '%s' % dirmatch.value
                self._load(href, skipcrawl=skipcrawl, originaluri=originaluri, \
                                    includelogs=includelogs, skipinit=skipinit)
            if loadcomplete:
                for match in matches:
                    self._load(match.value, skipcrawl=skipcrawl, originaluri=\
                       originaluri, includelogs=includelogs, skipinit=skipinit)

    def parse_schema(self, resp):
        """Function to get and replace schema $ref with data

        :param resp: response data containing ref items.
        :type resp: str.

        """
        #pylint: disable=maybe-no-member
        jsonpath_expr = jsonpath_rw.parse('$.."$ref"')
        matches = jsonpath_expr.find(resp.dict)
        respcopy = resp.dict
        typeregex = '([#,@].*?\.)'
        if matches:
            for match in matches:
                fullpath = str(match.full_path)
                jsonfile = match.value.split('#')[0]
                jsonpath = match.value.split('#')[1]
                listmatch = None
                found = None

                if 'redfish.dmtf.org' in jsonfile:
                    if 'odata' in jsonfile:
                        jsonpath = jsonpath.replace(jsonpath.split('/')[-1], \
                                            'odata' + jsonpath.split('/')[-1])
                    jsonfile = 'Resource.json'

                found = re.search(typeregex, fullpath)
                if found:
                    repitem = fullpath[found.regs[0][0]:found.regs[0][1]]
                    schemapath = '/' + fullpath.replace(repitem, '~').\
                                        replace('.', '/').replace('~', repitem)
                else:
                    schemapath = '/' + fullpath.replace('.', '/')

                if '.json' in jsonfile:
                    itempath = schemapath

                    if self.is_redfish:
                        if resp.request.path[-1] == '/':
                            newpath = '/'.join(resp.request.path.split('/')\
                                                [:-2]) + '/' + jsonfile + '/'
                        else:
                            newpath = '/'.join(resp.request.path.split('/')\
                                                [:-1]) + '/' + jsonfile + '/'
                    else:
                        newpath = '/'.join(resp.request.path.split('/')[:-1]) \
                                                                + '/' + jsonfile

                    if 'href.json' in newpath:
                        continue

                    if not newpath.lower() in self._visited_urls:
                        self.load(newpath, skipcrawl=True, includelogs=False, \
                                                skipinit=True, loadtype='ref')

                    instance = list()

                    #deprecated type "string" for Type.json
                    if 'string' in self.types:
                        for item in self.itertype('string'):
                            instance.append(item)
                    if 'object' in self.types:
                        for item in self.itertype('object'):
                            instance.append(item)

                    for item in instance:
                        if jsonfile in item.resp._rest_request._path:
                            if 'anyOf' in fullpath:
                                break

                            dictcopy = item.resp.dict
                            listmatch = re.search('[[][0-9]+[]]', itempath)

                            if listmatch:
                                start = listmatch.regs[0][0]
                                end = listmatch.regs[0][1]

                                newitempath = [itempath[:start], itempath[end:]]
                                start = jsonpointer.JsonPointer(newitempath[0])
                                end = jsonpointer.JsonPointer(newitempath[1])

                                del start.parts[-1], end.parts[-1]
                                vals = start.resolve(respcopy)

                                count = 0

                                for val in vals:
                                    try:
                                        if '$ref' in six.iterkeys(end.resolve(val)):
                                            end.resolve(val).pop('$ref')
                                            end.resolve(val).update(dictcopy)
                                            replace_pointer = jsonpointer.\
                                                JsonPointer(end.path + jsonpath)

                                            data = replace_pointer.resolve(val)
                                            set_pointer(val, end.path, data)
                                            start.resolve(respcopy)[count].\
                                                                    update(val)

                                            break
                                    except:
                                        count += 1
                            else:
                                itempath = jsonpointer.JsonPointer(itempath)
                                del itempath.parts[-1]

                                if '$ref' in six.iterkeys(itempath.resolve(respcopy)):
                                    itempath.resolve(respcopy).pop('$ref')
                                    itempath.resolve(respcopy).update(dictcopy)
                                    break

                if jsonpath:
                    if 'anyOf' in fullpath:
                        continue

                    if not jsonfile:
                        replacepath = jsonpointer.JsonPointer(jsonpath)
                        schemapath = schemapath.replace('/$ref', '')
                        if re.search('\[\d]', schemapath):
                            schemapath = schemapath.translate(None, '[]')
                        schemapath = jsonpointer.JsonPointer(schemapath)
                        data = replacepath.resolve(respcopy)

                        if '$ref' in schemapath.resolve(respcopy):
                            schemapath.resolve(respcopy).pop('$ref')
                            schemapath.resolve(respcopy).update(data)

                    else:
                        if not listmatch:
                            schemapath = schemapath.replace('/$ref', '')
                            replacepath = schemapath + jsonpath
                            replace_pointer = jsonpointer.\
                                                        JsonPointer(replacepath)
                            data = replace_pointer.resolve(respcopy)
                            set_pointer(respcopy, schemapath, data)

            resp.json(respcopy)
        else:
            resp.json(respcopy)

    def check_for_directory(self, matches):
        """Function to allow checking for new directory

        :param matches: current found matches.
        :type matches: dict.

        """
        for match in matches:
            if match.value == self._resourcedir:
                return (True, match)

        return (False, None)

    def update_member(self, member=None, resp=None, path=None, skipinit=None):
        """Adds member to this monolith. If the member already exists the
        data is updated in place.

        :param member: Ris monolith member object made by branch worker.
        :type member: RisMonolithMemberv100.
        :param resp: response received.
        :type resp: str.
        :param path: path correlating to the response.
        :type path: str.
        :param skipinit: flag to determine if progress bar should be updated.
        :type skipinit: boolean.

        """
        if not member:
            self._visited_urls.append(path.lower())

            member = RisMonolithMemberv100(resp, self.is_redfish)
            if not member.type:
                return

        self.types = member

        if not skipinit:
            self.progress += 1
            if LOGGER.getEffectiveLevel() == 40:
                self.update_progress()

    def load_from_dict(self, src):
        """Load data to monolith from dict

        :param src: data receive from rest operation.
        :type src: str.

        """
        self._type = src['Type']
        self._name = src['Name']
        self.typesadded = src["typepath"]
        for _, resp in list(src['resps'].items()):
            member = RisMonolithMemberv100(None, self.is_redfish)
            member.load_from_dict(resp)
            self.update_member(member=member, skipinit=True)
        return

    def to_dict(self):
        """Convert data to dict from monolith"""
        result = OrderedDict()
        result['Type'] = self.type
        result['Name'] = self.name
        result["typepath"] = self.typesadded
        result["resps"] = {x:v.to_dict() for x, v in list(self.pathsadded.items())}
        return result

    @property
    def location(self):
        """Return current location"""
        return self._current_location

    @location.setter
    def location(self, newval):
        """Set current location"""
        self._current_location = newval

    def iter(self):
        """Returns each member of monolith

        :rtype: RisMonolithMemberv100
        """
        for _, val in self.pathsadded.items():
            yield val

    def itertype(self, typeval):
        """Returns member of given type in monolith

        :param typeval: type name of the requested response.
        :type typeval: str.

        :rtype: RisMonolithMemberv100
        """
        types = self.gettypename(typeval)
        if types in self.typesadded:
            for item in self.typesadded[types]:
                yield self.pathsadded[item]
        else:
            raise RisInstanceNotFoundError("Unable to locate instance for" \
                                                            " '%s'" % types)

    def typecheck(self, types):
        """Check if a member of given type exists

        :param types: type name of the requested response.
        :type types: str.

        :rtype: bool.
        """
        if any(types in val for val in self.types):
            return True
        return False

    def gettypename(self, types):
        """Get the maj_type name of given type

        :param types: type name of the requested response.
        :type types: str.
        """
        types = types[1:] if types[0] in ("#", "#") else types
        val = list([x for x in self.types if types.lower() in x.lower()])
        return val[0] if val else None

class RisMonolith(RisMonolithv100):
    """Latest implementation of RisMonolith"""
    def __init__(self, client):
        """Initialize Latest RisMonolith

        :param client: client to utilize
        :type client: RmcClient object
        """
        super(RisMonolith, self).__init__(client)
