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
"""RMC helper implementation"""

#---------Imports---------

import os
import json
import errno
import logging
import hashlib

from redfish.rest.v1 import RestClient
from redfish.rest.containers import StaticRestResponse, RestRequest

from .ris import (RisMonolith)
from .sharedtypes import (JSONEncoder)
from .config import (AutoConfigParser)

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class RdmcError(Exception):
    """Base class for all RDMC Exceptions"""
    errcode = 1
    def __init__(self, message):
        Exception.__init__(self, message)

class InvalidCommandLineError(RdmcError):
    """Raised when user enter incorrect command line arguments"""
    pass

class FailureDuringCommitError(RdmcError):
    """Raised when there is an error while updating firmware"""
    pass

class UserNotAdminError(RdmcError):
    """Raised when user doesn't have admin priviledges"""
    pass

class UndefinedClientError(Exception):
    """Raised when there are no clients active (usually when user hasn't logged in"""
    pass

class InstanceNotFoundError(Exception):
    """Raised when attempting to select an instance that does not exist"""
    pass

class CurrentlyLoggedInError(Exception):
    """Raised when attempting to select an instance that does not exist"""
    pass

class NothingSelectedError(Exception):
    """Raised when attempting to access an object without first selecting it"""
    pass

class NothingSelectedFilterError(Exception):
    """Raised when the filter applied doesn't match any selection"""
    pass

class NothingSelectedSetError(Exception):
    """Raised when attempting to access an object
        without first selecting it"""
    pass

class InvalidSelectionError(Exception):
    """Raised when selection argument fails to match anything"""
    pass

class IdTokenError(Exception):
    """Raised when BIOS password credentials have not been provided"""
    pass

class ValueChangedError(Exception):
    """Raised if user tries to set/commit un-updated value from monolith"""
    pass

class LoadSkipSettingError(Exception):
    """Raised when one or more settings are absent in given server"""
    pass

class InvalidPathError(Exception):
    """Raised when requested path is not found"""
    pass

class UnableToObtainIloVersionError(Exception):
    """Raised when iloversion is missing from default path"""
    pass

class IncompatibleiLOVersionError(Exception):
    """Raised when the iLO version is above or below the required \
    version"""
    pass

class ValidationError(Exception):
    """Raised when there is a problem with user input"""
    def __init__(self, errlist):
        super(ValidationError, self).__init__(errlist)
        self._errlist = errlist

    def get_errors(self):
        """Wrapper function to return error list"""
        return self._errlist

class IloResponseError(Exception):
    """Raised when iLO returns with a non 200 response"""
    pass

class EmptyRaiseForEAFP(Exception):
    """Raised when you need to check for issues and take different action."""
    pass

class IncorrectPropValue(Exception):
    """Raised when you incorrect value to for the associated property"""
    pass

class RmcConfig(AutoConfigParser):
    """RMC config object"""
    def __init__(self, filename=None):
        """Initialize RmcConfig

        :param filename: file name to be used for Rmcconfig loading.
        :type filename: str

        """
        AutoConfigParser.__init__(self, filename=filename)
        self._sectionname = 'redfish'
        self._configfile = filename
        self._ac__logdir = os.getcwd()
        self._ac__cache = True
        self._ac__url = ''
        self._ac__username = ''
        self._ac__password = ''
        self._ac__sslcert = ''
        self._ac__commit = ''
        self._ac__format = ''
        self._ac__iloschemadir = ''
        self._ac__biosschemadir = ''
        self._ac__cachedir = ''
        self._ac__savefile = ''
        self._ac__loadfile = ''
        self._ac__biospasswordword = ''

    def get_configfile(self):
        """The current configuration file"""
        return self._configfile

    def set_configfile(self, config_file):
        """Set the current configuration file

        :param config_file: file name to be used for Rmcconfig loading.
        :type config_file: str

        """
        self._configfile = config_file

    def get_logdir(self):
        """Get the current log directory"""
        return self._get('logdir')

    def set_logdir(self, value):
        """Set the current log directory

        :param value: current working directory for logging
        :type value: str

        """
        return self._set('logdir', value)

    def get_cache(self):
        """Get the config file cache status"""

        if isinstance(self._get('cache'), bool):
            return self._get('cache')

        return self._get('cache').lower() in ("yes", "true", "t", "1")

    def set_cache(self, value):
        """Get the config file cache status

        :param value: status of config file cache
        :type value: bool

        """
        return self._set('cache', value)

    def get_url(self):
        """Get the config file URL"""
        url = self._get('url')
        url = url[:-1] if url.endswith('/') else url

        return url

    def set_url(self, value):
        """Set the config file URL

        :param value: URL path for the config file
        :type value: str

        """
        return self._set('url', value)

    def get_username(self):
        """Get the config file user name"""
        return self._get('username')

    def set_username(self, value):
        """Set the config file user name

        :param value: user name for config file
        :type value: str

        """
        return self._set('username', value)

    def get_password(self):
        """Get the config file password"""
        return self._get('password')

    def set_password(self, value):
        """Set the config file password

        :param value: password for config file
        :type value: str

        """
        return self._set('password', value)

    def get_commit(self):
        """Get the config file commit status"""
        return self._get('commit')

    def set_commit(self, value):
        """Set the config file commit status

        :param value: commit status
        :type value: str

        """
        return self._set('commit', value)

    def get_format(self):
        """Get the config file default format"""
        return self._get('format')

    def set_format(self, value):
        """Set the config file default format

        :param value: set the config file format
        :type value: str

        """
        return self._set('format', value)

    def get_schemadir(self):
        """Get the config file schema directory"""
        return self._get('iloschemadir')

    def set_schemadir(self, value):
        """Set the config file schema directory

        :param value: config file schema directory
        :type value: str

        """
        return self._set('iloschemadir', value)

    def get_biosschemadir(self):
        """Get the config file BIOS schema directory"""
        return self._get('biosschemadir')

    def set_biosschemadir(self, value):
        """Set the config file BIOS schema directory

        :param value: config file BIOS schema directory
        :type value: str

        """
        return self._set('biosschemadir', value)

    def get_cachedir(self):
        """Get the config file cache directory"""
        return self._get('cachedir')

    def set_cachedir(self, value):
        """Set the config file cache directory

        :param value: config file cache directory
        :type value: str

        """
        return self._set('cachedir', value)

    def get_defaultsavefilename(self):
        """Get the config file default save name"""
        return self._get('savefile')

    def set_defaultsavefilename(self, value):
        """Set the config file default save name

        :param value: config file save name
        :type value: str

        """
        return self._set('savefile', value)

    def get_defaultloadfilename(self):
        """Get the config file default load name"""
        return self._get('loadfile')

    def set_defaultloadfilename(self, value):
        """Set the config file default load name

        :param value: name of config file to load by default
        :type value: str

        """
        return self._set('loadfile', value)

    def get_bios_password(self):
        """Get the config file BIOS password"""
        return self._get('biospasswordword')

    def set_bios_password(self, value):
        """Set the config file BIOS password

        :param value: BIOS password for config file
        :type value: str

        """
        return self._set('biospasswordword', value)

    def get_proxy(self):
        """Get proxy value to be set for communication"""
        return self._get('proxy')

    def set_proxy(self, value):
        """Set proxy value for communication"""
        return self._set('proxy', value)

    def get_ssl_cert(self):
        """Get proxy value to be set for communication"""
        return self._get('sslcert')

    def set_ssl_cert(self, value):
        """Set proxy value for communication"""
        return self._set('sslcert', value)

class RmcCacheManager(object):
    """Manages caching/uncaching of data for RmcApp"""
    def __init__(self, rmc):
        """Initialize RmcCacheManager

        :param rmc: RmcApp to be managed
        :type rmc: RmcApp object

        """
        self._rmc = rmc

        self.encodefunct = lambda data: data
        self.decodefunct = lambda data: data

class RmcFileCacheManager(RmcCacheManager):
    """RMC file cache manager"""
    def __init__(self, rmc):
        super(RmcFileCacheManager, self).__init__(rmc)

    def logout_del_function(self, url=None):
        """Helper function for logging out a specific URL

        :param url: The URL to perform a logout request on.
        :type url: str.

        """
        cachedir = self._rmc.config.get_cachedir()
        indexfn = os.path.join(cachedir, "index") #%s\\index' % cachedir
        sessionlocs = []

        if os.path.isfile(indexfn):
            try:
                indexfh = open(indexfn, 'r')
                index_cache = json.load(indexfh)
                indexfh.close()

                for index in index_cache:
                    if url:
                        if url in index['url']:
                            os.remove(os.path.join(cachedir, index['href']))
                            break
                    else:
                        if os.path.isfile(os.path.join(cachedir, index['href'])):
                            monolith = open(os.path.join(cachedir, index['href']), 'r')
                            data = json.load(monolith)
                            monolith.close()
                            for item in data:
                                if 'login' in item and 'session_location' in data['login']:
                                    if 'blobstore' in data['login']['url']:
                                        loc = data['login']['session_location']\
                                                .split('//')[-1]
                                        sesurl = None
                                    else:
                                        loc = data['login']['session_location']\
                                                .split(data['login']['url'])[-1]
                                        sesurl = data['login']['url']
                                    sessionlocs.append((loc, sesurl,\
                                                self._rmc._cm.decodefunct\
                                                (data['login']['session_key'])))

                        os.remove(os.path.join(cachedir, index['href']))
            except BaseException as excp:
                LOGGER.warning('Unable to read cache data %s', excp)

        return sessionlocs

    def uncache_rmc(self, creds=None, enc=False):
        """Simple monolith uncache function"""
        cachedir = self._rmc.config.get_cachedir()
        indexfn = '%s/index' % cachedir

        if os.path.isfile(indexfn):
            try:
                indexfh = open(indexfn, 'r')
                index_cache = json.load(indexfh)
                indexfh.close()

                for index in index_cache:
                    clientfn = index['href']
                    self._uncache_client(clientfn, creds=creds, enc=enc)
            except BaseException as excp:
                LOGGER.warning('Unable to read cache data %s', excp)

    def _uncache_client(self, cachefn, creds=None, enc=False):
        """Complex monolith uncache function

        :param cachefn: The cache file name.
        :type cachefn: str.

        """
        cachedir = self._rmc.config.get_cachedir()
        clientsfn = '%s/%s' % (cachedir, cachefn)

        if os.path.isfile(clientsfn):
            try:
                clientsfh = open(clientsfn, 'r')
                client = json.load(clientsfh)
                clientsfh.close()

                if 'login' not in client:
                    return

                login_data = client['login']
                if 'url' not in login_data:
                    return

                self._rmc.typepath.getgen(login_data.get('ilo'), \
                                 url=login_data.get('url'), \
                                 isredfish=login_data.get('redfish', None), \
                                 ca_certs=login_data.get('ca_certs', None))
                if creds and login_data.get('url', '').startswith('blobstore://'):
                    if enc:
                        creds['username'] = self._rmc._cm.decodefunct(creds['username'])
                        creds['password'] = self._rmc._cm.decodefunct(creds['password'])
                    login_data['username'] = creds['username']
                    login_data['password'] = creds['password']

                redfishinst = RestClient(\
                    username=login_data.get('username', 'Administrator'), \
                    password=login_data.get('password', None), \
                    base_url=login_data.get('url', None), \
                    biospassword=login_data.get('bios_password', None), \
                    is_redfish=login_data.get('redfish', None), \
                    default_prefix=self._rmc.typepath.defs.startpath, \
                    proxy=login_data.get('proxy', None), \
                    ca_certs=login_data.get('ca_certs', None))
                if login_data.get('authorization_key'):
                    redfishinst.basic_auth = login_data.get('authorization_key')
                elif login_data.get('session_key'):
                    redfishinst.session_key = \
                                            self._rmc._cm.decodefunct(login_data.get('session_key'))
                    redfishinst.session_location = login_data.get('session_location')

                if 'selector' in client:
                    self._rmc.selector = client['selector']

                getdata = client['get']
                for key in list(getdata.keys()):
                    if key == redfishinst.default_prefix:
                        restreq = RestRequest(method='GET', path=key)
                        getdata[key]['restreq'] = restreq
                        redfishinst.root = StaticRestResponse(**getdata[key])
                        break

                self._rmc.monolith = RisMonolith(redfishinst, self._rmc.typepath)
                self._rmc.monolith.load_from_dict(client['monolith'])
                self._rmc.redfishinst = redfishinst
                #make sure root is there
                _ = redfishinst.root
                self._rmc.typepath.defineregschemapath(redfishinst.root.dict)
            except BaseException as excp:
                LOGGER.warning('Unable to read cache data %s', excp)

    def cache_rmc(self):
        """Caching function for monolith"""
        if not self._rmc.cache:
            return

        cachedir = self._rmc.config.get_cachedir()
        if not os.path.isdir(cachedir):
            try:
                os.makedirs(cachedir)
            except OSError as ex:
                if ex.errno == errno.EEXIST:
                    pass
                else:
                    raise

        index_map = dict()
        index_cache = list()

        if self._rmc.redfishinst:
            shaobj = hashlib.new("SHA256")
            shaobj.update(self._rmc.redfishinst.base_url.encode('utf-8'))
            md5str = shaobj.hexdigest()

            index_map[self._rmc.redfishinst.base_url] = md5str
            index_data = dict(url=self._rmc.redfishinst.base_url, href='%s' % md5str,)
            index_cache.append(index_data)

            indexfh = open('%s/index' % cachedir, 'w')
            json.dump(index_cache, indexfh, indent=2, cls=JSONEncoder)
            indexfh.close()

        if self._rmc.redfishinst:
            login_data = dict(\
                username=None, \
                password=None, url=self._rmc.redfishinst.base_url, \
                session_key=self._rmc._cm.encodefunct(self._rmc.redfishinst.session_key), \
                session_location=self._rmc.redfishinst.session_location, \
                authorization_key=self._rmc.redfishinst.basic_auth, \
                bios_password=self._rmc.redfishinst.bios_password, \
                redfish=self._rmc.monolith.is_redfish, \
                ilo=self._rmc.typepath.ilogen,\
                proxy=self._rmc.redfishinst.proxy,\
                ca_certs=self._rmc.redfishinst.connection.\
                                                        _connection_properties.get('ca_certs',None))

            clients_data = dict(selector=self._rmc.selector, login=login_data, \
                     monolith=self._rmc.monolith, get=self._rmc.monolith.paths)

            clientsfh = open('%s/%s' % (cachedir, \
                                     index_map[self._rmc.redfishinst.base_url]), 'w')

            json.dump(clients_data, clientsfh, indent=2, cls=JSONEncoder)
            clientsfh.close()
