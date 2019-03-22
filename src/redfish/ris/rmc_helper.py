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
"""RMC helper implementation"""

#---------Imports---------

import os
import json
import errno
import logging
import hashlib

from functools import partial
from six.moves.urllib.parse import urlparse

import redfish.rest

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

class RmcClient(object):
    """RMC client base class"""
    def __init__(self, url=None, username=None, password=None, sessionkey=None,\
                            typepath=None, biospassword=None, is_redfish=False,\
                            cache=False, proxy=None):
        """Initialized RmcClient
        :param url: redfish host name or IP address.
        :type url: str.
        :param username: user name required to login to server.
        :type: str.
        :param password: password credentials required to login.
        :type password: str.
        :param sessionkey: session key credential for current login
        :type sessionkey: str
        :param typepath: path to be used for client.
        :type typepath: str.
        :param biospassword: BIOS password for the server if set.
        :type biospassword: str.
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type is_redfish: boolean.

        """

        self._rest_client = redfish.rest.v1.get_client_instance \
            (base_url=url, username=username, password=password, \
            sessionkey=sessionkey, default_prefix=typepath.defs.startpath,\
            biospassword=biospassword, cache=cache, is_redfish=is_redfish,\
            proxy=proxy)

        self.typepath = typepath
        self._monolith = RisMonolith(self)
        self.selector = None
        self.get_username = self._rest_client.get_username
        self.set_username = self._rest_client.set_username
        self.set_password = self._rest_client.set_password
        self.get_password = self._rest_client.get_password
        self.get_proxy = self._rest_client.get_proxy
        self.set_proxy = self._rest_client.set_proxy
        self.get_session_key = self._rest_client.get_session_key
        self.get_session_location = self._rest_client.get_session_location
        self.get_authorization_key = self._rest_client.get_authorization_key
        self.login = partial(self._rest_client.login, auth="session")
        self.logout = self._rest_client.logout
        self.updatecredentials = self._rest_client.updatecredentials if \
            hasattr(self._rest_client, 'updatecredentials') else lambda: None
        # self.updatecredentials = getattr(self._rest_client, \
        #                             'updatecredentials', None)
        self.get = self._rest_client.get
        self.head = self._rest_client.head
        self.set = self._rest_client.patch
        self.toolpost = self._rest_client.post
        self.toolput = self._rest_client.put
        self.tooldelete = self._rest_client.delete
        self.get_biospassword = self._rest_client.get_biospassword
        self.set_biospassword = self._rest_client.set_biospassword
        self.get_base_url = self._rest_client.get_base_url
        if self.get_base_url().startswith('blobstore'):
            self.etagstr = 'etag'
        else:
            self.etagstr = 'ETag'

    def get_cache_dirname(self):
        """The rest client's current base URL converted to path"""
        parts = urlparse(self.get_base_url())
        pathstr = '%s/%s' % (parts.netloc, parts.path)
        return pathstr.replace('//', '/')

    def get_monolith(self):
        """The rest client's current monolith"""
        return self._monolith
    monolith = property(get_monolith, None)

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
        indexfn = os.path.join(cachedir, "index")
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
                        if os.path.isfile(os.path.join(cachedir, \
                                                       index['href'])):
                            monolith = open(os.path.join(cachedir, \
                                                         index['href']), 'r')
                            data = json.load(monolith)
                            monolith.close()
                            for item in data:
                                if 'login' in item and 'session_location' in \
                                                                data['login']:
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
                self._rmc.warn('Unable to read cache data %s' % excp)

        return sessionlocs

    def uncache_rmc(self):
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
                    self._uncache_client(clientfn)
            except BaseException as excp:
                self._rmc.warn('Unable to read cache data %s' % excp)

    def _uncache_client(self, cachefn):
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

                self._rmc.getgen(login_data.get('ilo'), \
                                 url=login_data.get('url'), \
                                 isredfish=login_data.get('redfish', None))
                rmc_client = RmcClient(\
                    username=login_data.get('username', 'Administrator'), \
                    password=login_data.get('password', None), \
                    url=login_data.get('url', None), \
                    sessionkey=login_data.get('session_key', None), \
                    biospassword=login_data.get('bios_password', None), \
                    typepath=self._rmc.typepath, \
                    is_redfish=login_data.get('redfish', None),
                    cache=True, proxy=login_data.get('proxy', None))

                rmc_client._rest_client.set_authorization_key(\
                                        login_data.get('authorization_key'))
                rmc_client._rest_client.set_session_key(\
                    self._rmc._cm.decodefunct(login_data.get('session_key')))
                rmc_client._rest_client.set_session_location(\
                                        login_data.get('session_location'))

                if 'selector' in client:
                    rmc_client.selector = client['selector']

                getdata = client['get']
                for key in list(getdata.keys()):
                    if key == rmc_client._rest_client.default_prefix:
                        restreq = redfish.rest.v1.RestRequest(\
                                                    method='GET', path=key)
                        getdata[key]['restreq'] = restreq
                        rmc_client._rest_client.set_root(redfish.rest.v1.\
                                            StaticRestResponse(**getdata[key]))

                rmc_client._monolith = RisMonolith(rmc_client)
                rmc_client._monolith.load_from_dict(client['monolith'])
                self._rmc._rmc_clients = rmc_client
                #make sure root is there
                rmc_client._rest_client.root
                self._rmc.typepath.defineregschemapath(rmc_client._rest_client.root.dict)
            except BaseException as excp:
                self._rmc.warn('Unable to read cache data %s' % excp)

    def cache_rmc(self):
        """Caching function for monolith"""
        if not self._rmc.config.get_cache():
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

        if self._rmc._rmc_clients:
            shaobj = hashlib.new("SHA256")
            shaobj.update(self._rmc._rmc_clients.get_base_url().encode('utf-8'))
            md5str = shaobj.hexdigest()

            index_map[self._rmc._rmc_clients.get_base_url()] = md5str
            index_data = dict(url=self._rmc._rmc_clients.get_base_url(), href='%s' % md5str,)
            index_cache.append(index_data)

            indexfh = open('%s/index' % cachedir, 'w')
            json.dump(index_cache, indexfh, indent=2, cls=JSONEncoder)
            indexfh.close()

        if self._rmc._rmc_clients:
            login_data = dict(\
                username=None, \
                password=None, url=self._rmc._rmc_clients.get_base_url(), \
                session_key=self._rmc._cm.encodefunct(self._rmc._rmc_clients.get_session_key()), \
                session_location=self._rmc._rmc_clients.get_session_location(), \
                authorization_key=self._rmc._rmc_clients.get_authorization_key(), \
                bios_password=self._rmc._rmc_clients.get_biospassword(), \
                redfish=self._rmc._rmc_clients.monolith.is_redfish, \
                ilo=self._rmc._rmc_clients.typepath.ilogen,\
                proxy=self._rmc._rmc_clients.get_proxy())

            clients_data = dict(selector=self._rmc._rmc_clients.selector, login=login_data, \
                     monolith=self._rmc._rmc_clients.monolith, \
                     get=self._rmc._rmc_clients.monolith.paths)

            clientsfh = open('%s/%s' % (cachedir, \
                                     index_map[self._rmc._rmc_clients.get_base_url()]), 'w')

            json.dump(clients_data, clientsfh, indent=2, cls=JSONEncoder)
            clientsfh.close()
