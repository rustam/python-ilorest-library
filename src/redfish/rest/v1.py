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
"""Helper module for working with REST technology."""

#---------Imports---------

import os
import time
import gzip
import json
import base64
import hashlib
import logging
import platform

from functools import partial
from collections import (OrderedDict)

import urllib3

from urllib3 import ProxyManager

try:
    urllib3.disable_warnings()
    from urllib3.contrib.socks import SOCKSProxyManager
except ImportError:
    pass

#Added for py3 compatibility
import six

from six import BytesIO
from six import StringIO
from six import string_types
from six.moves import http_client
from six.moves.urllib.parse import urlparse, urlencode

from redfish.hpilo.rishpilo import HpIloChifPacketExchangeError
from redfish.hpilo.risblobstore2 import BlobStore2, Blob2OverrideError, \
                            Blob2SecurityError

#---------End of imports---------


#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class RetriesExhaustedError(Exception):
    """Raised when retry attempts have been exhausted."""
    pass

class InvalidCredentialsError(Exception):
    """Raised when invalid credentials have been provided."""
    pass

class ServerDownOrUnreachableError(Exception):
    """Raised when server is unreachable."""
    pass

class ChifDriverMissingOrNotFound(Exception):
    """Raised when chif driver is missing or not found."""
    pass

class DecompressResponseError(Exception):
    """Raised when decompressing response failed."""
    pass

class JsonDecodingError(Exception):
    """Raised when there is an error in json data."""
    pass

class SecurityStateError(Exception):
    """Raised when there is a strict security state without authentication."""
    pass

class RisObject(dict):
    """Converts a JSON/Rest dict into a object so you can use .property
    notation"""
    __getattr__ = dict.__getitem__

    def __init__(self, d):
        """Initialize RisObject

        :param d: dictionary to be parsed
        :type d: dict

        """
        super(RisObject, self).__init__()
        self.update(**dict((k, self.parse(value)) \
                           for k, value in list(d.items())))

    @classmethod
    def parse(cls, value):
        """Parse for RIS value

        :param cls: class referenced from class method
        :type cls: RisObject
        :param value: value to be parsed
        :type value: data type
        :returns: returns parsed value

        """
        if isinstance(value, dict):
            return cls(value)
        elif isinstance(value, list):
            return [cls.parse(i) for i in value]

        return value

class RestRequest(object):
    """Holder for Request information"""
    def __init__(self, path, method='GET', data='', url=None):
        """Initialize RestRequest

        :param path: path within tree
        :type path: str
        :param method: method to be implemented
        :type method: str
        :param body: body payload for the rest call
        :type body: dict

        """
        self._path = path
        self._body = data
        self._method = method
        self.url = url

    @property
    def path(self):
        """Return object path"""
        return self._path

    @property
    def method(self):
        """Return object method"""
        return self._method

    @property
    def body(self):
        """Return object body"""
        return self._body

    def __str__(self):
        """Format string"""
        body = '' if not self._body else self._body
        try:
            return "{} {}\n\n{}".format(self.method, self.path, body)
        except:
            return "{} {}\n\n{}".format(self.method, self.path, '')

class RestResponse(object):
    """Returned by Rest requests"""
    def __init__(self, rest_request, http_response):
        """Initialize RestResponse

        :params rest_request: Holder for request information
        :type rest_request: RestRequest object
        :params http_response: Response from HTTP
        :type http_response: HTTPResponse

        """
        self._read = None
        self._status = None
        self._headers = None
        self._session_key = None
        self._session_location = None
        self._rest_request = rest_request
        self._http_response = http_response
        self._read = self._http_response.data if http_response is not None\
                                                                     else None
        self.ori = self._read

    @property
    def read(self):
        """Wrapper around httpresponse.content"""
        if self._read and not isinstance(self._read, six.text_type):
            self._read = self._read.decode("utf-8", "ignore")
        return self._read

    @read.setter
    def read(self, read):
        """Property for setting _read

        :param read: The data to set to read.
        :type read: str.

        """
        if read is not None:
            if isinstance(read, dict):
                read = json.dumps(read, indent=4)
            self._read = read

    def getheaders(self):
        """Property for accessing the headers"""
        return dict(self._http_response.headers) if self._http_response\
                                            is not None else self._headers

    def getheader(self, name):
        """Property for accessing an individual header

        :param name: The header name to retrieve.
        :type name: str.
        :returns: returns a header from HTTP response

        """
        return self._http_response.headers.get(name) if self._http_response\
                                        is not None else self._headers.get(name)

    def loaddict(self, newdict):
        """Property for setting JSON data

        :param newdict: The string data to set as JSON data.
        :type newdict: str.

        """
        self._read = json.dumps(newdict, indent=4)

    @property
    def dict(self):
        """Property for accessing the data as an dict"""
        return json.loads(self.read)

    @property
    def obj(self):
        """Property for accessing the data as an object"""
        return RisObject.parse(self.dict)

    @property
    def status(self):
        """Property for accessing the status code"""
        if self._status:
            return self._status

        return self._http_response.status if self._http_response \
                                                is not None else self._status

    @property
    def session_key(self):
        """Property for accessing the saved session key"""
        if self._session_key:
            return self._session_key

        self._session_key = self.getheader('x-auth-token')
        return self._session_key

    @property
    def session_location(self):
        """Property for accessing the saved session location"""
        if self._session_location:
            return self._session_location

        self._session_location = self.getheader('location')
        return self._session_location

    @property
    def request(self):
        """Property for accessing the saved http request"""
        return self._rest_request

    @property
    def path(self):
        """Return object path"""
        return self.request.path

    def __str__(self):
        """Class string formatter"""
        headerstr = ''
        for kiy, val in self.getheaders().items():
            headerstr += '%s %s\n' % (kiy, val)

        return "%(status)s\n%(headerstr)s\n\n%(body)s" % \
                            {'status': self.status, 'headerstr': headerstr, \
                             'body': self.read}

class JSONEncoder(json.JSONEncoder):
    """JSON Encoder class"""
    def default(self, obj):
        """Set defaults in JSON encoder class

        :param obj: object to be encoded into JSON.
        :type obj: RestResponse object.
        :returns: returns a JSON ordered dict

        """
        if isinstance(obj, RestResponse):
            jsondict = OrderedDict()
            jsondict['Status'] = obj.status
            jsondict['Headers'] = obj.getheaders()

            if obj.read:
                jsondict['Content'] = obj.dict

            return jsondict

        return json.JSONEncoder.default(self, obj)

class JSONDecoder(json.JSONDecoder):
    """Custom JSONDecoder that understands our types"""
    def decode(self, json_string):
        """Decode JSON string

        :param json_string: The JSON string to be decoded into usable data.
        :type json_string: str.
        :returns: returns a parsed dict

        """
        parsed_dict = super(JSONDecoder, self).decode(json_string)
        return parsed_dict

class _FakeSocket(BytesIO):
    """
       slick way to parse a http response.
       http://pythonwise.blogspot.com/2010/02/parse-http-response.html
    """
    def makefile(self, *args, **kwargs):
        """Return self object"""
        return self

class RisRestResponse(RestResponse):
    """Returned by Rest requests from RIS"""
    def __init__(self, rest_request, resp_txt):
        """Initialization of RisRestResponse

        :param rest_request: Holder for request information
        :type rest_request: RestRequest object
        :param resp_text: text from response to be buffered and read
        :type resp_text: str

        """
        if not isinstance(resp_txt, string_types):
            resp_txt = "".join(map(chr, resp_txt))
        self._respfh = StringIO(resp_txt)
        self._socket = _FakeSocket(bytearray(list(map(ord, self._respfh.\
                                                      read()))))

        response = http_client.HTTPResponse(self._socket)
        response.begin()
        response.data = response.read()
        response.headers = {ki[0]:ki[1] for ki in response.getheaders()}
        super(RisRestResponse, self).__init__(rest_request, response)

class StaticRestResponse(RestResponse):
    """A RestResponse object used when data is being cached."""
    def __init__(self, **kwargs):
        restreq = None

        if 'restreq' in kwargs:
            restreq = kwargs['restreq']

        super(StaticRestResponse, self).__init__(restreq, None)

        if 'Status' in kwargs:
            self._status = kwargs['Status']

        if 'Headers' in kwargs:
            self._headers = kwargs['Headers']

        if 'session_key' in kwargs:
            self._session_key = kwargs['session_key']

        if 'session_location' in kwargs:
            self._session_location = kwargs['session_location']

        if 'Content' in kwargs:
            content = kwargs['Content']

            if isinstance(content, string_types):
                self._read = content
            else:
                self._read = json.dumps(content)
        else:
            self._read = ''

    def getheaders(self):
        """Function for accessing the headers"""
        returnlist = {}

        if isinstance(self._headers, dict):
            returnlist = self._headers
        elif isinstance(self._headers, (list, tuple)):
            returnlist = {ki[0]:ki[1] for ki in self._headers}
        else:
            for item in self._headers:
                returnlist.update(item.items()[0])

        return returnlist

class AuthMethod(object):
    """AUTH Method class"""
    BASIC = 'basic'
    SESSION = 'session'

class RestClientBase(object):
    """Base class for RestClients"""
    MAX_RETRY = 1

    def __init__(self, base_url, username=None, password=None, \
                 default_prefix='/redfish/v1/', sessionkey=None, \
                 biospassword=None, cache=False, is_redfish=True, \
                 proxy=None):
        """Initialization of the base class RestClientBase

        :param base_url: The URL of the remote system
        :type base_url: str
        :param username: The user name used for authentication
        :type username: str
        :param password: The password used for authentication
        :type password: str
        :param default_prefix: The default root point
        :type default_prefix: str
        :param sessionkey: session key for the current login of base_url
        :type sessionkey: str
        :param biospassword: biospassword for base_url if needed
        :type biospassword: str

        """

        self.base_url = base_url
        self.__username = username
        self.__password = password
        self.__biospassword = biospassword
        self.__url = urlparse(base_url)
        self.__session_key = sessionkey
        self.__authorization_key = None
        self.__session_location = None
        self.__proxy = proxy
        self._conn = None
        self._conn_count = 0
        self.login_url = None
        self.default_prefix = default_prefix
        self.is_redfish = is_redfish

        self.__init_connection(proxy=proxy)
        if not cache:
            self.get_root_object()
        if not cache:
            if self.is_redfish:
                self.login_url = self.root.Links.Sessions['@odata.id']
            else:
                self.login_url = self.root.links.Sessions.href
        self.head = partial(self._rest_request, method='HEAD')
        self.put = partial(self._rest_request, method='PUT')
        self.delete = partial(self._rest_request, method='DELETE')
        self.post = partial(self._rest_request, method='POST')
        self.patch = partial(self._rest_request, method='PATCH')

    def __init_connection(self, url=None, proxy=False):
        """Function for initiating connection with remote server

        :param url: The URL of the remote system
        :type url: str

        """

        self.__url = url if url else self.__url
        if self.get_proxy() and proxy:
            if self.get_proxy().startswith('socks'):
                LOGGER.info("Initializing a SOCKS proxy.")
                http = SOCKSProxyManager(self.get_proxy(), cert_reqs='CERT_NONE')
            else:
                LOGGER.info("Initializing a HTTP proxy.")
                http = ProxyManager(self.get_proxy(), cert_reqs='CERT_NONE')
        else:
            LOGGER.info("Initializing no proxy.")
            http = urllib3.PoolManager(cert_reqs='CERT_NONE')

        self._conn = http.request

    def __destroy_connection(self):
        """Function for closing connection with remote server"""

        self._conn = None
        self._conn_count = 0

    def get_username(self):
        """Return used user name"""
        return self.__username

    def set_username(self, username):
        """Set user name

        :param username: The user name to be set.
        :type username: str

        """
        self.__username = username

    def get_password(self):
        """Return used password"""
        return self.__password

    def set_password(self, password):
        """Set password

        :param password: The password to be set.
        :type password: str

        """
        self.__password = password

    def get_proxy(self):
        """Return used proxy"""
        return self.__proxy

    def set_proxy(self, proxy):
        """Set proxy

        :param proxy: The proxy to be set.
        :type proxy: str

        """
        self.__proxy = proxy

    def get_biospassword(self):
        """Return BIOS password"""
        return self.__biospassword

    def set_biospassword(self, biospassword):
        """Set BIOS password

        :param biospassword: The bios password to be set.
        :type biospassword: str

        """
        self.__biospassword = biospassword

    def get_base_url(self):
        """Return used URL"""
        return self.base_url

    def set_base_url(self, url):
        """Set based URL

        :param url: The URL to be set.
        :type url: str

        """
        self.base_url = url

    def get_session_key(self):
        """Return session key"""
        return self.__session_key

    def set_session_key(self, session_key):
        """Set session key

        :param session_key: The session_key to be set.
        :type session_key: str

        """
        self.__session_key = session_key

    def get_session_location(self):
        """Return session location"""
        return self.__session_location

    def set_session_location(self, session_location):
        """Set session location

        :param session_location: The session_location to be set.
        :type session_location: str

        """
        self.__session_location = session_location

    def get_authorization_key(self):
        """Return authorization key"""
        return self.__authorization_key

    def set_authorization_key(self, authorization_key):
        """Set authorization key

        :param authorization_key: The authorization_key to be set.
        :type authorization_key: str

        """
        self.__authorization_key = authorization_key

    def get_root_object(self):
        """Perform an initial get and store the result"""
        try:
            resp = self.get(str(self.__url.path)+self.default_prefix)
        except Exception as excp:
            raise excp

        if resp.status != 200:
            raise ServerDownOrUnreachableError("Server not reachable, " \
                                               "return code: %d" % resp.status)

        content = resp.read
        root_data = None

        try:
            root_data = json.loads(content, "ISO-8859-1")
        except TypeError:
            root_data = json.loads(content)
        except ValueError as excp:
            LOGGER.error("%s for JSON content %s", excp, content)
            raise

        self.root = RisObject.parse(root_data)
        self.root_resp = resp

    def get(self, path, args=None, headers=None):
        """Perform a GET request

        :param path: the URL path.
        :param path: str.
        :params args: the arguments to get.
        :params args: dict.
        :returns: returns a rest request with method 'Get'

        """
        try:
            return self._rest_request(path, method='GET', args=args, \
                                                                headers=headers)
        except ValueError:
            LOGGER.debug("Error in json object getting path: %s", path)
            raise JsonDecodingError('Error in json decoding.')

    def _get_req_headers(self, headers=None, providerheader=None, \
                                                        optionalpassword=None):
        """Get the request headers

        :param headers: additional headers to be utilized
        :type headers: str
        :param provideheader: provider id for the header.
        :type providerheader: str.
        :param optionalpassword: provide password for authentication.
        :type optionalpassword: str.
        :returns: returns headers

        """
        headers = headers if isinstance(headers, dict) else dict()

        if providerheader:
            headers['X-CHRP-RIS-Provider-ID'] = providerheader

        token = self.__biospassword if self.__biospassword else optionalpassword
        if token:
            token = optionalpassword.encode('utf-8') if type(\
                optionalpassword).__name__ in 'basestr' else token
            hash_object = hashlib.new('SHA256')
            hash_object.update(token)
            headers['X-HPRESTFULAPI-AuthToken'] = hash_object.hexdigest().\
                                                    upper()

        if self.__session_key:
            headers['X-Auth-Token'] = self.__session_key
        elif self.__authorization_key:
            headers['Authorization'] = self.__authorization_key

        if self.is_redfish:
            headers['OData-Version'] = '4.0'

        return headers

    def set_root(self, root):
        """ Takes a root and set it as the current client root"""
        self.root = root

        if self.is_redfish:
            self.login_url = self.root.obj.Links.Sessions['@odata.id']
        else:
            self.login_url = self.root.obj.links.Sessions.href

    def _rest_request(self, path, method='GET', args=None, body=None, \
        headers=None, optionalpassword=None, providerheader=None):
        """Rest request main function

        :param path: path within tree
        :type path: str
        :param method: method to be implemented
        :type method: str
        :param args: the arguments for method
        :type args: dict
        :param body: body payload for the rest call
        :type body: dict
        :param headers: provide additional headers
        :type headers: dict
        :param optionalpassword: provide password for authentication
        :type optionalpassword: str
        :param provideheader: provider id for the header
        :type providerheader: str
        :returns: returns a RestResponse object

        """
        files = None
        request_args = {}
        external_uri = True if 'redfish.dmtf.org' in path else False
        headers = {} if external_uri else self._get_req_headers(headers, providerheader, \
                                    optionalpassword)
        reqpath = path.replace('//', '/') if not external_uri else path

        if body is not None:
            if body and isinstance(body, list) and isinstance(body[0], tuple):
                files = body
                body = None
            elif isinstance(body, (dict, list)):
                headers['Content-Type'] = 'application/json'
                body = json.dumps(body)
            elif not files:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                body = urlencode(body)

            if method == 'PUT':
                resp = self._rest_request(method='HEAD', path=path)

                try:
                    if resp.getheader('content-encoding') == 'gzip':
                        buf = StringIO()
                        gfile = gzip.GzipFile(mode='wb', fileobj=buf)

                        try:
                            gfile.write(str(body))
                        finally:
                            gfile.close()

                        compresseddata = buf.getvalue()
                        if compresseddata:
                            data = bytearray()
                            data.extend(memoryview(compresseddata))
                            body = data
                except BaseException as excp:
                    LOGGER.error('Error occur while compressing body: %s', excp)
                    raise

        if args:
            if method == 'GET':
                reqpath += '?' + urlencode(args)
            elif method == 'PUT' or method == 'POST' or method == 'PATCH':
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                body = urlencode(args)

        restreq = RestRequest(path, method, data=files if files else body, \
                              url=self.base_url)

        attempts = 1
        restresp = None
        while attempts <= self.MAX_RETRY:
            if LOGGER.isEnabledFor(logging.DEBUG):
                try:
                    logbody = None
                    if restreq.body:
                        if restreq.body[0] == '{':
                            logbody = restreq.body
                        else:
                            raise KeyError()
                    if restreq.method in ['POST', 'PATCH']:
                        debugjson = json.loads(restreq.body)
                        if 'Password' in debugjson.keys():
                            debugjson['Password'] = '******'
                        if 'OldPassword' in debugjson.keys():
                            debugjson['OldPassword'] = '******'
                        if 'NewPassword' in debugjson.keys():
                            debugjson['NewPassword'] = '******'
                        logbody = json.dumps(debugjson)
                    LOGGER.debug('HTTP REQUEST: %s\n\tPATH: %s\n\t'\
                                'HEADERS: %s\n\tBODY: %s', restreq.method, restreq.path, headers, \
                                 logbody)
                except:
                    LOGGER.debug('HTTP REQUEST: %s\n\tPATH: %s\n\tBODY: %s', restreq.method, \
                                                                restreq.path, 'binary body')
            LOGGER.info('Attempt %s of %s', attempts, path)

            try:
                while True:
                    if self._conn is None or external_uri:
                        self.__init_connection(proxy=external_uri)

                    inittime = time.time()
                    reqfullpath = self.base_url+reqpath if not external_uri else reqpath
                    request_args['headers'] = headers
                    if files:
                        request_args['fields'] = files
                    else:
                        request_args['body'] = body
                    resp = self._conn(method, reqfullpath, **request_args)

                    self._conn_count += 1
                    endtime = time.time()
                    LOGGER.info('Response Time to %s: %s seconds.', restreq.path, \
                                                                            str(endtime-inittime))

                    if resp.status not in list(range(300, 399)) or resp.status == 304:
                        break

                    newloc = resp.headers.get('location')
                    newurl = urlparse(newloc)

                    reqpath = newurl.path
                    self.__init_connection(newurl, proxy=external_uri)

                restresp = RestResponse(restreq, resp)

            except Exception as excp:
                attempts = attempts + 1
                LOGGER.info('Retrying %s [%s]', path, excp)
                time.sleep(1)

                self.__init_connection(proxy=external_uri)
                continue
            else:
                break

        if attempts <= self.MAX_RETRY:
            if LOGGER.isEnabledFor(logging.DEBUG):
                headerstr = ''
                if restresp is not None:
                    respheader = restresp.getheaders()
                    for kiy, headerval in respheader.items():
                        headerstr += '\t' + kiy + ': ' + headerval + '\n'
                    try:
                        LOGGER.debug('HTTP RESPONSE for %s:\nCode:%s\nHeaders:'\
                                '\n%s\nBody Response of %s: %s', restresp.request.path,\
                                str(restresp._http_response.status)+ ' ' + \
                                restresp._http_response.reason, \
                                headerstr, restresp.request.path, restresp.read\
                                .encode('ascii', 'ignore'))
                    except:
                        LOGGER.debug('HTTP RESPONSE:\nCode:%s', restresp)
                else:
                    LOGGER.debug('HTTP RESPONSE: No HTTP Response obtained')

            return restresp
        else:
            raise RetriesExhaustedError()

    def login(self, username=None, password=None, auth=AuthMethod.BASIC):
        """Login and start a REST session.  Remember to call logout() when
        you are done.

        :param username: the user name.
        :type username: str.
        :param password: the password.
        :type password: str.
        :param auth: authentication method
        :type auth: object/instance of class AuthMethod

        """

        self.__username = username if username else self.__username
        self.__password = password if password else self.__password

        if auth == AuthMethod.BASIC:
            auth_key = base64.b64encode(('{}:{}'.format(self.__username, \
                            self.__password)).encode('utf-8')).decode('utf-8')
            self.__authorization_key = 'Basic {}'.format(auth_key)

            headers = dict()
            headers['Authorization'] = self.__authorization_key

            respvalidate = self._rest_request('{}{}'.format(self.__url.path, \
                                            self.login_url), headers=headers)

            if respvalidate.status == 401:
                try:
                    if self.is_redfish:
                        delay = self.root.Oem.Hp.Sessions.LoginFailureDelay
                    else:
                        delay = self.root.Oem.Hpe.Sessions.LoginFailureDelay
                except KeyError:
                    delay = 5
                raise InvalidCredentialsError(delay)
        elif auth == AuthMethod.SESSION:
            data = dict()
            data['UserName'] = self.__username
            data['Password'] = self.__password

            headers = dict()
            resp = self._rest_request(self.login_url, method="POST", \
                                                    body=data, headers=headers)
            try:
                LOGGER.info(json.loads('%s', resp.read))
            except ValueError:
                pass
            LOGGER.info('Login returned code %s: %s', resp.status, resp.read)

            self.__session_key = resp.session_key
            self.__session_location = resp.session_location

            if not self.__session_key and not resp.status == 200:
                try:
                    if self.is_redfish:
                        delay = self.root.Oem.Hpe.Sessions.LoginFailureDelay
                    else:
                        delay = self.root.Oem.Hp.Sessions.LoginFailureDelay
                except KeyError:
                    delay = 5

                raise InvalidCredentialsError(delay)
            else:
                self.set_username(None)
                self.set_password(None)
        else:
            pass

    def logout(self):
        """ Logout of session. YOU MUST CALL THIS WHEN YOU ARE DONE TO FREE
        UP SESSIONS"""

        if self.__session_key:
            if self.base_url == "blobstore://.":
                session_loc = self.__session_location.replace("https://", '')
                session_loc = session_loc.replace(' ', '%20')
            else:
                session_loc = self.__session_location.replace(self.base_url, '')

            resp = self.delete(session_loc)
            LOGGER.info("User logged out: %s", resp.read)

            self.__session_key = None
            self.__session_location = None
            self.__authorization_key = None

class HttpClient(RestClientBase):
    """A client for Rest"""
    pass

class Blobstore2RestClient(RestClientBase):
    """A client for Rest that uses the blobstore2 as the transport"""
    _http_vsn_str = 'HTTP/1.1'

    def __init__(self, base_url, default_prefix='/rest/v1', username=None, \
                            password=None, sessionkey=None, is_redfish=False, \
                            cache=False, proxy=None):

        """Initialize Blobstore2RestClient

        :param base_url: The url of the remote system
        :type base_url: str
        :param username: The username used for authentication
        :type username: str
        :param password: The password used for authentication
        :type password: str
        :param default_prefix: The default root point
        :type default_prefix: str
        :param biospassword: biospassword for base_url if needed
        :type biospassword: str
        :param sessionkey: sessionkey for the current login of base_url
        :type sessionkey: str
        :param is_redfish: flag for checking redfish
        :type is_redfish: bool

        """
        self.is_redfish = is_redfish
        self.creds = not cache

        try:
            if not cache:
                correctcreds = BlobStore2.initializecreds(username=username, \
                                                          password=password)
                bs2 = BlobStore2()
                if not correctcreds:
                    security_state = int(bs2.get_security_state())
                    raise SecurityStateError(security_state)
        except Blob2SecurityError:
            raise InvalidCredentialsError(0)
        except HpIloChifPacketExchangeError as excp:
            LOGGER.info("Exception: %s", str(excp))
            raise ChifDriverMissingOrNotFound()
        except Exception as excp:
            if excp.message == 'chif':
                raise ChifDriverMissingOrNotFound()
            else:
                raise

        super(Blobstore2RestClient, self).__init__(base_url, \
                        username=username, password=password, \
                        default_prefix=default_prefix, sessionkey=sessionkey,\
                        cache=cache, is_redfish=is_redfish)

    def updatecredentials(self):
        """update credentials for high security if needed
        """
        if not self.creds:
            user = self._RestClientBase__username
            password = self._RestClientBase__password
            try:
                correctcreds = BlobStore2.initializecreds(username=user, \
                                                          password=password)
                if not correctcreds:
                    security_state = int(BlobStore2().get_security_state())
                    raise SecurityStateError(security_state)
            except Blob2SecurityError:
                raise InvalidCredentialsError(0)
            except Exception:
                raise

            self.creds = True

    def _rest_request(self, path='', method="GET", args=None, body=None,
                      headers=None, optionalpassword=None, providerheader=None):
        """Rest request for blob store client

        :param path: path within tree
        :type path: str
        :param method: method to be implemented
        :type method: str
        :param args: the arguments for method
        :type args: dict
        :param body: body payload for the rest call
        :type body: dict
        :param headers: provide additional headers
        :type headers: dict
        :param optionalpassword: provide password for authentication
        :type optionalpassword: str
        :param provideheader: provider id for the header
        :type providerheader: str
        :return: returns a RestResponse object

        """
        self.updatecredentials()
        headers = self._get_req_headers(headers, providerheader, \
                                                            optionalpassword)

        reqpath = path.replace('//', '/')

        oribody = body
        if body is not None:
            if isinstance(body, (dict, list)):
                headers['Content-Type'] = 'application/json'
                body = json.dumps(body)
            else:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                body = urlencode(body)

            if method == 'PUT':
                resp = self._rest_request(path=path)

                try:
                    if resp.getheader('content-encoding') == 'gzip':
                        buf = StringIO()
                        gfile = gzip.GzipFile(mode='wb', fileobj=buf)

                        try:
                            gfile.write(str(body))
                        finally:
                            gfile.close()

                        compresseddata = buf.getvalue()
                        if compresseddata:
                            data = bytearray()
                            data.extend(memoryview(compresseddata))
                            body = data
                except BaseException as excp:
                    LOGGER.error('Error occur while compressing body: %s', excp)
                    raise

            headers['Content-Length'] = len(body)

        if args:
            if method == 'GET':
                reqpath += '?' + urlencode(args)
            elif method == 'PUT' or method == 'POST' or method == 'PATCH':
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                body = urlencode(args)

        str1 = '{} {} {}\r\n'.format(method, reqpath, \
                                            Blobstore2RestClient._http_vsn_str)
        str1 += 'Host: \r\n'
        str1 += 'Accept-Encoding: identity\r\n'
        for header, value in headers.items():
            str1 += '{}: {}\r\n'.format(header, value)

        str1 += '\r\n'

        if body and len(body) > 0:
            if isinstance(body, bytearray):
                str1 = str1.encode("ASCII") + body
            else:
                str1 += body

        bs2 = BlobStore2()

        if not isinstance(str1, bytearray):
            str1 = str1.encode("ASCII")

        if LOGGER.isEnabledFor(logging.DEBUG):
            try:
                logbody = None
                if body:
                    if body[0] == '{':
                        logbody = body
                    else:
                        raise
                if method in ['POST', 'PATCH']:
                    debugjson = json.loads(body)
                    if 'Password' in debugjson.keys():
                        debugjson['Password'] = '******'
                    if 'OldPassword' in debugjson.keys():
                        debugjson['OldPassword'] = '******'
                    if 'NewPassword' in debugjson.keys():
                        debugjson['NewPassword'] = '******'
                    logbody = json.dumps(debugjson)

                LOGGER.debug('Blobstore REQUEST: %s\n\tPATH: %s\n\tHEADERS: '\
                             '%s\n\tBODY: %s', method, str(headers), path, logbody)
            except:
                LOGGER.debug('Blobstore REQUEST: %s\n\tPATH: %s\n\tHEADERS: '\
                             '%s\n\tBODY: %s', method, str(headers), path, 'binary body')

        inittime = time.time()

        for idx in range(5):
            try:
                resp_txt = bs2.rest_immediate(str1)
                break
            except Blob2OverrideError as excp:
                if idx == 4:
                    raise Blob2OverrideError(2)
                else:
                    continue

        endtime = time.time()

        bs2.channel.close()

        LOGGER.info("iLO Response Time to %s: %s secs.", path, str(endtime-inittime))
        #Dummy response to support a bad host response
        if len(resp_txt) == 0:
            resp_txt = "HTTP/1.1 500 Not Found\r\nAllow: " \
            "GET\r\nCache-Control: no-cache\r\nContent-length: " \
            "0\r\nContent-type: text/html\r\nDate: Tues, 1 Apr 2025 " \
            "00:00:01 GMT\r\nServer: " \
            "HP-iLO-Server/1.30\r\nX_HP-CHRP-Service-Version: 1.0.3\r\n\r\n\r\n"

        restreq = RestRequest(path, method, data=body, url=self.base_url)
        rest_response = RisRestResponse(restreq, resp_txt)

        if rest_response.status in range(300, 399) and \
                                                    rest_response.status != 304:
            newloc = rest_response.getheader("location")
            newurl = urlparse(newloc)

            rest_response = self._rest_request(newurl.path, method, args, \
                               oribody, headers, optionalpassword, \
                               providerheader)

        try:
            if rest_response.getheader('content-encoding') == 'gzip':
                if hasattr(gzip, "decompress"):
                    rest_response.read = gzip.decompress(rest_response.ori)
                else:
                    compressedfile = StringIO(rest_response.ori)
                    decompressedfile = gzip.GzipFile(fileobj=compressedfile)
                    rest_response.read = decompressedfile.read()
        except Exception:
            pass
        if LOGGER.isEnabledFor(logging.DEBUG):
            headerstr = ''
            headerget = rest_response.getheaders()
            for header in headerget:
                headerstr += '\t' + header + ': ' + headerget[header] + '\n'
            try:
                LOGGER.debug('Blobstore RESPONSE for %s:\nCode: %s\nHeaders:'\
                            '\n%s\nBody of %s: %s', rest_response.request.path,\
                            str(rest_response._http_response.status)+ ' ' + \
                            rest_response._http_response.reason, \
                            headerstr, rest_response.request.path, \
                            rest_response.read)
            except:
                LOGGER.debug('Blobstore RESPONSE for %s:\nCode:%s', \
                             rest_response.request.path, rest_response)
        return rest_response

    def _get_req_headers(self, headers=None, providerheader=None, \
                                                        optionalpassword=None):
        """Get the request headers for blob store client

        :param headers: additional headers to be utilized
        :type headers: str
        :param provideheader: provider id for the header
        :type providerheader: str
        :param optionalpassword: provide password for authentication
        :type optionalpassword: str
        :returns: returns request headers

        """
        headers = super(Blobstore2RestClient, self)._get_req_headers(headers, \
                                            providerheader, optionalpassword)
        headers['Accept'] = '*/*'
        headers['Connection'] = 'Keep-Alive'
        return headers

def get_client_instance(base_url=None, username=None, password=None, \
                                default_prefix='/rest/v1', biospassword=None, \
                                sessionkey=None, is_redfish=False, cache=False, \
                                proxy=None):
    """Create and return appropriate RESTful/REDFISH client instance.
    Instantiates appropriate Rest/Redfish object based on existing
    configuration. Use this to retrieve a pre-configured Rest object

    :param base_url: rest host or ip address.
    :type base_url: str.
    :param username: username required to login to server
    :type: str
    :param password: password credentials required to login
    :type password: str
    :param default_prefix: default root to extract tree
    :type default_prefix: str
    :param biospassword: BIOS password for the server if set
    :type biospassword: str
    :param sessionkey: session key credential for current login
    :type sessionkey: str
    :param is_redfish: If True, a Redfish specific header (OData)
    will be added to every request
    :type is_redfish: boolean
    :returns: a client object. Either HTTP or Blobstore.

    """
    if not base_url or base_url.startswith('blobstore://'):
        if platform.system() == 'Windows':
            lib = BlobStore2.gethprestchifhandle()
            BlobStore2.unloadchifhandle(lib)
        else:
            if not os.path.isdir('/dev/hpilo') and \
               not os.path.exists('/dev/char/vmkdriver/hpilo-d0ccb0'):
                raise ChifDriverMissingOrNotFound()

        return Blobstore2RestClient(base_url=base_url, \
                            default_prefix=default_prefix, username=username, \
                            password=password, sessionkey=sessionkey, \
                            is_redfish=is_redfish, cache=cache, proxy=proxy)
    else:
        return HttpClient(base_url=base_url, username=username, \
                          password=password, default_prefix=default_prefix, \
                          biospassword=biospassword, sessionkey=sessionkey, \
                          is_redfish=is_redfish, cache=cache, proxy=proxy)

redfish_client = partial(get_client_instance, default_prefix='/redfish/v1/', \
                         is_redfish=True)
redfish_client.__doc__ = "Create and return appropriate REDFISH client instance."\
            "Instantiates appropriate Redfish object based on existing"\
            "configuration. Use this to retrieve a pre-configured Redfish object"

rest_client = partial(get_client_instance, default_prefix='/rest/v1', \
                      is_redfish=False)
rest_client.__doc__ = "Create and return appropriate REST client instance."\
            "Instantiates appropriate Rest object based on existing"\
            "configuration. Use this to retrieve a pre-configured Rest object"
