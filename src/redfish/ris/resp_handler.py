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

"""Redfish Error response handler"""
import logging

import jsonpath_rw

from redfish.ris.ris import SessionExpired
from redfish.ris.utils import warning_handler
from redfish.ris.rmc_helper import IloResponseError, IdTokenError, ValueChangedError

#---------Debug logger---------

LOGGER = logging.getLogger()

#---------End of debug logger---------

class ResponseHandler(object):
    """Class to handle error responses from the server."""
    def __init__(self, validaition_mgr, msg_type):
        self.validation_mgr = validaition_mgr
        self.msg_reg_type = msg_type

    def output_resp(self, response, dl_reg=False, print_code=False):
        """ Prints or logs parsed MessageId response.

        :param response: message response of Redfish call.
        :type response: RestResponse.
        :param dl_reg: Flag to download message registries for extra error messaging responses.
        :type dl_reg: bool.
        :param print_code: Flag to print the HTTP response code in all instances.
        :type print_code: bool.

        """
        errmessages = []
        if not dl_reg and response.read:
            errmsgtype = self._get_errmsg_type(response)
            errmessages = self.get_error_messages(regtype=errmsgtype)

        self._invalid_return_handler(response, print_code=print_code, errmessages=errmessages)

    def return_reg(self, response):
        """ Returns the registry entry of the associated MessageId.

        :param response: message response of Redfish call.
        :type response: RestResponse.

        :returns: returns a list of error messages
        """

        contents = None
        errmsgtype = self._get_errmsg_type(response)
        errmessages = self.get_error_messages(regtype=errmsgtype)

        if not errmessages:
            return None
        try:
            contents = response.dict["Messages"][0]["MessageID"].split('.')
        except Exception:
            try:
                contents = response.dict["error"]["@Message.ExtendedInfo"]\
                                                                        [0]["MessageId"].split('.')
            except Exception:
                pass
        if contents:
            for messagetype in list(errmessages.keys()):
                if contents[0] == messagetype:
                    return errmessages[messagetype]
        return None

    @staticmethod
    def _get_errmsg_type(results):
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

    def get_error_messages(self, regtype=None):
        """Handler of error messages from iLO

        :param regtype: registry type to add to list.
        :type regtype: str.

        :returns: returns a list of error messages
        """

        LOGGER.info("Entering validation...")
        errmessages = {}
        reglist = []

        if not self.validation_mgr or regtype == 'no_id':
            return errmessages

        if not self.validation_mgr._classes:
            return None
        for reg in self.validation_mgr.iterregmems():
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
            messages = self.validation_mgr.get_registry_model(getmsg=True, currtype=reg, \
                                    searchtype=self.msg_reg_type)
            if messages:
                errmessages.update(messages)

        return errmessages

    def _invalid_return_handler(self, results, print_code=None, errmessages=None):
        """Main worker function for printing/raising all error messages

        :param results: dict of the results.
        :type results: sict.
        :param errmessages: dict of lists containing the systems error messages.
        :type errmessages: dict.
        :param print_code: Flag to also always print the return code.
        :type print_code: boolean.

        """

        output = ''
        try:
            contents = results.dict["Messages"][0]["MessageID"].split('.')
        except Exception:
            try:
                contents = results.dict["error"]["@Message.ExtendedInfo"][0]["MessageId"].split('.')
            except Exception:
                if results.status == 200 or results.status == 201:
                    if print_code:
                        warning_handler("[%d] The operation completed " \
                                            "successfully.\n" % results.status)
                    else:
                        warning_handler("[%d] The operation completed " \
                                            "successfully.\n" % results.status)
                elif results.status == 412:
                    warning_handler("The property you are trying to " \
                                         "change has been updated. Please " \
                                         "check entry again before manipulating it.\n")
                    raise ValueChangedError("")
                elif results.status == 403:
                    raise IdTokenError()
                else:
                    warning_handler("[%d] No message returned by iLO.\n" % results.status)

                    raise IloResponseError("")
                return

        if results.status == 401 and not contents[-1].lower() == 'insufficientprivilege':
            raise SessionExpired()
        elif results.status == 403:
            raise IdTokenError()
        elif results.status == 412:
            warning_handler("The property you are trying to change " \
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

                        if print_code:
                            warning_handler("[%d] %s\n" % (results.status, output))
                        if results.status == 200 or results.status == 201:
                            warning_handler("{0}\n".format(output))
                        if not results.status == 200 and not results.status == 201:
                            warning_handler("iLO response with code [%d]:"\
                                                 " %s\n" % (results.status, output))
                            raise IloResponseError("")
                        break

                    except IloResponseError as excp:
                        raise excp
                    except Exception:
                        pass
            if not output:
                if results.status == 200 or results.status == 201:
                    warning_handler("[%d] The operation completed successfully.\n" % results.status)
                else:
                    warning_handler("[{0}] iLO error response: {1}\n".\
                                         format(results.status, contents))
                    raise IloResponseError("")
        else:
            if results.status == 200 or results.status == 201:
                if print_code:
                    warning_handler("[%d] The operation completed successfully.\n" % results.status)
                else:
                    warning_handler("The operation completed successfully.\n")
            elif contents:
                warning_handler("iLO response with code [{0}]: {1}\n".\
                                     format(results.status, contents))
                raise IloResponseError("")
            else:
                warning_handler("[%d] No message returned.\n" % results.status)
