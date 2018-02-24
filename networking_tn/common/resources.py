# Copyright 2018 Tsinghuanet Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from networking_tn.tnosclient import exception as api_ex
import inspect
import os
from oslo_log import log as logging
import re
import six
import sys
import types

from networking_tn._i18n import _LE

LOG = logging.getLogger(__name__)


# For debug purpose
def funcinfo(cls=None, action=None, data=None):
    cur_func = inspect.stack()[1][3]
    caller = inspect.stack()[2][3]
    LOG.debug("## current function is %(cur_func)s,"
              "its caller is %(caller)s",
              {'cur_func': cur_func, 'caller': caller})
    if cls or action or data:
        LOG.debug("## cls: %(cls)s, action: %(action)s, data: %(data)s",
                  {'cls': cls.__name__, 'action': action, 'data': data})


class Exinfo(object):
    def __init__(self, exception):
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        LOG.error(_LE("An exception of type %(exception)s occured with "
                      "arguments %(args)s, line %(line)s, in %(file)s"),
                  {'exception': type(exception).__name__,
                   'args': exception.args,
                   'line': exc_tb.tb_lineno,
                   'file': fname})
