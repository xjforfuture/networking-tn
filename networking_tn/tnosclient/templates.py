# Copyright (c) 2015 Fortinet, Inc.
# All Rights Reserved.
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

#    FortiOS API request format templates.

# About api request message naming regulations:
# Prefix         HTTP method
# ADD_XXX    -->    POST
# SET_XXX    -->    PUT
# DELETE_XXX -->    DELETE
# GET_XXX    -->    GET

# Login
LOGIN = """
{
    "path": "/api/user/login",
    "method": "POST",
    "body": {
        "username": "{{ username }}",
        "password": "{{ secretkey }}"
    }
}
"""

TOUCH = """
{
    "path": "/api/user/touch",
    "method": "GET"
}
"""

SET_STATIC_ROUTE = """
{
    "path": "/api/router_static/*",
    "method": "POST",
    "body": {
        dest: "{{ dest }}", 
        distance: "10", 
        netmask: "{{ netmask }}", 
        gw_type: "ip", 
        gw_ip: "{{ gw_ip }}"
    }
}
"""