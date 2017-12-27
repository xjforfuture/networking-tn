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

RELOGIN = """login?redir=%2fapi%2fv2"""

LOGOUT = """
{
    "path": "/api/user/logout",
    "method": "POST"
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
    "path": "/api/router_static/?vdom=root",
    "method": "POST",
    "body": {
        "dest": "{{ dest }}", 
        "distance": "10", 
        "netmask": "{{ netmask }}", 
        "gw_type": "ip", 
        "gw_ip": "{{ gw_ip }}"
    }
}
"""

ADD_ADDRESS_ENTRY = """
{
    "path": "/api/system_address?vdom=root",
    "method": "POST",
    "body": {
        "mkey": "{{ name }}", 
        {% if type is defined %}
            "type": "{{ type }}",
        {% else %}
            "type": "ip-prefix",
        {% endif %}
        
        {% if ip_prefix is defined %}
            "ip-prefix": "{{ ip_prefix }}"
        {% else %}
            "ip-min": "{{ ip_min }}"
            "ip-max": "{{ ip_max }}"
        {% endif %}
            
    }
}
"""

ADD_SNAT = """
    "path": "/api/policy_nat_source_nat/?vdom=root",
    "method": "POST",
    "body": {
        "id": {{ id }}
        
        {% if desc is define %}
            "description": "{{ desc }}",
        {% endif %}
        
        "saddr":"{{ saddr }}"
        
        {% if daddr is define %}
            "daddr": "{{ daddr }}",
        {% else %}
            "daddr":"Any",
        {% endif %}
        
        {% if eif is define %}
            "eif": "{{ eif }}"
        {% endif %}
        
        {% if log_flag is define %}
            "log":"{{ log_flag }}"
        {% else %}
            "log":"disable"
        {% endif %}
        
        {% if reverse_flag is define %}
            "reverse":"{{ reverse_flag }}"
        {% else %}
            "reverse":"disable"
        {% endif %}
        
        {% if service is define %}
            "service":"{{ service }}"
        {% else %}
            "service":"Any"
        {% endif %}
        
        
        "status":"enable"
        "sticky":"disable"
        "trans":"trans-to"
        "trans_addr":"gw_addr"
        "trans_mode":"static"
        
    }

"""