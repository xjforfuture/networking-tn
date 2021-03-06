# Copyright (c) 2018 Tsinghuanet, Inc.
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

#    TnOS API request format templates.

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

ADD_SUB_INTF = """
{
    "path": "/api/system_interface?vdom=root",
    "method": "POST",
    "body": {
            "binding_zone": "l2zone",
            "zone_l2": "l2-trust",
            "vlanid": "{{ vlanid }}",
            "type": "subinterface",

            "interface":"{{ intf_name }}",
            "mkey": "{{ intf_name }}.{{ vlanid }}",
            "mkey_id": " "
    }
}
"""

DEL_SUB_INTF = """
{
    "path": "/api/system_interface?vdom=root",
    "method": "DELETE",
    "body": {
            "type": "subinterface",
            "mkey": "{{ intf_name }}",
            "mkey_id": "{{ id }}"
    }
}
"""

GET_INTF_INFO = """
{
    "path": "/api/system_interface?vdom=root",
    "method": "GET"
}
"""

CFG_INTF = """
{
    "path": "/api/system_interface/{{ intf_name }}?vdom=root",
    "method": "PUT",
    "body": {
            "mode": "static",
            "binding_zone": "l3zone",
            "zone_l3": "trust",
            
            {% if allows is defined %}
            "allowaccess": [
                {% for allow in allows[:-1] %}
                    "{{ allow }}",
                {% endfor %}
                "{{ allows[-1] }}"
            ],
            {% else %}
                "allowaccess": [],
            {% endif %}
            
            
            "_id": "{{ intf_name }}",
            
            {% if dns_state is defined %}
                "enableDNSproxy": "{{ dns_state }}",
            {% else %}
                "enableDNSproxy": "disable",
            {% endif %} 
            
            {% if mtu is defined %}
                "mtu": "{{ mtu }}",
            {% else %}
                "mtu": "1500",
            {% endif %} 
            
            {% if vlanid is defined %}
                "vlanid": "{{ vlanid }}",
            {% else %}
                "vlanid": " ",
            {% endif %} 
            
            "interface":"ethernet0",
            "type": "{{ type }}",
            "ip": "{{ ip_prefix }}",
            "mkey": "{{ intf_name }}",
            "mkey_id": "{{ id }}"
    }
}
"""

ADD_STATIC_ROUTE = """
{
    "path": "/api/router_static?vdom=root",
    "method": "POST",
    "body": {
        
        {% if gw_type is defined %}
            "gw_type": "{{ gw_type }}",
        {% else %}
            "gw_type": "ip",
        {% endif %} 
        
        {% if gw_ip is defined %}
            "gw_ip": "{{ gw_ip }}",
        {% endif %}
        
        {% if gw_interface is defined %}
            "gw_interface": "{{ gw_interface }}",
        {% endif %}
        
        {% if distance is defined %}
            "distance": "{{ distance }}",
        {% endif %}
        
        "dest": "{{ dest }}", 
        "netmask": "{{ netmask }}"
    }
}
"""

DEL_STATIC_ROUTE = """
{
    "path": "/api/router_static?vdom=root",
    "method": "DELETE",
    "body": {

        {% if gw_type is defined %}
            "gw_type": "{{ gw_type }}",
        {% else %}
            "gw_type": "ip",
        {% endif %} 

        {% if gw_ip is defined %}
            "gw_ip": "{{ gw_ip }}",
        {% endif %}

        {% if gw_interface is defined %}
            "gw_interface": "{{ gw_interface }}",
        {% endif %}

        {% if distance is defined %}
            "distance": "{{ distance }}",
        {% endif %}

        "mkey": "{{ dest }}",
        "dest": "{{ dest }}", 
        "netmask": "{{ netmask }}"
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
            "ip-min": "{{ ip_min }}",
            "ip-max": "{{ ip_max }}"
        {% endif %}
            
    }
}
"""

DEL_ADDRESS_ENTRY = """
{
    "path": "/api/system_address?vdom=root",
    "method": "DELETE",
    "body": {
        "mkey": "{{ name }}"
    }
}
"""

ADD_SERVICE_ENTRY = """
{
    "path": "/api/system_service?vdom=root",
    "method": "POST",
    "body": {
        {% if desc is defined %}
            "description":"{{ desc }}",
        {% else %}
            "description":"",
        {% endif %}
        
        "member": [
                {
                    "destination_port_max":"{{ dst_port_max }}",
                    "destination_port_min":"{{ dst_port_min }}",
                    "protocol":"{{ protocol }}",
                    "source_port_max":"{{ src_port_max }}",
                    "source_port_min":"{{ src_port_min }}"
                }
            ],
        
        "mkey":"{{ name }}"
    }
}
"""

DEL_SERVICE_ENTRY = """
{
    "path": "/api/system_service?vdom=root",
    "method": "DELETE",
    "body": {
        {% if desc is defined %}
            "description":"{{ desc }}",
        {% else %}
            "description":"",
        {% endif %}
        
        "member": [
                {
                    "destination_port_max":"{{ dst_port_max }}",
                    "destination_port_min":"{{ dst_port_min }}",
                    "protocol":"{{ protocol }}",
                    "source_port_max":"{{ src_port_max }}",
                    "source_port_min":"{{ src_port_min }}"
                }
            ],
        
        "mkey":"{{ name }}",
        "predefine": 0
    }
}
"""


ADD_SNAT_RULE = """
{
    "path": "/api/policy_nat_source_nat/?vdom=root",
    "method": "POST",
    "body": {
        "id": "{{ id }}",
        
        {% if desc is defined %}
            "description": "{{ desc }}",
        {% endif %}
        
        "saddr":"{{ saddr }}",
        
        {% if daddr is defined %}
            "daddr": "{{ daddr }}",
        {% else %}
            "daddr":"Any",
        {% endif %}
        
        {% if eif is defined %}
            "eif": "{{ eif }}",
        {% endif %}
        
        {% if log_flag is defined %}
            "log":"{{ log_flag }}",
        {% else %}
            "log":"disable",
        {% endif %}
        
        {% if reverse_flag is defined %}
            "reverse":"{{ reverse_flag }}",
        {% else %}
            "reverse":"disable",
        {% endif %}
        
        {% if service is defined %}
            "service":"{{ service }}",
        {% else %}
            "service":"Any",
        {% endif %}
        
        {% if status is defined %}
            "status":"{{ status }}",
        {% else %}
            "status":"enable",
        {% endif %}
        
        {% if sticky_flag is defined %}
            "sticky":"{{ sticky_flag }}",
        {% else %}
            "sticky":"disable",
        {% endif %}
        
        {% if trans is defined %}
            "trans":"{{ trans }}",
        {% else %}
            "trans":"trans-to",
        {% endif %}
        
        "trans_addr":"{{ trans_addr }}",
        
        {% if trans_mode is defined %}
            "trans_mode":"{{ trans_mode }}"
        {% else %}
            "trans_mode":"dynamicport"
        {% endif %}
    }
}
"""

DEL_SNAT_RULE = """
{
    "path": "/api/policy_nat_source_nat/?vdom=root",
    "method": "DELETE",
    "body": {
        "id": "{{ id }}",

        {% if desc is defined %}
            "description": "{{ desc }}",
        {% endif %}

        "saddr":"{{ saddr }}",

        {% if daddr is defined %}
            "daddr": "{{ daddr }}",
        {% else %}
            "daddr":"Any",
        {% endif %}

        {% if eif is defined %}
            "eif": "{{ eif }}",
        {% endif %}

        {% if log_flag is defined %}
            "log":"{{ log_flag }}",
        {% else %}
            "log":"disable",
        {% endif %}

        {% if reverse_flag is defined %}
            "reverse":"{{ reverse_flag }}",
        {% else %}
            "reverse":"disable",
        {% endif %}

        {% if service is defined %}
            "service":"{{ service }}",
        {% else %}
            "service":"Any",
        {% endif %}

        {% if status is defined %}
            "status":"{{ status }}",
        {% else %}
            "status":"enable",
        {% endif %}

        {% if sticky_flag is defined %}
            "sticky":"{{ sticky_flag }}",
        {% else %}
            "sticky":"disable",
        {% endif %}

        {% if trans is defined %}
            "trans":"{{ trans }}",
        {% else %}
            "trans":"trans-to",
        {% endif %}

        "trans_addr":"{{ trans_addr }}",

        {% if trans_mode is defined %}
            "trans_mode":"{{ trans_mode }}"
        {% else %}
            "trans_mode":"dynamicport"
        {% endif %}
    }
}
"""

MOVE_SNAT_RULE = """
{
    "path": "/api/policy_nat_source_nat/move/move?vdom=root&srcKey={{ srcKey }}&move_act={{ action }}&dstKey={{ dstKey }}",
    "method": "PUT",
    "body": {
        "dst":"{{ dstKey }}",
        "src":"{{ srcKey }}",
        "move_act":"{{ action }}",
        "_id":"move"
    }
}
"""

ADD_RULE = """
{
    "path": "/api/policy_security_rule?vdom=root",
    "method": "POST",
    "body": {
        "id":"{{ id }}",
        "action":"{{ action }}",
        "mkey":"{{ name }}",

        {% if desc is defined %}
            "description":"{{ desc }}",
        {% endif %}
        
        {% if daddr is defined %}
            "daddr": ["{{ daddr }}"],
        {% else %}
            "daddr":["Any"],
        {% endif %}
        
        {% if destinationAddr is defined %}
            "destinationAddr":"{{ destinationAddr }}",
        {% else %}
            "destinationAddr":"address",
        {% endif %}
        
        {% if dzone is defined %}
            "dzone":"{{ dzone }}",
        {% else %}
            "dzone":"trust",
        {% endif %}
            
        {% if saddr is defined %}
            "saddr": ["{{ saddr }}"],
        {% else %}
            "saddr":["Any"],
        {% endif %}
            
        {% if serGroup is defined %}
            "serGroup":"{{ serGroup }}",
        {% else %}
            "serGroup":"address",
        {% endif %}
            
        {% if service is defined %}
            "service": ["{{ service }}"],
        {% else %}
            "service":["Any"],
        {% endif %}    
            
        {% if sourceAddr is defined %}
            "sourceAddr":"{{ sourceAddr }}",
        {% else %}
            "sourceAddr":"address",
        {% endif %}
        
        {% if status is defined %}
            "status":"{{ status }}",
        {% else %}
            "status":"enable",
        {% endif %}        
        
        {% if szone is defined %}
            "szone":"{{ szone }}"
        {% else %}
            "szone":"trust"
        {% endif %}
    }
}
"""

DEL_RULE = """
{
    "path": "/api/policy_security_rule?vdom=root",
    "method": "DELETE",
    "body": {
        "id":"{{ id }}",
        "action":"{{ action }}",
        "mkey":"{{ name }}",

        {% if desc is defined %}
            "description":"{{ desc }}",
        {% endif %}

        {% if daddr is defined %}
            "daddr": ["{{ daddr }}"],
        {% else %}
            "daddr":["Any"],
        {% endif %}

        "daddrgroup":[],

        {% if dzone is defined %}
            "dzone":"{{ dzone }}",
        {% else %}
            "dzone":"trust",
        {% endif %}

        {% if saddr is defined %}
            "saddr": ["{{ saddr }}"],
        {% else %}
            "saddr":["Any"],
        {% endif %}

        "saddrgroup":[],

        {% if service is defined %}
            "service": ["{{ service }}"],
        {% else %}
            "service":["Any"],
        {% endif %}    
        
        "servicegroup":[],
        
        "sched":[],

        {% if status is defined %}
            "status":"{{ status }}",
        {% else %}
            "status":"enable",
        {% endif %}        

        {% if szone is defined %}
            "szone":"{{ szone }}"
        {% else %}
            "szone":"trust"
        {% endif %}
    }
}
"""

MOVE_RULE = """
{
    "path": "/api/policy_security_rule/move/move?vdom=root&srcKey={{ srcKey }}&move_act={{ action }}&dstKey={{ dstKey }}",
    "method": "PUT",
    "body": {
        "dst":"{{ dstKey }}",
        "src":"{{ srcKey }}",
        "move_act":"{{ action }}",
        "_id":"move"
    }
}
"""




