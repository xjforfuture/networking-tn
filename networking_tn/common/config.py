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

from networking_tn.tnosclient import client
from oslo_config import cfg

from networking_tn._i18n import _

ML2_TN = [
    cfg.StrOpt('vm_image_path', default='tnos.qcow2',
               help=_('TNOS image path')),
    cfg.StrOpt('address', default='',
               help=_('The address of fortigates to connect to')),
    cfg.StrOpt('port', default='80',
               help=_('The FGT port to serve API requests')),
    cfg.StrOpt('protocol', default='http',
               help=_('The tsinghuanet uses which protocol: http or https')),
    cfg.StrOpt('username', default='admin',
               help=_('The username used to login')),
    cfg.StrOpt('password', default='admin', secret=True,
               help=_('The password used to login')),
    cfg.StrOpt('int_interface', default='internal',
               help=_('The interface to serve tenant network')),
    cfg.StrOpt('ext_interface', default='',
               help=_('The interface to the external network')),
    cfg.StrOpt('tenant_network_type', default='vlan',
               help=_('tenant network type, default is vlan')),
    cfg.StrOpt('vlink_vlan_id_range', default='3500:4000',
               help=_('vdom link vlan interface, default is 3500:4000')),
    cfg.StrOpt('vlink_ip_range', default='169.254.0.0/20',
               help=_('vdom link interface IP range, '
                     'default is 169.254.0.0/20')),
    cfg.StrOpt('vip_mappedip_range', default='169.254.128.0/23',
               help=_('The intermediate IP range in floating IP process, '
                     'default is 169.254.128.0/23')),
    cfg.BoolOpt('npu_available', default=True,
                help=_('If npu_available is True, it requires hardware FGT'
                      'with NPU, default is True')),
    cfg.BoolOpt('enable_default_fwrule', default=False,
                help=_('If True, fwaas will add a deny all rule automatically,'
                       ' otherwise users need to add it manaully.')),
    cfg.StrOpt('av_profile', default=None,
               help=_('Assign a default antivirus profile in FWaaS, '
                     'the profile must exist in FGT, default is ""')),
    cfg.StrOpt('webfilter_profile', default=None,
               help=_('Assign a default web filter profile in FWaaS, '
                     'the profile must exist in FGT, default is ""')),
    cfg.StrOpt('ips_sensor', default=None,
               help=_('Assign a default IPS profile in FWaaS, '
                     'the profile must exist in FGT, default is ""')),
    cfg.StrOpt('application_list', default=None,
               help=_('Assign a default application control profile in FWaaS,'
                     ' the profile must exist in FGT, default is ""')),
    cfg.StrOpt('ssl_ssh_profile', default=None,
               help=_('Assign a default SSL/SSH inspection profile in FWaaS, '
                     'the profile must exist in FGT, default is ""'))
]

cfg.CONF.register_opts(ML2_TN, "ml2_tn")

tn_info = {
    'image_path' : cfg.CONF.ml2_tn.vm_image_path,
    'address': cfg.CONF.ml2_tn.address,
    'port': cfg.CONF.ml2_tn.port,
    'protocol': cfg.CONF.ml2_tn.protocol,
    'username': cfg.CONF.ml2_tn.username,
    'password': cfg.CONF.ml2_tn.password,
    'int_interface': cfg.CONF.ml2_tn.int_interface,
    'ext_interface': cfg.CONF.ml2_tn.ext_interface,
    'tenant_network_type': cfg.CONF.ml2_tn.tenant_network_type,
    'vlink_vlan_id_range': cfg.CONF.ml2_tn.vlink_vlan_id_range,
    'vlink_ip_range': cfg.CONF.ml2_tn.vlink_ip_range,
    'vip_mappedip_range': cfg.CONF.ml2_tn.vip_mappedip_range,
    'npu_available': cfg.CONF.ml2_tn.npu_available,
    'enable_default_fwrule': cfg.CONF.ml2_tn.enable_default_fwrule,
    'av_profile': cfg.CONF.ml2_tn.av_profile,
    'webfilter_profile': cfg.CONF.ml2_tn.webfilter_profile,
    'ips_sensor': cfg.CONF.ml2_tn.ips_sensor,
    'application_list': cfg.CONF.ml2_tn.application_list,
    'ssl_ssh_profile': cfg.CONF.ml2_tn.ssl_ssh_profile
}


def get_apiclient(address=None):
    """Tsinghuanet api client initialization."""
    #api_server = [(address if address else tn_info['address'], tn_info['port'],
    #              'https' == tn_info['protocol'])]

    api_server = [(address if address else tn_info['address'], tn_info['port'],
                   'https' == tn_info['protocol'])]

    return client.TnosApiClient(api_server, tn_info['username'], tn_info['password'])

