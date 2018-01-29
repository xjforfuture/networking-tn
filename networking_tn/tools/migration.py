# Copyright 2017 tsinghuanet Inc.
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

import time
import sys

from oslo_config import cfg
from oslo_log import log as logging
from neutron import version

from neutron.common import constants as l3_constants

from neutron.db import models_v2, l3_db
from neutron.db.models import l3 as l3_models

#from neutron.db.external_net_db import ExternalNetwork
from neutron.objects.network import ExternalNetwork

from oslo_db.sqlalchemy import session
import neutron.plugins.ml2.models as ml2_db
from neutron_fwaas.db.firewall import firewall_db

sys.path.append(r'/home/xiongjun/work/networking-tn/')

ROUTER_INTF = l3_db.DEVICE_OWNER_ROUTER_INTF
ROUTER_GW = l3_db.DEVICE_OWNER_ROUTER_GW

#streamlog = handlers.ColorHandler()
LOG = logging.getLogger(None).logger
#LOG.addHandler(streamlog)
LOG.setLevel(logging.DEBUG)

LOG.debug('trace')

CFG_ARGS = [
             '--config-file',
             '/etc/neutron/neutron.conf',
             '--config-file',
             '/etc/neutron/plugins/ml2/ml2_conf.ini'
           ]

CFG_KWARGS = {}
SUPPORTED_DR = ['vlan']

cfg.CONF(args=CFG_ARGS, project='neutron',
         version='%%prog %s' % version.version_info.release_string(),
         **CFG_KWARGS)

LOG.debug('trace')

cfg.CONF.import_group('ml2_tn', 'networking_tn.common.config')

LOG.debug('trace')

from networking_tn.common import resources
from networking_tn.services.l3_router import l3_tn
from networking_tn.db import models as tn_db
from networking_tn.tnosclient import tnos_router as tnos
from networking_tn.services.firewall import tn_fwaas_plugin as fw
from networking_tn.tnosclient import tnos_firewall as tnos_fw

LOG.debug('trace')

class Progress(object):
    def __init__(self, total, name=''):
       self.i = 0
       self.total = total if total else 1
       print "Starting %s:" % name

    def __enter__(self):
        return self

    def update(self):
        self.i += 1
        self.percent = float(self.i)/self.total
        sys.stdout.write('\r[{0:<30}] {1:.0%}'.format(
                '=' * int(round(self.percent * 29)) + '>', self.percent
            ))
        sys.stdout.flush()
        time.sleep(0.2)

    def __exit__(self, type, value, traceback):
        print ""


class Fake_context(object):
    def __init__(self, args=CFG_ARGS, kwargs=CFG_KWARGS):
        engine = session.EngineFacade.from_config(cfg.CONF)
        '''
        if not [driver for driver in cfg.CONF.ml2.type_drivers
                       if driver in SUPPORTED_DR]:
            LOG.error(_("The supported type driver %(sdr)s are not in the "
                          "ml2 type drivers %(td)s in the plugin config file.")
                        % {'sdr': SUPPORTED_DR,
                           'td': cfg.CONF.ml2.type_drivers})
            exit()
        '''

        self.session = engine.get_session(autocommit=True,
                                          expire_on_commit=False)

        self.request_id = 'migration_context'


class Fake_TNL3ServicePlugin(l3_tn.TNL3ServicePlugin):
    def __init__(self):
        self._tn_info = None
        self.tn_init()

    def create_router(self, context, router):
        LOG.debug("create_router: router=%s" % (router))
        # Limit one router per tenant
        router = router.get('router', None)
        if not router:
            return

        router_id = router['id']
        router_name = router['name']

        try:
            tn_router = tnos.TnosRouter(context, router_id, None, router_name, self._tn_info["image_path"],
                                        self._tn_info['address'])
            tn_client = tnos.get_tn_client(router_id)
            tn_router.get_intf_info(tn_client)
            tn_router.store_router()

        except Exception as e:
            LOG.error("Failed to create_router router=%(router)s",
                      {"router": router})
            resources.Exinfo(e)


    def add_router_interface(self, context, port):
        """creates interface on the tn device."""
        ip = port['fixed_ips'][0]['ip_address']
        if '.' in ip:
            LOG.debug(port)
            router_id = port['device_id']
            try:
                self._add_tn_router_interface(context, router_id, port, ip)
            except Exception as e:
                raise

    def _get_floatingip(self, context, id):
        return tn_db.query_record(context, l3_models.FloatingIP, id=id)


    def create_floatingip(self, context, floatingip, returned_obj):
        """Create floating IP.
        """
        LOG.debug(_("create_floatingip: floatingip=%s" % floatingip))
        self._allocate_floatingip(context, returned_obj)
        if returned_obj.get('port_id', None):
            if not floatingip['floatingip'].get('fixed_ip_address', None):
                floatingip['floatingip']['fixed_ip_address'] = \
                    returned_obj.get('fixed_ip_address')
            self._associate_floatingip(context, returned_obj['id'],
                                       floatingip)
            self.update_floatingip_status(context, returned_obj,
                                l3_constants.FLOATINGIP_STATUS_ACTIVE,
                                id=returned_obj['id'])
        return returned_obj


class Fake_TNFirewallPlugin(fw.TNFirewallPlugin):

    def create_firewall(self, context, fw_with_rules):
        LOG.debug("create_firewall() called")

        LOG.debug(fw_with_rules)

        tn_fw = tnos_fw.TNFirewall(fw_with_rules['id'], fw_with_rules['name'], fw_with_rules['description'])
        tn_policy = tn_fw.add_policy(fw_with_rules['firewall_policy_id'])
        rules = fw_with_rules['firewall_rule_list']

        if tn_policy.rules == []:
            LOG.debug('trace')
            for rule in rules:
                LOG.debug('trace')
                tn_policy.add_rule(rule)

        try:
            for router_id in fw_with_rules['add-router-ids']:
                LOG.debug('router %s', router_id)
                tn_fw.apply_to_router(router_id)
        except:
            raise
        else:
            tn_fw.store()

    def get_firewalls(self, context):

        fw_list = tn_db.query_records(context, firewall_db.Firewall)
        return fw_list

    def get_rules(self, context, policy_id):
        rule_list = tn_db.query_records(context, firewall_db.FirewallRule, firewall_policy_id=policy_id)

        return rule_list

def reset(dictionary):
    for key, value in dictionary.iteritems():
        if isinstance(value, list):
            dictionary[key] = []
        elif isinstance(value, dict):
            dictionary[key] = {}
        elif isinstance(value, (int, long)):
            dictionary[key] = 0
        elif isinstance(value, (str, unicode, type(None))):
            dictionary[key] = None
        elif isinstance(value, bool):
            dictionary[key] = False
        else:
            raise TypeError
    return dictionary

def cls2dict(record, dictionary, **kwargs):
    for key, value in record.__dict__.iteritems():
        if key in dictionary:
            dictionary[key] = value
        elif key in kwargs:
            dictionary[kwargs[key]] = value
    return dictionary

def port_migration(context, l3_driver):
    """
    :param mech_driver:
    :param context:
    :return:
    # table ports
    port
    {
        'status': 'DOWN',
        'binding: host_id': '',
        'allowed_address_pairs': [],
        'device_owner': 'network: router_interface',
        'binding: profile': {

        },
        # table ipallocations
        'fixed_ips': [{
            'subnet_id': u'f645b09c-a34a-42fb-9c14-b999e43a54c7',
            'ip_address': u'172.20.21.1'
        }],
        'id': 'fb66def6-bd5e-44a0-a3f7-7c0e8e08d9ff',
        'security_groups': [],
        'device_id': u'e4020c65-7003-468b-a34d-31af297397a0',
        'name': '',
        'admin_state_up': True,
        'network_id': u'f8e34426-ccf7-429c-b726-3809d54cabdc',
        'tenant_id': u'11513667f4ee4a14acb0985659456f24',
        'binding: vif_details': {
        },
        'binding: vnic_type': 'normal',
        'binding: vif_type': 'unbound',
        'mac_address': u'00: 0c: 29: d9: 18: 3f'
    }
    """
    port = {
        'device_owner': 'network: router_interface',
        'fixed_ips': [{
            'subnet_id': u'f645b09c-a34a-42fb-9c14-b999e43a54c7',
            'ip_address': u'172.20.21.1'
        }],
        'id': 'fb66def6-bd5e-44a0-a3f7-7c0e8e08d9ff',
        'device_id': u'e4020c65-7003-468b-a34d-31af297397a0',
        'admin_state_up': True,
        'network_id': u'f8e34426-ccf7-429c-b726-3809d54cabdc',
        'tenant_id': u'11513667f4ee4a14acb0985659456f24',
        'mac_address': u'00: 0c: 29: d9: 18: 3f'
    }
    ipallocation = {
        'subnet_id': u'f645b09c-a34a-42fb-9c14-b999e43a54c7',
        'ip_address': u'172.20.21.1'
    }

    records = tn_db.query_records(context, models_v2.Port)

    with Progress(len(records), 'port_migration') as p:
        for record in records:
            reset(port)
            cls2dict(record, port)
            db_routerport = tn_db.query_record(context, l3_models.RouterPort, port_id=record.id)

            if getattr(db_routerport, 'port_type', None) in [ROUTER_INTF, ROUTER_INTF]:
                l3_driver.add_router_interface(context, port)

            p.update()





def router_migration(context, l3_driver):
    """
    # table routers, router_extra_attributes
    router={
        u'router': {
            'external_gateway_info': None,
            u'name': u'adm_router',
            u'admin_state_up': True,
            u'tenant_id': u'01c2468ab38b4d4490a39765bb87cb00',
            'distributed': 'fakedistributed',
            'ha': 'fakeha'
        }
    }
    """
    router_obj = {
        'name': 'adm_router',
        'admin_state_up': True,
        'id': u'01c2468ab38b4d4490a39765bb87cb00'
    }
    router = {'router': router_obj}

    records = tn_db.query_records(context, l3_models.Router)

    with Progress(len(records), 'router_migration') as p:
        for record in records:
            reset(router_obj)
            cls2dict(record, router_obj)
            l3_driver.create_router(context, router)
            p.update()

def firewall_migration(context, fw_plugin):
    fw_list = fw_plugin.get_firewalls(context)

    for fw in fw_list:
        rule_list = fw_plugin.get_rules(context, fw['firewall_policy_id'])
        for rule in rule_list:
            LOG.debug(rule)
            #fw_plugin.create_firewall(context, rule)

def floatingip_migration(context, l3_driver):
    """
    # table floatingips, ipallocations
    floatingip = {
        u'floatingip': {
            u'floating_network_id': u'2bdcaa63-22c5-4e58-8e2e-8f35bef7f513',
            'tenant_id': u'11513667f4ee4a14acb0985659456f24',
            'fixed_ip_address': None,
            'port_id': None
        }
    }
    returned_obj
    {
        'floating_network_id': u'2bdcaa63-22c5-4e58-8e2e-8f35bef7f513',
        'router_id': None,
        'fixed_ip_address': None,
        'floating_ip_address': u'10.160.37.139',
        'tenant_id': u'11513667f4ee4a14acb0985659456f24',
        'status': 'DOWN',
        'port_id': None,
        'id': '78764016-da62-42fd-96a4-f2bd0510b5bc'
    }
    """

    returned_obj = {
        'fixed_ip_address': None,
        'floating_ip_address': u'10.160.37.139',
        'tenant_id': u'11513667f4ee4a14acb0985659456f24',
        'status': 'DOWN',
        'port_id': None,
        'id': '78764016-da62-42fd-96a4-f2bd0510b5bc'
        }
    floatingip = {'floatingip': returned_obj}
    records = tn_db.query_records(context, l3_models.FloatingIP)
    with Progress(len(records), 'floatingip_migration') as p:
        for record in records:
            reset(returned_obj)
            cls2dict(record, returned_obj, fixed_port_id='port_id')
            l3_driver.create_floatingip(context, floatingip, returned_obj)
            p.update()


def main():

        context = Fake_context()
        #l3_driver = Fake_TNL3ServicePlugin()
        #router_migration(context, l3_driver)
        #port_migration(context, l3_driver)

        fw_plugin = Fake_TNFirewallPlugin()
        firewall_migration(context, fw_plugin)

    #except Exception as e:
    #    raise(e)


if __name__ == "__main__":
    main()

