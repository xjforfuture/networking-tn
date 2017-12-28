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
import subprocess

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

sys.path.append(r'/home/xiongjun/work/networking-tn/')

ROUTER_INTF = l3_db.DEVICE_OWNER_ROUTER_INTF
ROUTER_GW = l3_db.DEVICE_OWNER_ROUTER_GW

#streamlog = handlers.ColorHandler()
LOG = logging.getLogger(None).logger
#LOG.addHandler(streamlog)
LOG.setLevel(logging.DEBUG)

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
cfg.CONF.import_group('ml2_tn', 'networking_tn.common.config')

from networking_tn.common import resources
from networking_tn.common import utils
from networking_tn.services.l3_router import l3_tn
from networking_tn.tasks import tasks
from networking_tn.tasks import constants as t_consts
from networking_tn.db import models as tn_db
from networking_tn.tnosclient import tnos_router as tnos
from networking_tn.ovsctl import ovsctl
from networking_tn.common import config

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
        self._router = []
        self.task_manager = tasks.TaskManager()
        self.task_manager.start()
        self.tn_init()

    def create_router(self, context, router):
        LOG.debug("create_router: router=%s" % (router))
        # Limit one router per tenant
        if not router.get('router', None):
            return

        router_id = router['router']['id']
        router_name = router['router']['name']
        with context.session.begin(subtransactions=True):
            try:
                router = tnos.TnosRouter(router_id, router_name, self._tn_info['image_path'])
                self._router.append(router)

            except Exception as e:
                LOG.error("Failed to create_router router=%(router)s",
                          {"router": router})
                resources.Exinfo(e)
                utils._rollback_on_err(self, context, e)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)


    def add_router_interface(self, context, port, is_gw):

        router_id = port['device_id']
        ip = port['fixed_ips'][0]['ip_address']
        mask = '255.255.255.0'
        intf_id = -1
        ovsdb = ovsctl.OvsCtlBlock()
        (port_name, tag) = ovsdb.get_port_tag(port['id'])
        if port_name is None:
            return

        router = self.get_router(router_id)

        if is_gw:
            intf_id = tnos.MANAGE_INTF_ID
            router.intfs[intf_id].is_gw = True
            router.set_restful_api_client(config.get_apiclient(ip))
        else:
            for intf in router.intfs:
                if intf.status:
                    continue
                else:
                    intf_id = router.intfs.index(intf)
                    if intf_id == tnos.MANAGE_INTF_ID:
                        intf_id = -1
                    else:
                        break

        if intf_id >= 0:
            #delete tmp, need later
            #ovsdb.del_port(l3_tn.INT_BRIDGE_NAME, port_name)

            intf = router.intfs[intf_id]
            intf.id = port['id']
            intf.ip = ip
            intf.mask = mask
            intf.status = True

            router.vm.config_intf_ip(intf_id, ip, mask)
            ovsdb.add_port(l3_tn.INT_BRIDGE_NAME, intf.extern_name)
            ovsdb.add_port_tag(intf.extern_name, tag)

            if is_gw:
                #config getway
                router.add_static_route('0.0.0.0','0.0.0.0', ip)

                router.add_address_entry('gw_addr', ip, str(32))

            else:
                addr_name = port['network_id'][:16]
                router.add_address_entry(addr_name, ip, str(24))
                router.add_address_snat(id='1', saddr=addr_name, trans_addr='gw_addr')

                '''
                utils.add_fwpolicy(self, context,
                                   vdom=db_namespace.vdom,
                                   srcintf=self.intf[intf_id].inner_name,
                                   dstintf=self.intf[tn_drv.MANAGE_INTF_ID].inner_name,
                                   nat='enable')
                '''

        else:
            LOG.error('add router interface fail!')

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

            if getattr(db_routerport, 'port_type', None) in [ROUTER_GW]:
                l3_driver.add_router_interface(context, port, True)

        for record in records:
            reset(port)
            cls2dict(record, port)
            db_routerport = tn_db.query_record(context, l3_models.RouterPort, port_id=record.id)

            if getattr(db_routerport, 'port_type', None) in [ROUTER_INTF]:
                l3_driver.add_router_interface(context, port, False)

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
    try:
        context = Fake_context()
        l3_driver = Fake_TNL3ServicePlugin()
        router_migration(context, l3_driver)
        port_migration(context, l3_driver)

        '''
        print("step7")
        floatingip_migration(context, l3_driver)
        print("step8")
        '''

    except Exception as e:
        raise(e)
    print "\nmigration completed.\n"


if __name__ == "__main__":
    main()

