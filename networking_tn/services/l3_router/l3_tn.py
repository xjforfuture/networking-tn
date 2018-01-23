# Copyright 2015 Fortinet Inc.
# All rights reserved.
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
#


"""Implentation of FortiOS service Plugin."""

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_lib import constants as l3_constants

from neutron.db.models import l3 as l3_db
from neutron.plugins.ml2 import db
from neutron.services.l3_router import l3_router_plugin as router
from neutron.db import l3_db as neu_l3_db

from networking_tn._i18n import _, _LE
from networking_tn.common import config
from networking_tn.common import resources
from networking_tn.db import models as tn_db
from networking_tn.tasks import tasks
from networking_tn.tnosclient import tnos_router as tnos


DEVICE_OWNER_ROUTER_INTF = l3_constants.DEVICE_OWNER_ROUTER_INTF
DEVICE_OWNER_ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_FLOATINGIP = l3_constants.DEVICE_OWNER_FLOATINGIP

LOG = logging.getLogger(__name__)


def neutron_to_tnos(id):
    return id[:16]


class TNL3ServicePlugin(router.L3RouterPlugin):
    """tn L3 service Plugin."""

    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute"]

    def __init__(self):
        """Initialize Fortinet L3 service Plugin."""
        super(TNL3ServicePlugin, self).__init__()
        self._tn_info = None
        #self._driver = None
        self.task_manager = tasks.TaskManager()
        self.task_manager.start()
        self.tn_init()

    def tn_init(self):
        """Fortinet specific initialization for this class."""
        LOG.debug("TNL3ServicePlugin_init")
        self._tn_info = config.tn_info
        #self._driver = config.get_apiclient()

        self.enable_fwaas = 'fwaas_fortinet' in cfg.CONF.service_plugins

    def create_router(self, context, router):
        LOG.debug("create_router: router=%s" % (router))
        # Limit one router per tenant
        if not router.get('router', None):
            return

        tenant_id = router['router']['tenant_id']
        router_name = router['router']['name']

        rlt = super(TNL3ServicePlugin, self).create_router(context, router)

        router_db = tn_db.query_record(context, l3_db.Router, name=router_name, tenant_id=tenant_id)
        LOG.debug(router_db)
        router_id = router_db['id']

        try:
            tn_router = tnos.TnosRouter(context, router_id, tenant_id, router_name, self._tn_info["image_path"], self._tn_info['address'])
            tn_client = tnos.get_tn_client(router_id)
            tn_router.get_intf_info(tn_client)
            tn_router.store_router()
            #router_db = tn_db.Tn_Router_Db.add_record(context, id=router_name, name=router_name, tenant_id=tenant_id)

        except Exception as e:
            LOG.error("Failed to create_router router=%(router)s",
                      {"router": router})
            resources.Exinfo(e)

        #router = tn_db.query_record(context, l3_db.Router, name=router_name)
        #tn_router.id = router['id']
        #LOG.debug(tn_router.id)
        #tn_db.update_record(context, router_db, id=router['id'])

        return rlt

    def update_router(self, context, id, router):
        LOG.debug("update_router: id=%(id)s, router=%(router)s",
                  {'id': id, 'router': router})


        updated = (super(TNL3ServicePlugin, self).update_router(context, id, router))

        LOG.debug(updated)

        gateway = router['router'].get('external_gateway_info')
        if gateway != None:
            self.__update_tn_router_gw(context, id, gateway, updated)

        routes = router['router'].get('routes')
        if routes != None:
            self.__update_tn_router_route(id, routes)

        return updated

    def __update_tn_router_gw(self, context, router_id, gateway, updated):
        network_id = gateway.get('network_id')

        if network_id != None:
            # add gateway
            port_id = updated.get('gw_port_id')
            if port_id != None:
                port = db.get_port(context, port_id)
                ips = updated['external_gateway_info']['external_fixed_ips']
                ip = ips[0]['ip_address']
                self.__add_tn_router_interface(context, router_id, port, ip)
        else:
            # del gatewayl
            self.__remove_tn_router_interface(context, router_id, is_gw=True)

    def __update_tn_router_route(self, router_id, routes):
        tn_router = tnos.get_tn_router(router_id=router_id)

        LOG.debug('config route: %s', routes)
        if tn_router == None:
            LOG.debug('tn_router is none')

        client = tnos.get_tn_client(router_id)
        if client == None:
            LOG.debug('client is none')

        #add route
        for route in routes:
            #dest is x.x.x.x/x
            dest = route['destination']
            next_hop = route['nexthop']
            dest = dest.split('/')
            if tn_router.get_static_route(dest[0], dest[1], next_hop) == None:
                tn_router.add_static_route(client, dest[0], dest[1], next_hop)

        #del route
        for old_route in tn_router.route_entry:
            flag = False
            for new_route  in routes:
                dest = new_route['destination']
                next_hop = new_route['nexthop']
                dest = dest.split('/')
                if old_route.dest==dest[0] and old_route.prefix==dest[1] and old_route.next_hop==next_hop:
                    flag = True
                    break

            if flag == False:
                tn_router.del_static_route(client,old_route)

        tn_router.store_router()


    def delete_router(self, context, id):
        LOG.debug("delete_router: router id=%s", id)
        try:

            router = tn_db.query_record(context, l3_db.Router, id=id)
            setattr(context, 'GUARD_TRANSACTION', False)
            super(TNL3ServicePlugin, self).delete_router(context, id)

            if getattr(router, 'tenant_id', None):

                LOG.debug(router)
                #tn_router = tnos.get_tn_router(router_name=router_name)
                tn_router = tnos.get_tn_router(router['id'])
                #tn_router_db = tn_db.query_record(context, tn_db.Tn_Router_Db, name=router_name)
                #LOG.debug('id %s , name %s, tenant_id %s', tn_router_db.id, tn_router_db.name, tn_router_db.tenant_id)

                if tn_router is not None:
                    tn_router.del_router(context)


        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to delete_router routerid=%(id)s"),
                          {"id": id})
                resources.Exinfo(e)

    def add_router_interface(self, context, router_id, interface_info):
        """creates interface on the tn device."""
        LOG.debug("TNL3ServicePlugin.add_router_interface: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})

        info = super(TNL3ServicePlugin, self).add_router_interface(
            context, router_id, interface_info)
        port = db.get_port(context, info['port_id'])
        port['admin_state_up'] = True
        port['port'] = port
        LOG.debug("TNL3ServicePlugin: "
                  "context=%(context)s"
                  "port=%(port)s "
                  "info=%(info)r",
                  {'context': context, 'port': port, 'info': info})
        interface_info = info
        subnet = self._core_plugin._get_subnet(context,interface_info['subnet_id'])
        network_id = subnet['network_id']
        tenant_id = port['tenant_id']
        port_filters = {'network_id': [network_id],
                        'device_owner': [DEVICE_OWNER_ROUTER_INTF]}
        port_count = self._core_plugin.get_ports_count(context,
                                                       port_filters)
        # port count is checked against 2 since the current port is already
        # added to db
        if port_count == 2:
            # This subnet is already part of some router
            LOG.error(_LE("TNL3ServicePlugin: adding redundant "
                          "router interface is not supported"))
            raise Exception(_("TNL3ServicePlugin:adding redundant "
                              "router interface is not supported"))
        try:
            self.__add_tn_router_interface(context, router_id, port, subnet['gateway_ip'])
        except Exception as e:
            LOG.error(_LE("Failed to create TN resources to add "
                        "router interface. info=%(info)s, "
                        "router_id=%(router_id)s"),
                      {"info": info, "router_id": router_id})

            with excutils.save_and_reraise_exception():
                self.remove_router_interface(context, router_id,
                                             interface_info)
        return info

    def __add_tn_router_interface(self, context, router_id, port, ip):
        tn_router = tnos.get_tn_router(router_id=router_id)
        if tn_router == None:
            LOG.debug('tn_router is none')

        client = tnos.get_tn_client(router_id)

        if client == None:
            LOG.debug('client is none')

        addr_name = neutron_to_tnos(port['id'])
        if port['device_owner'] in [neu_l3_db.DEVICE_OWNER_ROUTER_GW]:
            tn_intf = tn_router.add_intf(context, client, router_id, port, True)
            tn_router.add_address_entry(client, addr_name, ip + '/32')
        else:
            tn_intf = tn_router.add_intf(context, client, router_id, port, False)
            tn_router.add_address_entry(client, addr_name, ip + '/24')

        if tn_intf != None:
            tn_router.cfg_intf_ip(client, tn_intf, ip + '/24')

        tn_router.store_router()


    def remove_router_interface(self, context, router_id, interface_info):
        """Deletes vlink, default router from Fortinet device."""
        LOG.debug("TNL3ServicePlugin.remove_router_interface called: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})

        info = super(TNL3ServicePlugin, self).remove_router_interface(context, router_id, interface_info)

        self.__remove_tn_router_interface(context, router_id, port_id=interface_info['port_id'])

        return info

    def __remove_tn_router_interface(self, context, router_id, port_id=None, is_gw=False):
        tn_router = tnos.get_tn_router(router_id=router_id)
        client = tnos.get_tn_client(router_id)

        if is_gw:
            tn_intf = tn_router.get_router_gw_intf()
        else:
            tn_intf = tn_router.get_intf_by_extern_id(port_id)

        if tn_intf != None:
            addr_name = neutron_to_tnos(tn_intf.extern_id)
            tn_router.del_address_entry(client, addr_name)
            tn_router.del_intf(context, client, tn_intf)
            tn_router.store_router()

    '''
    def _add_interface_by_subnet(self, context, router, subnet_id, owner):
        LOG.debug("_add_interface_by_subnet(): router=%(router)s, "
                  "subnet_id=%(subnet_id)s, owner=%(owner)s",
                  {'router': router, 'subnet_id': subnet_id, 'owner': owner})
        subnet = self._core_plugin._get_subnet(context, subnet_id)
        if not subnet['gateway_ip']:
            msg = _('Subnet for router interface must have a gateway IP')
            raise n_exc.BadRequest(resource='router', msg=msg)
        self._check_for_dup_router_subnets(context, router,
                                           subnet['network_id'],
                                           [subnet])
        fixed_ip = {'ip_address': subnet['gateway_ip'],
                    'subnet_id': subnet['id']}

        # TODO(jerryz): move this out of transaction.
        setattr(context, 'GUARD_TRANSACTION', False)
        return (self._core_plugin.create_port(context, {
            'port':
            {'tenant_id': subnet['tenant_id'],
             'network_id': subnet['network_id'],
             'fixed_ips': [fixed_ip],
             'admin_state_up': True,
             'device_id': router.id,
             'device_owner': owner,
             'name': ''}}), [subnet], True)
    '''