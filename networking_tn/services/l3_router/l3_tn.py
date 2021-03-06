# Copyright 2018 Tsinghuanet Inc.
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


"""Implentation of TnOS service Plugin."""

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_lib import constants as l3_constants
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import events
from neutron_lib.callbacks import resources as rsc

from neutron.db.models import l3 as l3_db
from neutron.plugins.ml2 import db
from neutron.services.l3_router import l3_router_plugin as router
from neutron.db import l3_db as neu_l3_db
from neutron.db import models_v2
from neutron.db import api as db_api
from neutron_lib import constants as cst
from neutron_lib.plugins import constants as p_consts
from neutron_lib.plugins import directory
from oslo_db.sqlalchemy import session
from oslo_config import cfg

from networking_tn._i18n import _, _LE
from networking_tn.common import config
from networking_tn.common import resources
from networking_tn.db import tn_db
from networking_tn.tasks import tasks
from networking_tn.tnosclient import tnos_router
from networking_tn.tnosclient import tnos_firewall


DEVICE_OWNER_ROUTER_INTF = l3_constants.DEVICE_OWNER_ROUTER_INTF
DEVICE_OWNER_ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_FLOATINGIP = l3_constants.DEVICE_OWNER_FLOATINGIP

LOG = logging.getLogger(__name__)

class Fake_context(object):
    def __init__(self):
        engine = session.EngineFacade.from_config(cfg.CONF)
        self.session = engine.get_session(autocommit=True,
                                          expire_on_commit=False)

        self.request_id = 'tn_router_init_context'


class TNL3ServicePlugin(router.L3RouterPlugin):
    """tn L3 service Plugin."""

    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute"]

    def __init__(self):
        """Initialize Tsinghuanet L3 service Plugin."""
        super(TNL3ServicePlugin, self).__init__()
        self._tn_info = None
        # self._driver = None
        self.task_manager = tasks.TaskManager()
        self.task_manager.start()
        self.tn_init()

    def tn_init(self):
        """Tsinghuanet specific initialization for this class."""
        LOG.debug("TNL3ServicePlugin_init")
        self._tn_info = config.tn_info
        self.enable_fwaas = 'tn_firewall' in cfg.CONF.service_plugins

        # todo xiongjun
        # self.l3_tn_start()

    def l3_tn_start(self):
        context = Fake_context()
        tn_routers = tnos_router.get_tn_routers(context)
        LOG.debug(tn_routers)
        for router in tn_routers:
            LOG.debug(router)
            if tnos_router.tn_router_is_exist(router.id) == False:
                LOG.debug("create router")
                tnos_router.create_router(context, router.id, router.tenant_id, router.name,
                              config.tn_info["image_path"], config.tn_info['address'])

                intfs = tnos_router.get_intfs(context, router_id=router.id)
                for intf in intfs:
                    dev_owner = neu_l3_db.DEVICE_OWNER_ROUTER_GW if intf.is_gw == 'True' else DEVICE_OWNER_ROUTER_INTF
                    port = {'device_owner':dev_owner, 'id':intf.id}
                    self._add_tn_router_interface(context, router.id, port, intf.ip_prefix)

                routes = tnos_router.get_static_routes(context, router_id=router.id)
                for route in routes:
                    tnos_router.add_static_route(context, route.router_id, route.dest, route.prefix, route.next_hop)


    def create_router(self, context, router):
        LOG.debug("create_router: router=%s" % (router))
        # Limit one router per tenant
        if not router.get('router', None):
            return

        rlt = super(TNL3ServicePlugin, self).create_router(context, router)
        LOG.debug(rlt)

        #with context.session.begin(subtransactions=True):
        tenant_id = router['router']['tenant_id']
        router_name = router['router']['name']

        router_db = tn_db.query_record(context, l3_db.Router, name=router_name, tenant_id=tenant_id)
        LOG.debug(router_db)
        router_id = router_db['id']

        try:
            tnos_router.create_router(context, router_id, tenant_id, router_name,
                               self._tn_info["image_path"], self._tn_info['address'])


            gateway = router['router'].get('external_gateway_info')
            if gateway is not None:
                self._update_tn_router_gw(context, router_id, gateway, rlt)

        except Exception as e:
            LOG.error("Failed to create_router router=%(router)s",
                      {"router": router})
            resources.Exinfo(e)

        return rlt


    @db_api.retry_if_session_inactive()
    def _update_router(self, context, id, router):
        r = router['router']
        gw_info = r.pop(neu_l3_db.EXTERNAL_GW_INFO, l3_constants.ATTR_NOT_SPECIFIED)
        original = self.get_router(context, id)
        # check whether router needs and can be rescheduled to the proper
        # l3 agent (associated with given external network);
        # do check before update in DB as an exception will be raised
        # in case no proper l3 agent found
        if gw_info != l3_constants.ATTR_NOT_SPECIFIED:
            candidates = self._check_router_needs_rescheduling(
                context, id, gw_info)
            # Update the gateway outside of the DB update since it involves L2
            # calls that don't make sense to rollback and may cause deadlocks
            # in a transaction.
            self._update_router_gw_info(context, id, gw_info)
        else:
            candidates = None
        router_db = self._update_router_db(context, id, r)
        if candidates:
            l3_plugin = directory.get_plugin(plugin_constants.L3)
            l3_plugin.reschedule_router(context, id, candidates)
        updated = self._make_router_dict(router_db)

        routes = r.get('routes')
        if routes is None:
            registry.notify(rsc.ROUTER, events.AFTER_UPDATE, self,
                            context=context, router_id=id, old_router=original,
                            router=updated, request_attrs=r, router_db=router_db)

            self.notify_router_updated(context, updated['id'], None)

        return updated


    def update_router(self, context, id, router):
        LOG.debug("update_router: id=%(id)s, router=%(router)s",
                  {'id': id, 'router': router})

        r = router['router']
        if 'routes' in r:
            with context.session.begin(subtransactions=True):
                # check if route exists and have permission to access
                router_db = self._get_router(context, id)
                self._update_extra_routes(context, router_db, r['routes'])
            # NOTE(yamamoto): expire to ensure the following update_router
            # see the effects of the above _update_extra_routes.
            context.session.expire(router_db, attribute_names=['route_list'])

        updated =  self._update_router(context, id, router)

        LOG.debug(updated)

        gateway = router['router'].get('external_gateway_info')
        if gateway is not None:
            self._update_tn_router_gw(context, id, gateway, updated)

        routes = router['router'].get('routes')
        if routes is not None:
            self._update_tn_router_route(context, id, routes)

        return updated


    def update_router_old(self, context, id, router):
        LOG.debug("update_router: id=%(id)s, router=%(router)s",
                  {'id': id, 'router': router})

        updated = (super(TNL3ServicePlugin, self).update_router(context, id, router))
        #with context.session.begin(subtransactions=True):
        LOG.debug(updated)

        gateway = router['router'].get('external_gateway_info')
        if gateway is not None:
            self._update_tn_router_gw(context, id, gateway, updated)

        routes = router['router'].get('routes')
        if routes is not None:
            self._update_tn_router_route(context, id, routes)
            # todo xiongjun: patch, fix bug: namespace interface will be up when update router
            tnos_router.shutdown_old_intf(context, id)

        return updated

    def _update_tn_router_gw(self, context, router_id, gateway, updated):
        network_id = gateway.get('network_id')

        if network_id != None:
            # add gateway
            port_id = updated.get('gw_port_id')
            if port_id != None:
                port = db.get_port(context, port_id)
                ips = updated['external_gateway_info']['external_fixed_ips']
                ip = ips[0]['ip_address']
                self._add_tn_router_interface(context, router_id, port, ip)
        else:
            # del gatewayl
            self._remove_tn_router_interface(context, router_id, is_gw=True)

    def _update_tn_router_route(self, context, router_id, routes=[], del_all=False):

        # del route
        old_routes = tnos_router.get_static_routes(context, router_id=router_id)
        for old_route in old_routes:
            flag = False
            for new_route in routes:
                dest = new_route['destination']
                next_hop = new_route['nexthop']
                dest = dest.split('/')
                if old_route.dest == dest[0] and old_route.prefix == dest[1] and old_route.next_hop == next_hop:
                    flag = True
                    break

            if flag == False or del_all == True:
                tnos_router.del_static_route(context, router_id, old_route.dest, old_route.prefix, old_route.next_hop)

        # add route
        for route in routes:
            #dest is x.x.x.x/x
            dest = route['destination']
            next_hop = route['nexthop']
            dest = dest.split('/')

            db_route = tnos_router.get_static_route(context, router_id=router_id, dest=dest[0], prefix=dest[1], next_hop=next_hop)
            LOG.debug('db route: %s',db_route)
            if db_route is None:
                tnos_router.add_static_route(context, router_id, dest[0], dest[1], next_hop)

    def delete_router(self, context, id):
        LOG.debug("delete_router: router id=%s", id)

        try:
            if self.enable_fwaas:
                fw_plugin = directory.get_plugin(p_consts.FIREWALL)
                fw_plugin.update_firewall_for_delete_router(context, id)

            self._update_tn_router_route(context, id, del_all=True)
            self._remove_tn_router_interface(context, id, is_gw=True)

            router = tn_db.query_record(context, l3_db.Router, id=id)
            setattr(context, 'GUARD_TRANSACTION', False)
            if getattr(router, 'tenant_id', None):
                LOG.debug(router)
                tnos_router.del_router(context, router['id'])

        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to delete_router routerid=%(id)s"),
                          {"id": id})
                resources.Exinfo(e)
        else:
            super(TNL3ServicePlugin, self).delete_router(context, id)

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
        subnet = self._core_plugin._get_subnet(context, interface_info['subnet_id'])
        network_id = subnet['network_id']
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

        #with context.session.begin(subtransactions=True):
        try:
            self._add_tn_router_interface(context, router_id, port, subnet['gateway_ip'])
        except Exception as e:
            LOG.error(_LE("Failed to create TN resources to add "
                        "router interface. info=%(info)s, "
                        "router_id=%(router_id)s"),
                      {"info": info, "router_id": router_id})


            self.remove_router_interface(context, router_id, interface_info)

        return info

    def _add_tn_router_interface(self, context, router_id, port, ip):

        client = tnos_router.get_tn_client(context, router_id)
        if port['device_owner'] in [neu_l3_db.DEVICE_OWNER_ROUTER_GW]:
            tn_intf = tnos_router.add_intf(context, router_id, port['id'], True)
            if tn_intf is not None:
                tnos_router.cfg_intf_ip(context, router_id, tn_intf, ip+'/24')

                default_snat = tnos_firewall.TNSnatRule.create(context, router_id, tnos_firewall.TNOS_NAT_TRANS['trans-to'],
                                                 inner_id=tnos_firewall.TNOS_RULE_ID_MAX,
                                                 trans_addr=ip+'/32')
                LOG.debug('trace')
                tnos_firewall.TNSnatRule.add_apply(context, client, default_snat)

        else:
            tn_intf = tnos_router.add_intf(context, router_id, port['id'], False)
            if tn_intf is not None:
                tnos_router.cfg_intf_ip(context, router_id, tn_intf, ip+'/24')

                snat = tnos_firewall.TNSnatRule.create(context, router_id,
                                                       tnos_firewall.TNOS_NAT_TRANS['no-trans'], dstaddr=ip+'/24')

                tnos_firewall.TNSnatRule.add_apply(context, client, snat)

                default_snat = tnos_firewall.TNSnatRule.get(context, router_id=router_id,
                                                            inner_id=tnos_firewall.TNOS_RULE_ID_MAX)
                if default_snat is not None:
                    tnos_firewall.TNSnatRule.move_apply(context, client, snat, default_snat,
                                                        tnos_firewall.TNOS_INSERT_RULE_ACTION['insert_before'])


    def remove_router_interface(self, context, router_id, interface_info):
        """Deletes vlink, default router from Tsinghuanet device."""
        LOG.debug("TNL3ServicePlugin.remove_router_interface called: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})
        info = super(TNL3ServicePlugin, self).remove_router_interface(context, router_id, interface_info)

        #with context.session.begin(subtransactions=True):
        client = tnos_router.get_tn_client(context, router_id)
        self._remove_tn_router_interface(context, router_id, port_id=interface_info['port_id'])
        return info

    def _remove_tn_router_interface(self, context, router_id, port_id=None, is_gw=False):
        client = tnos_router.get_tn_client(context, router_id)
        # with context.session.begin(subtransactions=True):
        if is_gw == True:
            tn_intf = tnos_router.get_intf(context, router_id=router_id, is_gw='True')

        if port_id is not None:
            tn_intf = tnos_router.get_intf(context, id=port_id)

        LOG.debug(tn_intf)

        if tn_intf is not None:
            if is_gw == True:
                default_snat = tnos_firewall.TNSnatRule.get(context, router_id=router_id,
                                                            inner_id=tnos_firewall.TNOS_RULE_ID_MAX)
                tnos_firewall.TNSnatRule.del_apply(context, client, default_snat)
                tnos_firewall.TNSnatRule.delete(context, default_snat)
            else:
                snat = tnos_firewall.TNSnatRule.get(context, router_id=router_id, dstaddr=tn_intf.ip_prefix)
                tnos_firewall.TNSnatRule.del_apply(context, client, snat)
                tnos_firewall.TNSnatRule.delete(context, snat)

            tnos_router.del_intf(context, router_id, intf_id=tn_intf.id)

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