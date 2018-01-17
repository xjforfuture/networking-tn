
import neutron.plugins.ml2.models as ml2_db

import time
import subprocess
import shelve
import sys
from oslo_log import log as logging

from networking_tn.tnosclient import tnos_driver as tn_drv
from networking_tn.tnosclient import ovs_cb as ovsctl
from networking_tn.common import config
from networking_tn.tnosclient import templates

if __name__ == '__main__':
    sys.path.append(r'/home/xiongjun/work/networking-tn/')
    LOG = logging.getLogger(None).logger
    # LOG.addHandler(streamlog)
    LOG.setLevel(logging.DEBUG)
else:
    LOG = logging.getLogger(__name__)

ROUTER_MAX_INTF = 3
MANAGE_INTF_ID = 0
ROUTER_INTF = 1
GW_INTF = 2

MIN_SUB_INTF_ID = 1
MAX_SUB_INTF_ID = 4094


INT_BRIDGE_NAME = 'br-int'
TN_ROUTER_DB_NAME = '/opt/stack/tnos/tn_router_db'


def tn_router_id_convert(router_id):
    id = str(router_id[0:8])
    return id

def tn_db_lock(fd):
    #fcntl.flock(fd, fcntl.LOCK_EX)
    pass

def tn_db_unlock(fd):
    #fcntl.flock(fd, fcntl.lock_un)
    pass

def tn_db_add(key, obj):
    tn_db = shelve.open(TN_ROUTER_DB_NAME)

    tn_db_lock(tn_db)
    tn_db[key] = obj
    tn_db_unlock(tn_db)
    tn_db.close()

def tn_db_modify(key, obj):
    tn_db_add(key, obj)

def tn_db_get(key):
    tn_db = shelve.open(TN_ROUTER_DB_NAME)
    tn_db_lock(tn_db)
    try:
        obj = tn_db[key]
    except:
        obj = None
    finally:
        tn_db.close()
        tn_db_unlock(tn_db)

    return obj

def tn_db_del(key):

    tn_db = shelve.open(TN_ROUTER_DB_NAME)
    try:
        del tn_db[key]
    finally:
        tn_db.close()


def create_tnos(name, image_path, manage_ip):

    tnos = tn_drv.TNOSvm(name, image_path)
    tnos.start(MANAGE_INTF_ID, manage_ip)

    return tnos

def get_manage_ip():
    max = 0
    ip = None
    tn_db = shelve.open(TN_ROUTER_DB_NAME)
    for item in tn_db.items():
        tn_router = tn_db[item[0]]
        if type(tn_router) == TnosRouter:
            ip = tn_router.manage_ip
            ip = ip.split('.')
            if int(ip[2]) > max:
                max = int(ip[2])

    if ip != None:
        ip[2] = str(max + 1)
        ip = '.'.join(ip)

    tn_db.close()

    return ip

def get_tn_router(router_id):
    router_id = tn_router_id_convert(router_id)
    return tn_db_get(router_id)

class TNL3Interface(object):
    def __init__(self, extern_name, inner_name):
        self.subnet_id = ''
        self.extern_id = ''
        self.inner_id = ''
        self.extern_name = extern_name
        self.inner_name = inner_name
        self.state = None

        self.type = ' '
        self.mac = '00:00:00:00:00:01'
        self.vlan_id = []
        self.ip_prefix = '0.0.0.0/0'
        self.is_gw = False

        #subinterface attribute
        self.is_sub_intf = False
        self.sub_intf = []

    def init(self):
        self.subnet_id = ''
        self.extern_id = ''
        self.inner_id = ''
        self.status = False  # True is usred
        self.state = None

        self.type = ' '
        self.mac = '00:00:00:00:00:01'
        self.ip_prefix = '0.0.0.0/0'
        self.is_gw = False

class TNL3Address(object):
    def __init__(self, name, ip_prefix):
        self.name = name
        self.ip_prefix = ip_prefix

class TNL3Route(object):
    def __init__(self, dest, prefix, gw_ip):
        self.dest = dest
        self.prefix = prefix
        self.gw_ip =gw_ip


class TnosRouter(object):

    def __init__(self, context, router_id, tenant_id, name, image_path='tnos.qcow2', manage_ip='90.1.1.1'):
        router_id = tn_router_id_convert(router_id)
        self.router_id = router_id
        self.tenant_id = tenant_id
        self.name = name
        #self.api_client = config.get_apiclient(manage_ip)
        ip = get_manage_ip()
        if ip is None:
            ip = manage_ip

        self.manage_ip = ip

        self.vm = create_tnos(router_id, image_path, self.manage_ip)

        self.init_intf(context, self.manage_ip)
        self.init_addr()
        self.route_entry = []

    def del_router(self, context):
        ovsctl.del_port(context, INT_BRIDGE_NAME, self.intfs[GW_INTF].extern_name)
        self.vm.destroy()
        tn_db_del(self.router_id)

    def store_router(self):
        tn_db_modify(self.router_id, self)

    def init_intf(self, context, manage_ip):
        self.intfs = []
        cmd = ''
        for i in range(0, ROUTER_MAX_INTF):
            # extern_name is tapx-tenant_id+name
            intf = TNL3Interface('tap' + str(i) + '-' + self.router_id, 'ethernet' + str(i))
            if i == MANAGE_INTF_ID:
                intf.ip = manage_ip
            else:
                if i == GW_INTF:
                    intf.is_gw = True

            self.intfs.append(intf)
            cmd = cmd + 'sudo ifconfig %s up \n' % intf.extern_name
            intf.state = 'up'

        subprocess.Popen(cmd, shell=True)

        extern_ip = manage_ip.split('.')
        extern_ip[-1] = str(int(extern_ip[-1]) + 1)
        extern_ip = '.'.join(extern_ip)
        cmd = 'sudo ifconfig ' + self.intfs[MANAGE_INTF_ID].extern_name + ' ' + extern_ip + '/24'
        subprocess.Popen(cmd, shell=True)

    def add_intf(self, context, api_client, router_id, port, is_gw):

        LOG.debug(port['id'])

        port_name = None
        for i in range(10):
            (port_name, tag) = ovsctl.get_port_tag(context, port['id'])
            if port_name == None or tag == []:
                time.sleep(3)
            else:
                break

        if port_name == None or tag == []:
            return None

        cmd = 'sudo ip netns exec qrouter-'+router_id+' ifconfig '+port_name+' down'
        subprocess.Popen(cmd, shell=True)

        if is_gw:
            intf = self.intfs[GW_INTF]
            intf.vlan_id.append(tag)
            intf.extern_id = port['id']
            ovsctl.add_port(context, INT_BRIDGE_NAME, intf.extern_name)
            ovsctl.add_access_port_tag(context, intf.extern_name, tag)
            return intf
        else:
            # add and get intferface by restful api
            intf = self.intfs[ROUTER_INTF]
            api_client.request(templates.ADD_SUB_INTF, intf_name=intf.inner_name, vlanid=tag)

            if len(intf.sub_intf) == 0:
                ovsctl.add_port(context, INT_BRIDGE_NAME, intf.extern_name)
            ovsctl.add_trunk_port_tag(context, intf.extern_name, tag)

            intf.vlan_id.append(tag)
            sub_intf = TNL3Interface(intf.extern_name, intf.inner_name+'.'+str(tag))
            sub_intf.extern_id = port['id']
            sub_intf.vlan_id.append(tag)
            intf.sub_intf.append(sub_intf)

            self.get_intf_info(api_client)

            return sub_intf

    def del_intf(self, context, api_client, intf):
        if self.intfs[GW_INTF] is intf:
            intf.vlan_id = []
            ovsctl.del_port(context, INT_BRIDGE_NAME, self.intfs[GW_INTF].extern_name)
        else:
            api_client.request(templates.DEL_SUB_INTF, intf_name=intf.inner_name, id=intf.inner_id)
            ovsctl.del_trunk_port_tag(context, intf.extern_name, intf.vlan_id[0])

            main_intf = self.intfs[ROUTER_INTF]
            main_intf.vlan_id.remove(intf.vlan_id[0])
            main_intf.sub_intf.remove(intf)

            if len(main_intf.sub_intf) == 0:
                ovsctl.del_port(context, INT_BRIDGE_NAME, self.intfs[ROUTER_INTF].extern_name)

    def get_intf_by_subnet(self, subnet_id):
        for intf in self.intfs:
            if intf.subnet_id == subnet_id:
                return intf

    def get_intf_by_extern_id(self, extern_id):
        if self.intfs[GW_INTF].extern_id == extern_id:
            return self.intfs[GW_INTF]

        intf = self.intfs[ROUTER_INTF]
        for sub_intf in intf.sub_intf:
            if sub_intf.extern_id == extern_id:
                return sub_intf

    def get_router_gw_intf(self):
        return self.intfs[GW_INTF]

    def get_intf_info(self, api_client):
        msg = api_client.request(templates.GET_INTF_INFO)
        intf_info = msg['reply']

        for info in intf_info:
            if info['mkey'] == self.intfs[MANAGE_INTF_ID].inner_name:
                continue

            if info['mkey'] == self.intfs[GW_INTF].inner_name:
                self.intfs[GW_INTF].inner_id = info['mkey_id']
                self.intfs[GW_INTF].type = info['type']
                continue

            if info['mkey'] == self.intfs[ROUTER_INTF].inner_name:
                self.intfs[ROUTER_INTF].inner_id = info['mkey_id']
                self.intfs[ROUTER_INTF].type = info['type']
                continue

            for intf in self.intfs[ROUTER_INTF].sub_intf:
                if info['mkey'] == intf.inner_name:
                    intf.inner_id = info['mkey_id']
                    intf.type = info['type']


    def get_mac(self):
        #self.api_client.request()
        pass

    def cfg_intf_ip(self, api_client, intf, ip_prefix):
        intf.ip_prefix = ip_prefix
        allows = ["ping"]
        api_client.request(templates.CFG_INTF, intf_name=intf.inner_name, id=intf.inner_id, type=intf.type,
                           ip_prefix=ip_prefix, allows=allows)

    def add_static_route(self, api_client, dest, prefix, gw_ip):
        route = TNL3Route(dest, prefix, gw_ip)
        self.route_entry.append(route)
        api_client.request(templates.ADD_STATIC_ROUTE, dest=dest, netmask=prefix, gw_ip=gw_ip)

    def init_addr(self):
        self.addr = {}
        self.addr['Any'] = TNL3Address('Any', '0.0.0.0/0')

    def add_address_entry(self, api_client, addr_name, ip_prefix):
        self.addr[addr_name] = TNL3Address(addr_name, ip_prefix)
        api_client.request(templates.ADD_ADDRESS_ENTRY, name=addr_name, ip_prefix=ip_prefix)

    def del_address_entry(self, api_client, addr_name):

        api_client.request(templates.DEL_ADDRESS_ENTRY, name=addr_name)
        del self.addr[addr_name]

    def add_address_snat(self, api_client, id, saddr, trans_addr):
        api_client.request(templates.ADD_ADDRESS_SNAT, id=id, saddr=saddr, trans_addr=trans_addr)

    def add_rule(self, api_client, **msg):
        api_client.request(templates.ADD_RULE, **msg)

    def add_default_permit_rule(self, api_client, **msg):
        self.add_rule(api_client, id='1', action='permit', **msg)


def main():
    tn_router = TnosRouter(None, '1234567890', '55', '66', '/opt/stack/tnos/tnos.qcow2', '90.1.1.1')

    tn_router.store_router()
    db_router = get_tn_router('1234567890')
    print(db_router.name, db_router.vm.vmname, db_router.manage_ip)

    conn = config.get_apiclient(db_router.manage_ip)

    intf = db_router.intfs[ROUTER_INTF]
    conn.request(templates.ADD_SUB_INTF, intf_name=intf.inner_name, vlanid=12)

    intf.vlan_id.append(12)
    sub_intf = TNL3Interface(intf.extern_name, intf.inner_name+'.'+'12')
    sub_intf.extern_id = 'xxxx'
    sub_intf.vlan_id.append(12)
    intf.sub_intf.append(sub_intf)

    db_router.get_intf_info(conn)


    db_router.cfg_intf_ip(conn, sub_intf, '55.1.1.1/24')
    db_router.add_static_route(conn, dest='0.0.0.0', prefix='0.0.0.0', gw_ip=db_router.manage_ip)
    db_router.add_address_entry(conn, 'xxxxx', '33.1.1.0/24')

    db_router.del_address_entry(conn, 'xxxxx')

    conn.request(templates.DEL_SUB_INTF, intf_name=sub_intf.inner_name, id=sub_intf.inner_id)

    #db_router.del_router()


if __name__ == '__main__':
    main()