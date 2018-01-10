
import subprocess
import shelve
import fcntl
from oslo_log import log as logging

from networking_tn.tnosclient import tnos_driver as tn_drv
from networking_tn.ovsctl import ovsctl
from networking_tn.common import config

if __name__ == '__main__':
    LOG = logging.getLogger(None).logger
    # LOG.addHandler(streamlog)
    LOG.setLevel(logging.DEBUG)
else:
    LOG = logging.getLogger(__name__)

ROUTER_MAX_INTF = 3
MANAGE_INTF_ID = 0

INT_BRIDGE_NAME = 'br-int'
TN_ROUTER_DB_NAME = '/opt/stack/tnos/tn_router_db'



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
        ip = tn_router.manage_ip
        ip = ip.split('.')
        if int(ip[2]) > max:
            max = int(ip[2])

    if ip != None:
        ip[2] = str(max + 1)
        ip = '.'.join(ip)

    tn_db.close()

    return ip

def get_tn_router(tenant_id=None, router_name=None):
    return tn_db_get(tenant_id+router_name)

class TNL3Interface():
    def __init__(self, extern_name, inner_name, intf_id=None, status=None):
        self.id = intf_id
        self.status = 'use'
        self.state = None
        self.extern_name = extern_name
        self.inner_name = inner_name
        self.mac = '00:00:00:00:00:01'
        self.ip = '0.0.0.0'
        self.mask = '255.255.255.0'
        self.is_gw = False

class TnosRouter():

    def __init__(self, tenant_id, name, image_path='tnos.qcow2', manage_ip='90.1.1.1'):
        self.tenant_id = tenant_id
        self.name = name
        #self.api_client = config.get_apiclient(manage_ip)
        ip = get_manage_ip()
        if ip is None:
            ip = manage_ip

        self.manage_ip = ip

        print('ip:', ip)
        self.vm = create_tnos(tenant_id+name, image_path, self.manage_ip)

        self.intfs = []
        cmd = ''
        for i in range(0, ROUTER_MAX_INTF):
            #extern_name is tapx-tenant_id+name
            intf = TNL3Interface('tap' + str(i)+'-'+tenant_id+name, 'ethernet' + str(i))
            if i == MANAGE_INTF_ID:
                intf.ip = manage_ip

            self.intfs.append(intf)
            cmd = cmd + 'sudo ifconfig %s up \n' % intf.extern_name
            intf.state = 'up'

        subprocess.Popen(cmd, shell=True)

        extern_ip = ip.split('.')
        extern_ip[-1] = str(int(extern_ip[-1]) + 1)
        extern_ip = '.'.join(extern_ip)
        cmd = 'sudo ifconfig '+self.intfs[MANAGE_INTF_ID].extern_name +' '+ extern_ip+'/24'
        subprocess.Popen(cmd, shell=True)

        tn_db_add(tenant_id+name, self)

    def del_router(self):
        self.vm.destroy()
        tn_db_del(self.tenant_id+self.name)

    def add_intf(self, port, is_gw):
        ip = port['fixed_ips'][0]['ip_address']
        mask = '255.255.255.0'
        intf_id = -1
        ovsdb = ovsctl.OvsCtlBlock()
        (port_name, tag) = ovsdb.get_port_tag(port['id'])
        if port_name is None:
            return

        if is_gw:
            intf_id = MANAGE_INTF_ID
            self.intfs[intf_id].is_gw = True

        else:
            for intf in self.intfs:
                if intf.status:
                    continue
                else:
                    intf_id = self.intfs.index(intf)
                    if intf_id == MANAGE_INTF_ID:
                        intf_id = -1
                    else:
                        break

        if intf_id >= 0:
            # delete tmp, need later
            # ovsdb.del_port(l3_tn.INT_BRIDGE_NAME, port_name)

            intf = self.intfs[intf_id]
            intf.id = port['id']
            intf.ip = ip
            intf.mask = mask
            intf.status = True

            # todo xiongjun
            #self.vm.config_intf_ip(intf_id, ip, mask)
            ovsdb.add_port(INT_BRIDGE_NAME, intf.extern_name)
            ovsdb.add_port_tag(intf.extern_name, tag)

            if is_gw:
                # config getway
                tmp = ip.split('.')
                tmp[-1] = '1'
                gw_ip = '.'.join(tmp)
                self.add_static_route(dest="0.0.0.0", netmask="0.0.0.0", gw_ip=gw_ip)
                self.add_address_entry('gw_addr', ip, str(32))

            else:
                addr_name = port['network_id'][:16]
                self.add_address_entry(addr_name, ip, str(24))
                self.add_address_snat(id='1', saddr=addr_name, trans_addr='gw_addr')


    def del_intf(self):
        pass

    def get_mac(self):
        #self.api_client.request()
        pass

    def add_static_route(self, api_client, **msg):
        api_client.request('ADD_STATIC_ROUTE', **msg)

    def add_address_entry(self, api_client, addr_name, ip, prefix):
        ip_prefix = ip + '/' + prefix
        api_client.request('ADD_ADDRESS_ENTRY', name=addr_name, ip_prefix=ip_prefix)

    def add_address_snat(self, api_client, id, saddr, trans_addr):
        api_client.request('ADD_ADDRESS_SNAT', id=id, saddr=saddr, trans_addr=trans_addr)

    def add_rule(self, api_client, **msg):
        api_client.request('ADD_RULE', **msg)

    def add_default_permit_rule(self, api_client, **msg):
        self.add_rule(api_client, id='1', action='permit', **msg)


def main():
    tn_router = TnosRouter('55', '66', '/opt/stack/tnos/tnos.qcow2', '90.1.1.1')

    db_router = get_tn_router('55', '66')
    print(db_router.name, db_router.vm.vmname, db_router.manage_ip)

    conn = config.get_apiclient(db_router.manage_ip)

    #db_router.del_router()

    db_router.add_static_route(conn, dest='0.0.0.0', netmask='0.0.0.0', gw_ip=db_router.manage_ip)



if __name__ == '__main__':
    main()