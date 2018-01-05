
import subprocess
from oslo_log import log as logging

from networking_tn.tnosclient import tnos_driver as tn_drv
from networking_tn.ovsctl import ovsctl
from networking_tn.common import config

LOG = logging.getLogger(__name__)

ROUTER_MAX_INTF = 3
MANAGE_INTF_ID = 0

INT_BRIDGE_NAME = 'br-int'

def create_tnos(name, image_path):
    tnos = tn_drv.TNOSvm.get(name)
    if not tnos:
        tnos = tn_drv.TNOSvm(name, image_path)
        tnos.start()

    elif tnos.state is 'shutdown':
        tnos.start()
    elif tnos.state is 'crashed':
        tnos.stop()
        tnos.start()

    tnos.enable_http(MANAGE_INTF_ID)
    tnos.enable_https(MANAGE_INTF_ID)
    tnos.enable_ping(MANAGE_INTF_ID)
    tnos.enable_telnet(MANAGE_INTF_ID)

    return tnos

def add_nat():
    pass


class TNL3Interface():
    def __init__(self, extern_name, inner_name, intf_id=None, status=None):
        self.id = intf_id
        self.status = status
        self.state = None
        self.extern_name = extern_name
        self.inner_name = inner_name
        self.mac = None
        self.ip = None
        self.mask = None
        self.is_gw = None

class TnosRouter():

    tn_router = []

    def __init__(self, tenant_id, name, image_path='tnos.qcow2'):
        self.driver = None
        self.id = None
        self.tenant_id = tenant_id
        self.name = name
        self.vm = create_tnos(name, image_path)
        self.api_client = None
        TnosRouter.tn_router.append(self)

        self.intfs = []
        cmd = ''
        for i in range(0, ROUTER_MAX_INTF):
            intf = TNL3Interface('tap' + str(i), 'ethernet' + str(i))
            self.intfs.append(intf)
            cmd = cmd + 'sudo ifconfig %s up \n' % intf.extern_name
            intf.state = 'up'

        subprocess.Popen(cmd, shell=True)

    @staticmethod
    def get_tn_router(router_id=None, router_name=None):
        for tn_router in TnosRouter.tn_router:
            LOG.debug('%s %s' % (tn_router.name, router_name))
            if router_name and tn_router.name == router_name:
                return tn_router
            if router_id and tn_router.id == router_id:
                return tn_router

    def set_restful_api_client(self, client):
        self.api_client = client

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
            self.set_restful_api_client(config.get_apiclient(ip))
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

            self.vm.config_intf_ip(intf_id, ip, mask)
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

    def add_static_route(self, **msg):
        self.api_client.request('ADD_STATIC_ROUTE', **msg)

    def add_address_entry(self, addr_name, ip, prefix):
        ip_prefix = ip + '/' + prefix
        self.api_client.request('ADD_ADDRESS_ENTRY', name=addr_name, ip_prefix=ip_prefix)

    def add_address_snat(self, id, saddr, trans_addr):
        self.api_client.request('ADD_ADDRESS_SNAT', id=id, saddr=saddr, trans_addr=trans_addr)

    def add_rule(self, **msg):
        self.api_client.request('ADD_RULE', **msg)

    def add_default_permit_rule(self, **msg):
        self.add_rule(id='1', action='permit', **msg)

    def del_router(self):
        self.vm.destroy()
        TnosRouter.tn_router.remove(self)



