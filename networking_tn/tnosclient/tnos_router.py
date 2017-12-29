
import subprocess

from networking_tn.tnosclient import tnos_driver as tn_drv
from networking_tn.tnosclient import templates

ROUTER_MAX_INTF = 3
MANAGE_INTF_ID = 0

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

    def __init__(self, id, name, image_path):
        self.driver = None
        self.vm = None
        self.id = id
        self.name = name
        self.vm = create_tnos(name, image_path)
        self.api_client = None

        self.intfs = []
        cmd = ''
        for i in range(0, ROUTER_MAX_INTF):
            intf = TNL3Interface('tap' + str(i), 'ethernet' + str(i))
            self.intfs.append(intf)
            cmd = cmd + 'ifconfig %s up \n' % intf.extern_name
            intf.state = 'up'

        subprocess.Popen(cmd, shell=True)

    def set_restful_api_client(self, client):
        self.api_client = client

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


