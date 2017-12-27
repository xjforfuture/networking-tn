
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

    tnos.enable_http()
    tnos.enable_https()
    tnos.enable_ping()
    tnos.enable_telnet()

    return tnos

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

    def add_static_route(self, dest, netmask, gw_ip):
        self.api_client.request(templates.SET_STATIC_ROUTE, dest=dest, netmask=netmask, gw_ip=gw_ip)


