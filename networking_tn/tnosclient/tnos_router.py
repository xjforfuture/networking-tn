
import time
import subprocess
import sys
from oslo_log import log as logging
from networking_tn._i18n import _, _LE

from networking_tn.tnosclient import tnos_driver as tn_drv
from networking_tn.ovsctl import ovsctl
from networking_tn.common import config
from networking_tn.tnosclient import templates
from networking_tn.db import tn_db

if __name__ == '__main__':
    sys.path.append(r'/home/xiongjun/work/networking-tn/')
    LOG = logging.getLogger(None).logger
    # LOG.addHandler(streamlog)
    LOG.setLevel(logging.DEBUG)
else:
    LOG = logging.getLogger(__name__)

TNOS_CLIENT = {}
first= None
sec=None

ROUTER_MAX_INTF = 3
MANAGE_INTF = 0
ROUTER_INTF = 1
GW_INTF = 2

MIN_SUB_INTF_ID = 1
MAX_SUB_INTF_ID = 4094


EXTERN_INTF_NAME = 'tap%(num)s-%(router_priv_id)s'
INNER_INTF_NAME = 'ethernet%(num)s'

INT_BRIDGE_NAME = 'br-int'


def tn_router_id_convert(router_id):
    id = str(router_id[0:8])
    return id


def wait_for_ovs(context, port):
    for i in range(10):
        (port_name, tag) = ovsctl.get_port_tag(context, port['id'])

        if port_name is None or tag == [] or tag is None:
            time.sleep(3)
        else:
            return (port_name, tag)
    return (None, None)
    #raise Exception(_("add router interface to ovs fail!"))


def get_extern_intf_name(intf_num, router_priv_id):
    return EXTERN_INTF_NAME % {'num': str(intf_num), 'router_priv_id': router_priv_id}


def get_inner_intf_name(intf_num, vlan_id=None):
    if vlan_id is None:
        return INNER_INTF_NAME % {'num': str(intf_num)}
    else:
        return INNER_INTF_NAME % {'num': str(intf_num)}+'.'+str(vlan_id)


def get_tn_client(context, router_id):

    if router_id in TNOS_CLIENT:
        return TNOS_CLIENT[router_id]

    # for test
    if router_id == '999999':
        TNOS_CLIENT[router_id] = config.get_apiclient('88.1.1.1')
        return TNOS_CLIENT[router_id]

    tn_router = tn_db.query_record(context, tn_db.Tn_Router, id=router_id)
    if tn_router is not None:
        TNOS_CLIENT[router_id] = config.get_apiclient(tn_router.manage_ip)
        return TNOS_CLIENT[router_id]


def create_tnos(id, priv_id, image_path, manage_ip):

    tnos = tn_drv.TNOSvm(id, priv_id, image_path)
    return tnos.start(MANAGE_INTF, manage_ip)


def get_manage_ip(context, manage_ip):
    max_num = 0
    ip = None
    routers = tn_db.query_records(context, tn_db.Tn_Router)
    for router in routers:
        ip = router.manage_ip
        ip = ip.split('.')
        if int(ip[2]) > max_num:
            max_num = int(ip[2])

    if ip is None:
        return manage_ip
    elif max_num < 254:
        ip[2] = str(max_num + 1)
        ip = '.'.join(ip)
        return ip
    else:
        return None


def get_tn_router(context, router_id):
    return tn_db.query_record(context, tn_db.Tn_Router, id=router_id)


def create_router(context, id, tenant_id, name, image_path='tnos.qcow2', manage_ip='90.1.1.1'):
    priv_id = tn_router_id_convert(id)

    ip = get_manage_ip(context, manage_ip)
    if ip is None:
        LOG.error('Too more routers, there is no manage ip!')
        return

    image = create_tnos(id, priv_id, image_path, ip)

    init_intf(priv_id, ip)
    TNOS_CLIENT[id] = config.get_apiclient(ip)

    router = tn_db.query_record(context, tn_db.Tn_Router, id=id)
    if router is None:
        tn_db.add_record(context, tn_db.Tn_Router, id=id, priv_id=priv_id,
                         tenant_id=tenant_id, name=name, manage_ip=ip, image_name=image)
    else:
        tn_db.update_record(context, router, id=id, priv_id=priv_id,
                            tenant_id=tenant_id, name=name, manage_ip=ip, image_name=image)


def del_router(context, router_id):
    # kill vm and delete router
    router = tn_db.query_record(context, tn_db.Tn_Router, id=router_id)
    if router is not None:
        tn_drv.destroy_vm(router_id, router.image_name)
        tn_db.delete_record(context, tn_db.Tn_Router, id=router_id)
        del TNOS_CLIENT[router_id]


def init_intf(router_priv_id, manage_ip):
    cmd = ''
    for i in range(0, ROUTER_MAX_INTF):
        # extern_name is tapx-tenant_id+name
        extern_name = get_extern_intf_name(i, router_priv_id)
        cmd = cmd + 'sudo ifconfig %s up \n' % extern_name

        if i == MANAGE_INTF:
            extern_ip = manage_ip.split('.')
            extern_ip[-1] = str(int(extern_ip[-1]) + 1)
            extern_ip = '.'.join(extern_ip)
            cmd = cmd + 'sudo ifconfig ' + extern_name + ' ' + extern_ip + '/24 \n'

    subprocess.Popen(cmd, shell=True)

def add_intf(context, router_id, port, is_gw):

    LOG.debug(port)

    (port_name, tag) = wait_for_ovs(context, port)
    if port_name is None:
        return None

    router = get_tn_router(context, router_id)
    if is_gw:
        extern_name = get_extern_intf_name(GW_INTF, router.priv_id)
        inner_name = get_inner_intf_name(GW_INTF)

        ovsctl.add_port(context, INT_BRIDGE_NAME, extern_name)
        ovsctl.add_access_port_tag(context, extern_name, tag)

        intf = tn_db.add_record(context, tn_db.Tn_Interface, id=port['id'], router_id=router_id,
                                extern_name=extern_name, inner_name=inner_name, state='up',
                                vlan_id=tag, is_gw='True', is_sub='False')

    else:
        # add and get intferface by restful api
        api_client = get_tn_client(context, router_id)
        extern_name = get_extern_intf_name(ROUTER_INTF, router.priv_id)
        inner_name = get_inner_intf_name(ROUTER_INTF)
        api_client.request(templates.ADD_SUB_INTF, intf_name=inner_name, vlanid=tag)

        count = tn_db.query_count(context, tn_db.Tn_Interface, router_id=router_id, is_gw='False')
        # first router interface
        if count == 0:
            ovsctl.add_port(context, INT_BRIDGE_NAME, extern_name)

        ovsctl.add_trunk_port_tag(context, extern_name, tag)

        sub_inner_name = get_inner_intf_name(ROUTER_INTF, tag)
        intf = tn_db.add_record(context, tn_db.Tn_Interface, id=port['id'], router_id=router_id,
                                extern_name=extern_name, inner_name=sub_inner_name, state='up',
                                vlan_id=tag, is_gw='False', is_sub='True')

    cmd = 'sudo ip netns exec qrouter-' + router_id + ' ifconfig ' + port_name + ' 0.0.0.0'
    subprocess.Popen(cmd, shell=True)

    cmd = 'sudo ip netns exec qrouter-' + router_id + ' ifconfig ' + port_name + ' down'
    subprocess.Popen(cmd, shell=True)
    # ovsctl.del_port(context, INT_BRIDGE_NAME, port_name)

    cmd = 'sudo ifconfig %s up \n' % intf.extern_name
    subprocess.Popen(cmd, shell=True)
    get_intf_info(context, router_id)

    return intf


def del_intf(context, router_id, intf_id):
    intf = tn_db.query_record(context, tn_db.Tn_Interface, id=intf_id)

    if intf is not None:
        api_client = get_tn_client(context, router_id)

        if intf.is_gw == 'True':
            ovsctl.del_port(context, INT_BRIDGE_NAME, intf.extern_name)
        else:
            api_client.request(templates.DEL_SUB_INTF, intf_name=intf.inner_name, id=intf.inner_id)
            ovsctl.del_trunk_port_tag(context, intf.extern_name, intf.vlan_id)

            count = tn_db.query_count(context, tn_db.Tn_Interface, router_id=router_id, is_gw='False')
            if count == 1:
                # the last one
                ovsctl.del_port(context, INT_BRIDGE_NAME, intf.extern_name)

        tn_db.delete_record(context, tn_db.Tn_Interface, id=intf.id)


def get_intf(context, **kwargs):
    return tn_db.query_record(context, tn_db.Tn_Interface, **kwargs)


def get_intf_info(context, router_id):
    api_client = get_tn_client(context, router_id)
    msg = api_client.request(templates.GET_INTF_INFO)
    intf_info = msg['reply']

    intfs = tn_db.query_records(context, tn_db.Tn_Interface, router_id=router_id)
    for info in intf_info:
        for intf in intfs:
            if info['mkey'] == intf.inner_name:
                tn_db.update_record(context, intf, inner_id=info['mkey_id'], type=info['type'])


def cfg_intf_ip(context, router_id, intf, ip_prefix):
    api_client = get_tn_client(context, router_id)
    allows = ["ping"]

    api_client.request(templates.CFG_INTF, intf_name=intf.inner_name, id=intf.inner_id, type=intf.type,
                       ip_prefix=ip_prefix, allows=allows)

    tn_db.update_record(context, intf, ip_prefix=ip_prefix)


def add_static_route(context, router_id, dest, prefix, next_hop):
    api_client = get_tn_client(context, router_id)
    try:
        api_client.request(templates.ADD_STATIC_ROUTE, dest=dest, netmask=prefix, gw_ip=next_hop)
    except Exception:
        raise
    else:
        tn_db.add_record(context, tn_db.Tn_Static_Route,
                         router_id=router_id, dest=dest, prefix=prefix, next_hop=next_hop)


def del_static_route(context, router_id, dest, prefix, next_hop):
    api_client = get_tn_client(context, router_id)
    try:
        api_client.request(templates.DEL_STATIC_ROUTE, dest=dest, netmask=prefix, gw_ip=next_hop)
    except Exception:
        raise
    else:
        tn_db.delete_record(context, tn_db.Tn_Static_Route,
                            router_id=router_id, dest=dest, prefix=prefix, next_hop=next_hop)


def get_static_route(context, **kwargs):
    return tn_db.query_records(context, tn_db.Tn_Static_Route, **kwargs)


def router_test(context):
    # create_router(context, '1234567890000', '987654321', 'xxx', '/opt/stack/tnos/tnos.qcow2', '80.1.1.10')


    add_static_route(context, '88ca761e-d06c-49e2-92cb-0c552c779a6e', '0.0.0.0', '0', '172.24.4.1')

    # del_router(context, '1234567890000')


