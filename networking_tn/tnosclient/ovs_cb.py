
import neutron.plugins.ml2.models as ml2_db
from neutron.agent.ovsdb import api as ovsdb_api
'''
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.schema.open_vswitch import impl_idl
from ovsdbapp import constants

from ovs.db import idl
from ovsdbapp.backend.ovs_idl import idlutils
'''

from oslo_log import log as logging

if __name__ == '__main__':
    #sys.path.append(r'/home/xiongjun/work/networking-tn/')
    LOG = logging.getLogger(None).logger
    # LOG.addHandler(streamlog)
    LOG.setLevel(logging.DEBUG)
else:
    LOG = logging.getLogger(__name__)

ovs_db = None

def connect_ovs_db(context):
    global ovs_db
    if ovs_db == None:
        ovs_db = ovsdb_api.from_config(context)

def add_port(context, bridge_name, port_name):
    connect_ovs_db(context)
    with ovs_db.transaction() as txn:
        cmd = ovs_db.add_port(bridge=bridge_name, may_exist=False, port=port_name)
        txn.add(cmd)

def del_port(context, bridge_name, port_name):
    connect_ovs_db(context)
    with ovs_db.transaction() as txn:
        cmd = ovs_db.del_port(bridge=bridge_name, if_exists=True, port=port_name)
        txn.add(cmd)

def add_trunk_port_tag(context, port_name, tag):
    connect_ovs_db(context)
    port_names = []
    port_names.append(port_name)
    port_infos = ovs_db.db_list("Port", port_names, columns=["name", "trunks"],
                               if_exists=True).execute(check_error=True, log_errors=True)
    #port_info = ovs_db.db_list("Port", None, if_exists=True).execute(check_error=True, log_errors=True)

    if port_infos != []:
        port_info = port_infos[0]

        LOG.debug(port_info)

        tags = port_info['trunks']
        if tag not in tags:
            tags.append(tag)
            ovs_db.db_set('Port', port_name, ("trunks", tags)).execute(check_error=False, log_errors=True)


def del_trunk_port_tag(context, port_name, tag):
    connect_ovs_db(context)
    port_names = []
    port_names.append(port_name)
    port_infos = ovs_db.db_list("Port", port_names, columns=["name", "trunks"],
                               if_exists=True).execute(check_error=True, log_errors=True)
    #port_info = ovs_db.db_list("Port", None, if_exists=True).execute(check_error=True, log_errors=True)

    if port_infos != []:
        port_info = port_infos[0]

        LOG.debug(port_info)

        tags = port_info['trunks']
        if tag in tags:
            tags.remove(tag)
            ovs_db.db_set('Port', port_name, ("trunks", tags)).execute(check_error=False, log_errors=True)


def add_access_port_tag(context, port_name, tag):
    connect_ovs_db(context)
    port_names = []
    port_names.append(port_name)
    port_infos = ovs_db.db_list("Port", port_names, columns=["name", "tag"],
                                if_exists=True).execute(check_error=True, log_errors=True)
    # port_info = ovs_db.db_list("Port", None, if_exists=True).execute(check_error=True, log_errors=True)

    if port_infos != []:
        port_info = port_infos[0]

        LOG.debug(port_info)

        if port_info['tag'] != tag:
            ovs_db.db_set('Port', port_name, ("tag", tag)).execute(check_error=False, log_errors=True)
    '''
    return

    for x in port_info:
        #LOG.debug('port_info:', x)
        print('port_info:', x)

    info_by_port = {
        x['name']: {
            'trunks': x['trunks']
        }
        for x in port_info
    }

    for name in port_names:
        try:
            cur_info = info_by_port[name]
        except KeyError:
            continue
        other_config = cur_info['other_config']

        if cur_info['tag'] != tag:
            other_config['tag'] = str(tag)
            ovs_db.db_set('Port', name, ("other_config", other_config)).execute(check_error=False, log_errors=True)
            ovs_db.db_set('Port', name, ("tag", tag)).execute(check_error=False, log_errors=True)

    '''

def del_access_port_tag(context, port_name):
    connect_ovs_db(context)
    port_names = []
    port_names.append(port_name)
    port_infos = ovs_db.db_list("Port", port_names, columns=["name", "tag"],
                                if_exists=True).execute(check_error=True, log_errors=True)
    # port_info = ovs_db.db_list("Port", None, if_exists=True).execute(check_error=True, log_errors=True)
    if port_infos != []:
        port_info = port_infos[0]

        LOG.debug(port_info)
        ovs_db.db_set('Port', port_name, ("tag", None)).execute(check_error=False, log_errors=True)

def get_port_tag(context, port_name):
    connect_ovs_db(context)

    port_info = ovs_db.db_list("Port", None, columns=["name", "tag", "other_config"],
                                    if_exists=True).execute(check_error=False, log_errors=False)

    if port_info != None:
        LOG.debug('trace %d', len(port_info))

        for cur_info in port_info:
            if cur_info['name'][3:13] in port_name:
                return (cur_info['name'], cur_info['tag'])

    return (None, None)

def conf_list(context):
    connect_ovs_db(context)
    port_info = ovs_db.db_list("Port", None, columns=["name", "tag", "other_config"],
                                      if_exists=True).execute(check_error=True, log_errors=True)
    for x in port_info:
        print('port_info:', x)


def main():

    print('step4')
    #add_port('br-int', 'tap0')
    #add_port_tag('tap0', 2)
    #add_port('br-int', 'tap1')

    add_port_tag(None, 'tap1-beb4b806', 10)
    #add_port_tag(None, 'tap1-beb4b806', 11)
    #add_port_tag(None, 'tap1-beb4b806', 12)

    #conf_list()

    #get_port_tag('123')

if __name__ == '__main__':
    main()