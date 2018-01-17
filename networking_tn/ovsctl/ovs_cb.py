
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

ovs_db = ovsdb_api.from_config(None)


def add_port(bridge_name, port_name):
    with ovs_db.transaction() as txn:
        cmd = ovs_db.add_port(bridge=bridge_name, may_exist=False, port=port_name)
        txn.add(cmd)

def del_port(bridge_name, port_name):
    with ovs_db.transaction() as txn:
        cmd = ovs_db.del_port(bridge=bridge_name, if_exists=True, port=port_name)
        txn.add(cmd)

def add_port_tag(port_name, tag):
    port_names = []
    port_names.append(port_name)
    port_info = ovs_db.db_list("Port", port_names, columns=["name", "tag", "other_config"],
                               if_exists=True).execute(check_error=True, log_errors=True)

    info_by_port = {
        x['name']: {
            'tag': x['tag'],
            'other_config': x['other_config'] or {}
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

def get_port_tag(port_name):

    LOG.debug('trace')

    port_info = ovs_db.db_list("Port", None, columns=["name", "tag", "other_config"],
                                    if_exists=True).execute(check_error=False, log_errors=False)
    if port_info != None:
        return port_info

    #with ovs_db.transaction() as txn:
    #    cmd = ovs_db.db_list("Port", None, columns=["name", "tag", "other_config"], if_exists=True)
    #    txn.add(cmd)
    #    port_info = cmd.result

    if port_info != None:
        LOG.debug('trace %d', len(port_info))

        for cur_info in port_info:
            LOG.debug('%s %s', cur_info['name'], port_name)
            if cur_info['name'][3:13] in port_name:
                return (cur_info['name'], cur_info['tag'])

    return ('nothing', None)

def conf_list():
    port_info = ovs_db.db_list("Port", None, columns=["name", "tag", "other_config"],
                                      if_exists=True).execute(check_error=True, log_errors=True)
    for x in port_info:
        print('port_info:', x)


def main():

    print('step4')
    #add_port('br-int', 'tap0')
    #add_port_tag('tap0', 2)
    #add_port('br-int', 'tap1')
    #add_port_tag('tap1', 1)
    #conf_list()

    get_port_tag('123')

if __name__ == '__main__':
    main()