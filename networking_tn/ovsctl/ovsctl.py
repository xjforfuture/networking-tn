from oslo_config import cfg
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.schema.open_vswitch import impl_idl
from ovsdbapp import constants

from debtcollector import moves
from ovs.db import idl
from ovsdbapp.backend.ovs_idl import idlutils
import tenacity

'''
from neutron.agent.ovsdb.native import helpers

TransactionQueue = moves.moved_class(connection.TransactionQueue,
                                     'TransactionQueue', __name__)
moves.moved_class(connection.Connection, 'Connection', __name__)
'''

_connection = None

def idl_factory():
    conn = constants.DEFAULT_OVSDB_CONNECTION
    schema_name = 'Open_vSwitch'
    helper = idlutils.get_schema_helper(conn, schema_name)

    print('step0')
    '''
    try:
        helper = idlutils.get_schema_helper(conn, schema_name)
    except Exception:
        helpers.enable_connection_uri(conn)

        @tenacity.retry(wait=tenacity.wait_exponential(multiplier=0.01),
                        stop=tenacity.stop_after_delay(1),
                        reraise=True)
        def do_get_schema_helper():
            return idlutils.get_schema_helper(conn, schema_name)

        helper = do_get_schema_helper()
    '''
    # TODO(twilson) We should still select only the tables/columns we use
    helper.register_all()

    print('step1')
    return idl.Idl(conn, helper)


def api_factory():
    global _connection
    if _connection is None:
        try:
            _connection = connection.Connection(
                idl=idl_factory(),
                timeout=10)
        except TypeError:
            #pylint: disable=unexpected-keyword-arg,no-value-for-parameter
            _connection = connection.Connection(
                idl_factory=idl_factory,  # noqa
                timeout=10)
    return impl_idl.OvsdbIdl(_connection)

class OvsCtlBlock():
    def __init__(self):
        self.ovs_db = api_factory()

    def add_port(self, bridge_name, port_name):
        with self.ovs_db.transaction() as txn:
            cmd = self.ovs_db.add_port(bridge=bridge_name, may_exist=False, port=port_name)
            txn.add(cmd)

    def del_port(self, bridge_name, port_name):
        with self.ovs_db.transaction() as txn:
            cmd = self.ovs_db.del_port(bridge=bridge_name, if_exists=True, port=port_name)
            txn.add(cmd)

    def add_port_tag(self, port_name, tag):
        port_names = []
        port_names.append(port_name)
        port_info = self.ovs_db.db_list("Port", port_names, columns=["name", "tag", "other_config"],
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
                self.ovs_db.db_set('Port', name, ("other_config", other_config)).execute(check_error=False, log_errors=True)
                self.ovs_db.db_set('Port', name, ("tag", tag)).execute(check_error=False, log_errors=True)

    def get_port_tag(self, port_name):

        port_info = self.ovs_db.db_list("Port", None, columns=["name", "tag", "other_config"],
                                        if_exists=True).execute(check_error=True, log_errors=True)
        # todo xiongjun.  router interface name must be rename
        info = [x for x in port_info if len(x['name'])>10]
        for cur_info in info:
            if cur_info['name'][3:13] in port_name:
                return (cur_info['name'], cur_info['tag'])

        return (None, None)

    def conf_list(self):
        port_info = self.ovs_db.db_list("Port", None, columns=["name", "tag", "other_config"],
                                          if_exists=True).execute(check_error=True, log_errors=True)
        for x in port_info:
            print('port_info:', x)


def main():
    ovsctl = OvsCtlBlock()
    print('step4')
    ovsctl.add_port('br-int', 'tap0')
    ovsctl.add_port_tag('tap0', 2)
    ovsctl.add_port('br-int', 'tap1')
    ovsctl.add_port_tag('tap1', 1)
    ovsctl.conf_list()

if __name__ == '__main__':
    main()