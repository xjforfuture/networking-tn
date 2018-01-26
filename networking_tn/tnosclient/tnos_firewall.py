
from oslo_log import log as logging

from networking_tn.db import tn_db
from networking_tn.tnosclient import templates
from networking_tn.tnosclient import tnos_router as tnos
from networking_tn.tnosclient.tnos_router import *

if __name__ == '__main__':
    sys.path.append(r'/home/xiongjun/work/networking-tn/')
    LOG = logging.getLogger(None).logger
    LOG.setLevel(logging.DEBUG)
else:
    LOG = logging.getLogger(__name__)

L4_PORT_MAX = '65535'
TNOS_RULE_ID_MIN = 1
TNOS_RULE_ID_MAX = 256

TNOS_ACTION = {'allow':'permit',
               'deny':'deny',
               'reject':'deny'}

TNOS_INSERT_RULE_ACTION = {'insert_after':'after', 'insert_before':'before'}

TN_POLICIES = {}

def get_tn_fw(fw_id):
    return tn_db.tn_db_get('firewall'+str(fw_id))

def get_tn_policy(policy_id):
    try:
        return TN_POLICIES[policy_id]
    except:
        policy = tn_db.tn_db_get('policy' + str(policy_id))
        if policy != None:
            TN_POLICIES[policy_id] = policy
            return policy


class TNL3Address(object):
    def __init__(self, name, ip_prefix):
        self.name = name
        self.ip_prefix = ip_prefix

    def add_apply(self, client):
        if self.name != ADDR_ANY.name:
            client.request(templates.ADD_ADDRESS_ENTRY, name=self.name, ip_prefix=self.ip_prefix)

    def del_apply(self, client):
        if self.name != ADDR_ANY.name:
            client.request(templates.DEL_ADDRESS_ENTRY, name=self.name)


ADDR_ANY = TNL3Address('Any', '0.0.0.0/0')

class TNService(object):
    def __init__(self, name, protocol=None, src_port=None, dst_port=None):
        self.name = name
        self.protocol = protocol
        if src_port == None:
            self.src_port_min = '0'
            self.src_port_max = L4_PORT_MAX
        elif ':' in src_port:
            range = src_port.split(':')
            self.src_port_min = range[0]
            self.src_port_max = range[1]
        else:
            self.src_port_min = src_port
            self.src_port_max = src_port

        if dst_port == None:
            self.dst_port_min = '0'
            self.dst_port_max = L4_PORT_MAX
        elif ':' in dst_port:
            range = dst_port.split(':')
            self.dst_port_min = range[0]
            self.dst_port_max = range[1]
        else:
            self.dst_port_min = dst_port
            self.dst_port_max = dst_port

    def add_apply(self, client):
        if self.name not in DEFAULT_SERVICE:
            client.request(templates.ADD_SERVICE_ENTRY, name=self.name, protocol=self.protocol,
                           dst_port_max=self.dst_port_max, dst_port_min=self.dst_port_min,
                           src_port_max=self.src_port_max, src_port_min=self.src_port_min)

    def del_apply(self, client):
        if self.name not in DEFAULT_SERVICE:
            client.request(templates.DEL_SERVICE_ENTRY, name=self.name, protocol=self.protocol,
                           dst_port_max=self.dst_port_max, dst_port_min=self.dst_port_min,
                           src_port_max=self.src_port_max, src_port_min=self.src_port_min)

SERVICE_ANY = TNService('Any')
SERVICE_TCP_ANY = TNService('TCP-ANY', 'TCP')
SERVICE_UDP_ANY = TNService('UDP-ANY', 'UDP')
SERVICE_ICMP = TNService('ICMP', 'ICMP')
DEFAULT_SERVICE = [SERVICE_ANY.name, SERVICE_TCP_ANY.name, SERVICE_UDP_ANY.name, SERVICE_ICMP.name]


class TNRule(object):
    def __init__(self, inner_id, rule_dict):
        ''' rule_dict is :
        {'protocol': u'tcp', 'description': u'', 'source_port': None, 'source_ip_address': u'11.1.1.1/24',
         'destination_ip_address': None, 'firewall_policy_id': None, 'position': None, 'destination_port': None,
         'id': '420de054-dd56-477f-bb45-2aa697182fb9', 'name': u'test-rule-4',
         'tenant_id': u'38f7e18b122949f39473e8c6d76aae19', 'enabled': True, 'action': u'allow', 'ip_version': 4,
         'shared': False, 'project_id': u'38f7e18b122949f39473e8c6d76aae19'}
         '''

        self.id = rule_dict['id']
        self.inner_id = inner_id
        self.name = rule_dict['name']+'-'+str(self.inner_id)
        self.desc = rule_dict['description']
        self.protocol = rule_dict['protocol']
        self.action = TNOS_ACTION[rule_dict['action']]
        self.enable = 'enable' if rule_dict['enabled'] else 'disable'
        self.policy_id = rule_dict['firewall_policy_id']

        if rule_dict['source_ip_address'] != None:
            self.src_addr = TNL3Address(self.name+'-sa', rule_dict['source_ip_address'])
        else:
            self.src_addr = ADDR_ANY

        if rule_dict['destination_ip_address'] != None:
            self.dst_addr = TNL3Address(self.name+'-da', rule_dict['destination_ip_address'])
        else:
            self.dst_addr = ADDR_ANY

        self.init_service(rule_dict)


    def init_service(self, rule_dict):
        if (self.protocol == None
            and rule_dict['source_port'] == None
            and rule_dict['destination_port'] == None):
            self.service = SERVICE_ANY

        elif (self.protocol == 'tcp'
            and rule_dict['source_port'] == None
            and rule_dict['destination_port'] == None):
            self.service = SERVICE_TCP_ANY

        elif (self.protocol == 'udp'
            and rule_dict['source_port'] == None
            and rule_dict['destination_port'] == None):
            self.service = SERVICE_UDP_ANY

        elif self.protocol == "icmp":
            self.service = SERVICE_ICMP

        else:
            self.service = TNService(self.name+'-svc', self.protocol, rule_dict['source_port'], rule_dict['destination_port'])

    def add_apply(self, client):
        LOG.debug('trace')
        self.src_addr.add_apply(client)
        self.dst_addr.add_apply(client)
        self.service.add_apply(client)

        client.request(templates.ADD_RULE, id=self.inner_id, name=self.name, action=self.action, desc=self.desc,
                       daddr=self.dst_addr.name, saddr=self.src_addr.name, service=self.service.name, status=self.enable)

    def del_apply(self, client):
        LOG.debug('trace')
        client.request(templates.DEL_RULE, id=self.inner_id, name=self.name, action=self.action, desc=self.desc,
                       daddr=self.dst_addr.name, saddr=self.src_addr.name, service=self.service.name,
                       status=self.enable)

        self.src_addr.del_apply(client)
        self.dst_addr.del_apply(client)
        self.service.del_apply(client)


    def __str__(self):
        info = "id %s name %s src_ip_name %s" % (self.id, self.name, self.src_addr.name)
        return info

class TNPolicy(object):
    def __init__(self, id, name, desc=None):
        self.id = id
        self.name = name
        self.desc = desc
        self.rules = []
        self.firewall_id = []
        self.rule_inner_use = []

    def delete(self):
        del TN_POLICIES[self.id]
        tn_db.tn_db_del('policy'+str(self.id))

    def store(self):
        TN_POLICIES[self.id] = self
        tn_db.tn_db_modify('policy'+str(self.id), self)

    def add_rule(self, rule_dict):
        for i in range(TNOS_RULE_ID_MIN, TNOS_RULE_ID_MAX+1):
            if i not in self.rule_inner_use:
                self.rule_inner_use.append(i)

                rule = TNRule(i, rule_dict)
                rule.policy_id = self.id
                self.rules.append(rule)
                return rule

    def del_rule(self, rule_id):
        rule = self.get_rule(rule_id)
        if rule != None:
            self.rules.remove(rule)

    def insert_rule_apply(self, client, src_rule_id, dst_rule_id, action):

        src = self.get_rule(src_rule_id)
        dst = self.get_rule(dst_rule_id)
        client.request(templates.MOVE_RULE, srcKey=src.inner_id, dstKey=dst.inner_id, action=action)
        self.rules.remove(src)
        dst_index = self.rules.index(dst)
        if action == TNOS_INSERT_RULE_ACTION['insert_before']:
            self.rules.insert(dst_index,src)
        if action == TNOS_INSERT_RULE_ACTION['insert_after']:
            self.rules.insert(dst_index+1,src)

    def remove_rule_apply(self, client, rule_id):
        rule = self.get_rule(rule_id)
        if rule != None:
            rule.del_apply(client)
            self.del_rule(rule_id)

    def get_rule(self, rule_id):
        for rule in self.rules:
            if rule.id == rule_id:
                return rule


class TNFirewall(object):
    def __init__(self, id, name, desc=None):
        self.id = id
        self.name = name
        self.desc = desc
        self.policy_id = None
        self.router_ids = []

    def delete(self):
        policy = get_tn_policy(self.policy_id)
        if policy != None:
            policy.firewall_id.remove(self.id)
            if policy.firewall_id == []:
                policy.delete()

        tn_db.tn_db_del('firewall'+str(self.id))

    def store(self):
        policy = get_tn_policy(self.policy_id)
        if policy != None:
            policy.store()

        tn_db.tn_db_modify('firewall'+str(self.id), self)

    def add_policy(self, policy_id, name=None, desc=None):
        policy = get_tn_policy(policy_id)
        if policy == None:
            policy = TNPolicy(policy_id, name, desc)
        policy.firewall_id.append(self.id)
        self.policy_id = policy_id
        policy.store()
        return policy

    def del_policy(self):
        policy = get_tn_policy(self.policy_id)
        if policy != None:
            self.policy_id = None
            policy.firewall_id.remove(self.id)
            if policy.firewall_id == []:
                policy.delete()

    def apply_to_router(self, router_id):
        if router_id not in self.router_ids:
            self.router_ids.append(router_id)
            client = tnos.get_tn_client(router_id)
            if client != None:
                policy = get_tn_policy(self.policy_id)
                if policy != None:
                    for rule in policy.rules:
                        rule.add_apply(client)
            else:
                LOG.debug('error')

    def unapply_to_router(self, router_id):
        LOG.debug('router ids %s', self.router_ids)
        if router_id in self.router_ids:
            LOG.debug('trace')
            self.router_ids.remove(router_id)
            client = tnos.get_tn_client(router_id)
            if client != None:
                policy = get_tn_policy(self.policy_id)
                if policy != None:
                    for rule in policy.rules:
                        rule.del_apply(client)
            else:
                LOG.debug('error')

    def add_rule_apply(self, rule_dict):
        policy = get_tn_policy(self.policy_id)
        if policy != None:
            rule = policy.add_rule(rule_dict)
            for router_id in self.router_ids:
                client = tnos.get_tn_client(router_id)
                if client != None:
                    rule.add_apply(client)
                else:
                    LOG.debug('error')

    def update_rule_apply(self, rule_dict):
        self.remove_rule_apply(rule_dict['id'])
        self.add_rule_apply(rule_dict)

    def move_rule_apply(self, src_rule_id, dst_rule_id, action):
        for router_id in self.router_ids:
            client = tnos.get_tn_client(router_id)
            if client != None:
                policy = get_tn_policy(self.policy_id)
                policy.insert_rule_apply(client, src_rule_id, dst_rule_id, action)
            else:
                LOG.debug('error')

    def remove_rule_apply(self, rule_id):
        for router_id in self.router_ids:
            client = tnos.get_tn_client(router_id)
            if client != None:
                policy = get_tn_policy(self.policy_id)
                policy.remove_rule_apply(client, rule_id)
            else:
                LOG.debug('error')

def main():

    tn_fw = TNFirewall('0a70bcd8-66cb-4235-b8b4-7dda9a3256bf', 'test1', 'test1-desc')
    tn_policy = tn_fw.add_policy('1234', 'test1', 'test1-desc')

    rule_info = {
        'protocol': u'tcp', 'description': u'123', 'source_port': None, 'source_ip_address': u'10.1.1.1/24',
        'destination_ip_address': None, 'firewall_policy_id': u'86451772-69f4-438d-a27c-414997b5c1cc',
        'position': 1, 'destination_port': None, 'id': u'5683780b-77d3-4d1b-acb7-4360b7f48347',
        'name': u'test-rule-1', 'tenant_id': u'38f7e18b122949f39473e8c6d76aae19', 'enabled': True,
        'action': 'allow', 'ip_version': 4, 'shared': False, 'project_id': u'38f7e18b122949f39473e8c6d76aae19'
    }
    tn_policy.add_rule(rule_info)

    rule_info = {
        'protocol': u'tcp', 'description': u'123', 'source_port': None, 'source_ip_address': None,
        'destination_ip_address': u'20.1.1.1/24', 'firewall_policy_id': u'86451772-69f4-438d-a27c-414997b5c1cc',
        'position': 1, 'destination_port': None, 'id': u'5683780b-77d3-4d1b-acb7-4360b7f48348',
        'name': u'test-rule-2', 'tenant_id': u'38f7e18b122949f39473e8c6d76aae19', 'enabled': True,
        'action': 'allow', 'ip_version': 4, 'shared': False, 'project_id': u'38f7e18b122949f39473e8c6d76aae19'
    }
    tn_policy.add_rule(rule_info)

    tn_fw.store()

    tn_firewall = get_tn_fw('0a70bcd8-66cb-4235-b8b4-7dda9a3256bf')
    tn_firewall.apply_to_router('1234567890')

    rule_info = {
        'protocol': u'icmp', 'description': u'123', 'source_port': None, 'source_ip_address': u'10.1.1.1/24',
        'destination_ip_address': None, 'firewall_policy_id': u'86451772-69f4-438d-a27c-414997b5c1cc',
        'position': 1, 'destination_port': None, 'id': u'5683780b-77d3-4d1b-acb7-4360b7f48349',
        'name': u'test-rule-3', 'tenant_id': u'38f7e18b122949f39473e8c6d76aae19', 'enabled': True,
        'action': 'allow', 'ip_version': 4, 'shared': False, 'project_id': u'38f7e18b122949f39473e8c6d76aae19'
    }
    tn_firewall.add_rule_apply(rule_info)

    tn_firewall.move_rule_apply('5683780b-77d3-4d1b-acb7-4360b7f48349',
                                  '5683780b-77d3-4d1b-acb7-4360b7f48347',
                                  TNOS_INSERT_RULE_ACTION['insert_before'])

    #tn_firewall.unapply_to_router('1234567890')

if __name__ == '__main__':
    main()

