
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

class TNL3Address(object):
    @staticmethod
    def create(context, rule_id, name, ip_prefix):
        tn_db.add_record(context, tn_db.Tn_Address, rule_id=rule_id, name=name, ip_prefix=ip_prefix)

    @staticmethod
    def delete(context, rule_id, name):
        tn_db.delete_record(context, tn_db.Tn_Address, rule_id=rule_id, name=name)

    @staticmethod
    def add_apply(context, client, rule_id, name):
        addr = tn_db.query_record(context, tn_db.Tn_Address, rule_id=rule_id, name=name)

        if addr is not None:
            client.request(templates.ADD_ADDRESS_ENTRY, name=addr.name, ip_prefix=addr.ip_prefix)

    @staticmethod
    def del_apply(context, client, rule_id, name):
        addr = tn_db.query_record(context, tn_db.Tn_Address, rule_id=rule_id, name=name)

        if addr is not None:
            client.request(templates.DEL_ADDRESS_ENTRY, name=addr.name)

class TNService(object):
    @staticmethod
    def create(context, rule_id, name, protocol=None, src_port=None, dst_port=None):
        if src_port == None:
            src_port_min = '0'
            src_port_max = L4_PORT_MAX
        elif ':' in src_port:
            range = src_port.split(':')
            src_port_min = range[0]
            src_port_max = range[1]
        else:
            src_port_min = src_port
            src_port_max = src_port

        if dst_port == None:
            dst_port_min = '0'
            dst_port_max = L4_PORT_MAX
        elif ':' in dst_port:
            range = dst_port.split(':')
            dst_port_min = range[0]
            dst_port_max = range[1]
        else:
            dst_port_min = dst_port
            dst_port_max = dst_port

        tn_db.add_record(context, tn_db.Tn_Service, rule_id=rule_id, name=name,
                         protocol=protocol, src_port_min=src_port_min, src_port_max=src_port_max,
                         dst_port_min=dst_port_min, dst_port_max=dst_port_max)

    @staticmethod
    def delete(context, rule_id):
        tn_db.delete_record(context, tn_db.Tn_Service, rule_id=rule_id)

    @staticmethod
    def add_apply(context, client, rule_id):
        svc = tn_db.query_record(context, tn_db.Tn_Service, rule_id=rule_id)

        if svc is not None:
            client.request(templates.ADD_SERVICE_ENTRY, name=svc.name, protocol=svc.protocol,
                           dst_port_max=svc.dst_port_max, dst_port_min=svc.dst_port_min,
                           src_port_max=svc.src_port_max, src_port_min=svc.src_port_min)

    @staticmethod
    def del_apply(context, client, rule_id):
        svc = tn_db.query_record(context, tn_db.Tn_Service, rule_id=rule_id)

        if svc is not None:
            client.request(templates.DEL_SERVICE_ENTRY, name=svc.name, protocol=svc.protocol,
                           dst_port_max=svc.dst_port_max, dst_port_min=svc.dst_port_min,
                           src_port_max=svc.src_port_max, src_port_min=svc.src_port_min)

class TNRule(object):
    @staticmethod
    def create(context, inner_id, rule_dict):
        ''' rule_dict is :
        {'protocol': u'tcp', 'description': u'', 'source_port': None, 'source_ip_address': u'11.1.1.1/24',
         'destination_ip_address': None, 'firewall_policy_id': None, 'position': None, 'destination_port': None,
         'id': '420de054-dd56-477f-bb45-2aa697182fb9', 'name': u'test-rule-4',
         'tenant_id': u'38f7e18b122949f39473e8c6d76aae19', 'enabled': True, 'action': u'allow', 'ip_version': 4,
         'shared': False, 'project_id': u'38f7e18b122949f39473e8c6d76aae19'}
         '''

        id = rule_dict['id']
        name = rule_dict['name']+'-'+str(inner_id)
        desc = rule_dict['description']
        protocol = rule_dict['protocol']
        action = TNOS_ACTION[rule_dict['action']]
        enable = 'enable' if rule_dict['enabled'] else 'disable'
        policy_id = rule_dict['firewall_policy_id']

        srcaddr = TNRule.init_address(context, id, name, '-sa', rule_dict['source_ip_address'])
        dstaddr = TNRule.init_address(context, id, name, '-da', rule_dict['destination_ip_address'])

        service = TNRule.init_service(context, id, name, rule_dict['protocol'],
                                      rule_dict['source_port'], rule_dict['destination_port'])

        return tn_db.add_record(context, tn_db.Tn_Rule, id=id, policy_id=policy_id, inner_id=inner_id,
                         name=name, desc=desc, protocol=protocol, action=action, enable=enable,
                         srcaddr=srcaddr, dstaddr=dstaddr, service=service)

    @staticmethod
    def delete(context, rule):
        TNL3Address.delete(context, rule.id, rule.srcaddr)
        TNL3Address.delete(context, rule.id, rule.dstaddr)
        TNService.delete(context, rule.id)
        tn_db.delete_record(context, tn_db.Tn_Rule, id=rule.id)

    @staticmethod
    def gets(context, **kwargs):
        return tn_db.query_records(context, tn_db.Tn_Rule, **kwargs)

    @staticmethod
    def get(context, **kwargs):
        return tn_db.query_record(context, tn_db.Tn_Rule, **kwargs)

    @staticmethod
    def init_address(context, rule_id, rule_name, addr_postfix, addr):
        if addr != None:
            addr_name = rule_name+addr_postfix
            TNL3Address.create(context, rule_id, addr_name, addr)
        else:
            addr_name = 'Any'

        return addr_name

    @staticmethod
    def init_service(context, rule_id, rule_name, protocol, src_port, dst_port):
        if (protocol == None and src_port == None and dst_port == None):
            svc_name = 'Any'

        elif (protocol == 'tcp' and src_port == None and dst_port == None):
            svc_name = 'TCP-ANY'

        elif (protocol == 'udp' and src_port == None and dst_port == None):
            svc_name = 'UDP-ANY'

        elif protocol == "icmp":
            svc_name = 'ICMP'

        else:
            svc_name = rule_name+'-svc'
            TNService.create(context, rule_id, svc_name, protocol, src_port, dst_port)

        return svc_name

    @staticmethod
    def add_apply(context, client, rule):
        LOG.debug('trace')
        TNL3Address.add_apply(context, client, rule.id, rule.srcaddr)
        TNL3Address.add_apply(context, client, rule.id, rule.dstaddr)
        TNService.add_apply(context, client, rule.id)

        client.request(templates.ADD_RULE, id=rule.inner_id, name=rule.name, action=rule.action, desc=rule.desc,
                       daddr=rule.dstaddr, saddr=rule.srcaddr, service=rule.service, status=rule.enable)

    @staticmethod
    def del_apply(context, client, rule):
        LOG.debug('trace')
        client.request(templates.DEL_RULE, id=rule.inner_id, name=rule.name, action=rule.action, desc=rule.desc,
                       daddr=rule.dstaddr, saddr=rule.srcaddr, service=rule.service, status=rule.enable)

        TNL3Address.del_apply(context, client, rule.id, rule.srcaddr)
        TNL3Address.del_apply(context, client, rule.id, rule.dstaddr)
        TNService.del_apply(context, client, rule.id)


class TNPolicy(object):
    @staticmethod
    def create(context, id, name, desc=None):
        return tn_db.add_record(context, tn_db.Tn_Policy, id=id, name=name, desc=desc, reference_count=1)

    @staticmethod
    def delete(context, policy):
        rules = TNRule.gets(context, policy_id=policy.id)
        for rule in rules:
            TNPolicy.del_rule(context, policy, rule)

        tn_db.delete_record(context, tn_db.Tn_Policy, id=policy.id)

    @staticmethod
    def update(context, obj, **kwargs):
        tn_db.update_record(context, obj, **kwargs)

    @staticmethod
    def get(context, **kwargs):
        return tn_db.query_record(context, tn_db.Tn_Policy, **kwargs)

    @staticmethod
    def add_rule(context, policy, rule_dict):
        if policy.rule_inner_use is None:
            used = []
        else:
            used = policy.rule_inner_use.split(',')

        for i in range(TNOS_RULE_ID_MIN, TNOS_RULE_ID_MAX+1):
            if str(i) not in used:
                rule = TNRule.create(context, i, rule_dict)
                used.append(str(i))
                used = ','.join(used)

                TNPolicy.update(context, policy, rule_inner_use=used)

                return rule

    @staticmethod
    def del_rule(context, policy, rule):
        used = policy.rule_inner_use.split(',')
        used.remove(str(rule.inner_id))
        used = ','.join(used)
        TNPolicy.update(context, policy, rule_inner_use=used)

        TNRule.delete(context, rule)


    @staticmethod
    def insert_rule_apply(context, client, policy, src_rule_id, dst_rule_id, action):

        src = TNRule.get(context, id=src_rule_id)
        dst = TNRule.get(context, id=dst_rule_id)
        client.request(templates.MOVE_RULE, srcKey=src.inner_id, dstKey=dst.inner_id, action=action)
        '''
        self.rules.remove(src)
        dst_index = self.rules.index(dst)
        if action == TNOS_INSERT_RULE_ACTION['insert_before']:
            self.rules.insert(dst_index,src)
        if action == TNOS_INSERT_RULE_ACTION['insert_after']:
            self.rules.insert(dst_index+1,src)
        '''

    @staticmethod
    def add_rule_and_apply(context, client, policy, rule_dict):
        rule = TNPolicy.add_rule(context, policy, rule_dict)
        TNRule.add_apply(context, client, rule)

    @staticmethod
    def remove_rule_and_apply(context, client, policy, rule_id):
        rule = TNRule.get(context, id=rule_id)
        TNRule.del_apply(context, client, rule)
        TNPolicy.del_rule(context, policy, rule)


class TNFirewall(object):
    @staticmethod
    def create(context, id, name, desc=None):
        return tn_db.add_record(context, tn_db.Tn_Firewall, id=id, name=name, desc=desc)

    @staticmethod
    def delete(context, fw):
        TNFirewall.del_policy(context, fw)
        tn_db.delete_record(context, tn_db.Tn_Firewall, id=fw.id)

    @staticmethod
    def update(context, obj, **kwargs):
        tn_db.update_record(context, obj, **kwargs)

    @staticmethod
    def get(context, **kwargs):
        return tn_db.query_record(context, tn_db.Tn_Firewall, **kwargs)

    @staticmethod
    def add_policy(context, fw, policy_id, name=None, desc=None):
        policy = TNPolicy.get(context, id=policy_id)
        if policy is None:
            policy = TNPolicy.create(context, policy_id, name, desc)
        else:
            TNPolicy.update(context, policy, reference_count=policy.reference_count+1)

        TNFirewall.update(context, fw, policy_id=policy_id)
        return policy

    @staticmethod
    def del_policy(context, fw):
        policy = TNPolicy.get(context, id=fw.policy_id)
        if policy is not None:
            count = policy.reference_count - 1
            if count == 0:
                TNPolicy.delete(context, policy)
            else:
                TNPolicy.update(context, policy, reference_count=count)

        TNFirewall.update(context, fw, policy_id=None)

    @staticmethod
    def apply_to_router(context, fw, router_id):
        if fw.router_ids is not None:
            router_ids = fw.router_ids.split(',')
        else:
            router_ids = []

        if router_id not in router_ids:
            router_ids.append(router_id)
            LOG.debug('router ids %s', router_ids)
            router_ids = ','.join(router_ids)

            LOG.debug('router ids %s', router_ids)
            TNFirewall.update(context, fw, router_ids=router_ids)
            client = tnos.get_tn_client(context, router_id)
            if client != None:
                rules = TNRule.gets(context, policy_id=fw.policy_id)
                for rule in rules:
                    TNRule.add_apply(context, client, rule)
            else:
                LOG.debug('error')

    @staticmethod
    def unapply_to_router(context, fw, router_id):
        LOG.debug('router ids %s', fw.router_ids)
        router_ids = fw.router_ids.split(',')
        if router_id in router_ids:
            LOG.debug('trace')
            router_ids.remove(router_id)
            router_ids = ','.join(router_ids)
            TNFirewall.update(context, fw, router_ids=router_ids)
            client = tnos.get_tn_client(context, router_id)
            if client != None:
                rules = TNRule.gets(context, policy_id=fw.policy_id)
                for rule in rules:
                    TNRule.del_apply(context, client, rule)
            else:
                LOG.debug('error')

    @staticmethod
    def add_rule_and_apply(context, fw, rule_dict):
        router_ids = fw.router_ids.split(',')
        for router_id in router_ids:
            client = tnos.get_tn_client(context, router_id)
            if client != None:
                policy = TNPolicy.get(context, id=fw.policy_id)
                TNPolicy.add_rule_and_apply(context, client, policy, rule_dict)
            else:
                LOG.debug('error')

    @staticmethod
    def update_rule_and_apply(context, fw, rule_dict):
        TNFirewall.remove_rule_and_apply(context, fw, rule_dict['id'])
        TNFirewall.add_rule_and_apply(context, fw, rule_dict)

    @staticmethod
    def move_rule_apply(context, fw, src_rule_id, dst_rule_id, action):
        router_ids = fw.router_ids.split(',')
        for router_id in router_ids:
            client = tnos.get_tn_client(context, router_id)
            if client != None:
                policy = TNPolicy.get(context, id=fw.policy_id)
                TNPolicy.insert_rule_apply(context, client, policy, src_rule_id, dst_rule_id, action)
            else:
                LOG.debug('error')

    @staticmethod
    def remove_rule_and_apply(context, fw, rule_id):
        router_ids = fw.router_ids.split(',')
        for router_id  in router_ids:
            client = tnos.get_tn_client(context, router_id)
            if client != None:
                policy = TNPolicy.get(context, id=fw.policy_id)
                TNPolicy.remove_rule_and_apply(context, client, policy, rule_id)
            else:
                LOG.debug('error')

def main_test(context):

    router_id = '48026c38-9fb8-4fd6-ac56-237d17fd8b9f'

    '''
    tn_fw = TNFirewall.create(context, '111111111', 'test1', 'test1-desc')
    tn_policy = TNFirewall.add_policy(context, tn_fw, '111111', 'test1-desc')

    rule_info = {
        'protocol': u'tcp', 'description': u'123', 'source_port': None, 'source_ip_address': u'10.1.1.1/24',
        'destination_ip_address': None, 'firewall_policy_id': u'111111',
        'position': 1, 'destination_port': None, 'id': u'5683780b-77d3-4d1b-acb7-4360b7f48347',
        'name': u'test-rule-1', 'tenant_id': u'38f7e18b122949f39473e8c6d76aae19', 'enabled': True,
        'action': 'allow', 'ip_version': 4, 'shared': False, 'project_id': u'38f7e18b122949f39473e8c6d76aae19'
    }
    TNPolicy.add_rule(context, tn_policy, rule_info)

    rule_info = {
        'protocol': u'tcp', 'description': u'123', 'source_port': None, 'source_ip_address': None,
        'destination_ip_address': u'20.1.1.1/24', 'firewall_policy_id': u'111111',
        'position': 1, 'destination_port': None, 'id': u'5683780b-77d3-4d1b-acb7-4360b7f48348',
        'name': u'test-rule-2', 'tenant_id': u'38f7e18b122949f39473e8c6d76aae19', 'enabled': True,
        'action': 'allow', 'ip_version': 4, 'shared': False, 'project_id': u'38f7e18b122949f39473e8c6d76aae19'
    }
    TNPolicy.add_rule(context, tn_policy, rule_info)

    TNFirewall.apply_to_router(context, tn_fw, router_id)
    '''


    tn_fw = TNFirewall.get(context, id='111111111')

    '''
    rule_info = {
        'protocol': u'icmp', 'description': u'123', 'source_port': None, 'source_ip_address': u'10.1.1.1/24',
        'destination_ip_address': None, 'firewall_policy_id': u'111111',
        'position': 1, 'destination_port': None, 'id': u'5683780b-77d3-4d1b-acb7-4360b7f48349',
        'name': u'test-rule-3', 'tenant_id': u'38f7e18b122949f39473e8c6d76aae19', 'enabled': True,
        'action': 'allow', 'ip_version': 4, 'shared': False, 'project_id': u'38f7e18b122949f39473e8c6d76aae19'
    }

    TNFirewall.add_rule_and_apply(context, tn_fw, rule_info)
    '''

    #TNFirewall.remove_rule_and_apply(context, tn_fw, '5683780b-77d3-4d1b-acb7-4360b7f48349')
    TNFirewall.move_rule_apply(context, tn_fw, '5683780b-77d3-4d1b-acb7-4360b7f48349',
                               '5683780b-77d3-4d1b-acb7-4360b7f48347', TNOS_INSERT_RULE_ACTION['insert_before'])

    '''
    TNFirewall.unapply_to_router(context, tn_fw, router_id)
    TNFirewall.delete(context, tn_fw)
    '''
