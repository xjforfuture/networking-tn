# Copyright 2017 tsinghuanet Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import libvirt
import subprocess
import time

TNOS_VM_STATE = 'running'


class LibvirtDriver():

    VIRT_STATE_NAME_MAP = {0: TNOS_VM_STATE,
                           1: TNOS_VM_STATE,
                           2: TNOS_VM_STATE,
                           3: 'paused',
                           4: 'shutdown',
                           5: 'shutdown',
                           6: 'crashed'}

    @staticmethod
    def __get_conn():
        '''
        Detects what type of dom this node is and attempts to connect to the
        correct hypervisor via libvirt.
        '''
        # This has only been tested on kvm and xen, it needs to be expanded to
        # support all vm layers supported by libvirt
        try:
            conn = libvirt.open('qemu:///system')
        except Exception:
            print('Sorry,failed to open a connection to the hypervisor ')
        return conn

    @staticmethod
    def list_active_vms():
        '''
        Return a list of names for active virtual machine on the minion

        CLI Example::

            salt '*' virt.list_active_vms
        '''
        conn = LibvirtDriver.__get_conn()
        vms = []
        for id_ in conn.listDomainsID():
            vms.append(conn.lookupByID(id_).name())
        print(vms)
        return vms

    @staticmethod
    def list_inactive_vms():
        '''
        Return a list of names for inactive virtual machine on the minion

        CLI Example::

            salt '*' virt.list_inactive_vms
        '''
        conn = LibvirtDriver.__get_conn()
        vms = []
        for id_ in conn.listDefinedDomains():
            vms.append(id_)

        print(vms)
        return vms

    @staticmethod
    def list_vms():
        '''
        Return a list of virtual machine names on the minion

        CLI Example::

            salt '*' virt.list_vms
        '''
        vms = []
        vms.extend(LibvirtDriver.list_active_vms())
        vms.extend(LibvirtDriver.list_inactive_vms())

        print('list_vms ', len(vms), vms)
        return vms

    @staticmethod
    def _get_dom(vm_):
        '''
        Return a domain object for the named vm
        '''
        conn = LibvirtDriver.__get_conn()
        if vm_ not in LibvirtDriver.list_vms():
            raise Exception('The specified vm is not present')
        return conn.lookupByName(vm_)

    @staticmethod
    def vm_state(vm_=None):
        '''
        Return list of all the vms and their state.

        If you pass a VM name in as an argument then it will return info
        for just the named VM, otherwise it will return all VMs.

        CLI Example::

            salt '*' virt.vm_state <vm name>
        '''

        def _info(vm_):
            state = ''
            dom = LibvirtDriver._get_dom(vm_)
            raw = dom.info()
            state = LibvirtDriver.VIRT_STATE_NAME_MAP.get(raw[0], 'unknown')
            return state

        info = {}
        if vm_:
            info[vm_] = _info(vm_)
        else:
            for vm_ in LibvirtDriver.list_vms():
                info[vm_] = _info(vm_)
        return info


class TNOSvm():
    libvirt_cmd = '''kvm -nographic -device e1000,netdev=eth0 -netdev tap,id=eth0,script=nothing -device e1000,netdev=eth1 -netdev tap,id=eth1,script=nothing '''

    def __init__(self, vmname, image_name):
        self.manage_ip = None
        self.subprocess = None
        self.vmname = vmname
        self.image_name = image_name

    def start(self):
        '''create tnos vm'''
        cmd = TNOSvm.libvirt_cmd + self.image_name
        self.subprocess = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)

        for i in range(50):
            message = self.subprocess.stdout.readline()
            print message
            if 'Username' in message:
                break

        self.subprocess.stdin.write('admin\n')
        message = self.subprocess.stdout.readline()
        print message

        self.subprocess.stdin.write('admin\n')
        message = self.subprocess.stdout.readline()
        print message

        self.subprocess.stdin.write('\n')
        message = self.subprocess.stdout.readline()
        print message

        self.subprocess.stdin.write('\n')
        message = self.subprocess.stdout.readline()
        print message

        self.set_mange_ip('20.1.1.3', '255.255.255.0')


    def destroy(self):
        pass

    def is_running(self):
        try:
            self.subprocess.stdin.write('\n')
        except Exception:
            return False

    def login(self, username='admin', passward='admin'):
        self.subprocess.stdin.write(username+'\n')
        self.subprocess.stdin.write(passward+'\n')

    def set_mange_ip(self, ip, mask):
        self.subprocess.stdin.write('enable\n')
        message = self.subprocess.stdout.readline()
        print message

        self.subprocess.stdin.write('config\n')
        message = self.subprocess.stdout.readline()
        print message

        self.subprocess.stdin.write('interface ethernet0\n')
        message = self.subprocess.stdout.readline()
        print message

        cmd = 'ip address '+ ip + ' ' + mask +'\n'
        self.subprocess.stdin.write(cmd)
        message = self.subprocess.stdout.readline()
        print message

        self.subprocess.stdin.write('enable\n')
        message = self.subprocess.stdout.readline()
        print message


def main():
    tnos = TNOSvm('tnos1', '/home/xiongjun/work/tnos_d65a731d65a731.qcow2')
    tnos.start()
    #if tnos.is_running():
    tnos.login()
    tnos.set_mange_ip('20.1.1.3', '255.255.255.0')
    #else:
    print('tnos is not running')



if __name__ == "__main__":
    main()
