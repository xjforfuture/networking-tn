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

import os
import signal
import libvirt
import subprocess
import time
from shutil import copyfile

from oslo_log import log as logging

LOG = logging.getLogger(__name__)

VIRT_STATE_MAP = ['running',
                  'shutdown',
                  'crashed']

class TNOSvm():
    kvm_cmd = 'kvm -nographic ' \
                  + '-device e1000,netdev=eth0 -netdev tap,id=eth0,script=nothing ' \
                  + '-device e1000,netdev=eth1 -netdev tap,id=eth1,script=nothing ' \
                  + '-device e1000,netdev=eth2 -netdev tap,id=eth2,script=nothing '
    image = 'tnos'
    image_id = 0
    tnosvm = []

    def __init__(self, vmname, source_image):
        self.manage_ip = None
        self.subprocess = None
        self.vmname = vmname

        TNOSvm.image_id += 1
        self.image_name = TNOSvm.image + str(TNOSvm.image_id)
        image_path = source_image.split('/')
        self.image_name = self.image_name + '.' + image_path[-1].split('.')[-1]
        image_path[-1] = self.image_name
        image_path = '/'.join(image_path)

        self.image_name = image_path
        copyfile(source_image, image_path)
        LOG.debug("copy file :%s to %s" % (source_image, self.image_name))

        TNOSvm.tnosvm.append(self)

        LOG.debug("%s init" % self.vmname)

    @staticmethod
    def get(vmname):
        for vm in TNOSvm.tnosvm:
            if vm.vmname == vmname:
                return vm
        return None


    def start(self):
        '''create tnos vm'''
        LOG.info("%s start" % self.image_name)
        cmd = TNOSvm.kvm_cmd + self.image_name
        self.subprocess = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)

        time.sleep(15)
        for i in range(1024):
            message = self.subprocess.stdout.readline()
            if 'Username' in message:
                break

        if i+1 == 1024:
            self.state = VIRT_STATE_MAP[2]
            return False
        else:
            self.state = VIRT_STATE_MAP[0]
            return True


    def stop(self):
        try:
            os.kill(self.subprocess.pid+1, signal.SIGKILL)
            self.state = VIRT_STATE_MAP[1]
            LOG.info("%s stop" % self.vmname)
        except OSError, e:
            LOG.info("%s stop error" % self.vmname)

    def destroy(self):
        self.stop()
        os.remove(self.image_name)
        LOG.info("Destroy %s" % self.vmname)

        for vm in TNOSvm.tnosvm:
            if vm is self:
                TNOSvm.tnosvm.pop(vm)

    def is_running(self):
        return self.state

    def login(self, username='admin', passward='admin'):
        self.subprocess.stdin.write(username+'\n')
        self.subprocess.stdin.write(passward+'\n')

    def into_interface(self, intf_id):
        self.login()
        self.subprocess.stdin.write('end\n')
        self.subprocess.stdin.write('enable\n')
        self.subprocess.stdin.write('config\n')
        self.subprocess.stdin.write('interface ethernet'+ str(intf_id) + '\n')

    def config_intf_ip(self, intf_id, ip, mask):
        self.into_interface(intf_id)

        self.subprocess.stdin.write('zone trust \n')
        cmd = 'ip address '+ ip + ' ' + mask +'\n'
        self.subprocess.stdin.write(cmd)

    def enable_ping(self):
        self.into_interface(MANAGE_INTF_ID)
        self.subprocess.stdin.write('manage ping\n')

        #for debug
        self.into_interface(1)
        self.subprocess.stdin.write('zone trust \n')
        self.subprocess.stdin.write('manage ping\n')

        self.into_interface(2)
        self.subprocess.stdin.write('zone trust \n')
        cmd = 'ip address 90.1.1.1/24\n'
        self.subprocess.stdin.write(cmd)
        self.subprocess.stdin.write('manage ping\n')
        self.subprocess.stdin.write('manage telnet\n')

    def enable_http(self):
        self.into_interface(MANAGE_INTF_ID)
        self.subprocess.stdin.write('manage http\n')

    def enable_https(self):
        self.into_interface(MANAGE_INTF_ID)
        self.subprocess.stdin.write('manage https\n')

    def enable_telnet(self):
        self.into_interface(MANAGE_INTF_ID)
        self.subprocess.stdin.write('manage telnet\n')

    def display_config(self, line_num=1024):
        flag = True
        self.subprocess.stdin.write('show running-config\n')
        while line_num:
            line_num = line_num - 1
            message = self.subprocess.stdout.readline()
            if 'show running-config' in message:
                flag = True
            if flag:
                print message
                if '!' in message:
                    break


def main():
    tnos = TNOSvm('tnos1', '/home/xiongjun/work/tnos.qcow2')
    state = tnos.start()
    if not state:
        print("TNOS is not running")

    tnos.login()
    tnos.config_intf_ip(MANAGE_INTF_ID, '20.1.1.3', '255.255.255.0')
    tnos.display_config()

    #tnos.destroy()

if __name__ == "__main__":
    main()
