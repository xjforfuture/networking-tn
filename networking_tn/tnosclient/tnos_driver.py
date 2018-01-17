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

import subprocess
import shutil

from oslo_log import log as logging

LOG = logging.getLogger(__name__)

VIRT_STATE_MAP = {'running':'running',
                  'shutdown':'shutdown',
                  'crashed':'crashed'}

class TNOSvm():
    '''
    kvm_cmd = 'sudo kvm -nographic ' \
                  + '-device e1000,netdev=eth0 -netdev tap,id=eth0,script=/opt/stack/tnos/nothing ' \
                  + '-device e1000,netdev=eth1 -netdev tap,id=eth1,script=/opt/stack/tnos/nothing ' \
                  + '-device e1000,netdev=eth2 -netdev tap,id=eth2,script=/opt/stack/tnos/nothing '
    '''

    kvm_cmd = 'sudo kvm -nographic -net tap,ifname=%(tap0)s,script=no -net nic ' \
              +'-net tap,ifname=%(tap1)s,script=no -net nic ' \
              +'-net tap,ifname=%(tap2)s,script=no -net nic %(image_path)s'

    image = 'tnos'

    def __init__(self, vmname, source_image):
        self.vmname = vmname
        self.state = VIRT_STATE_MAP['shutdown']
        self.shell_pid = None
        self.vm_pid = None

        self.image_name = TNOSvm.image + vmname
        image_path = source_image.split('/')
        self.image_name = self.image_name + '.' + image_path[-1].split('.')[-1]
        image_path[-1] = self.image_name
        image_path = '/'.join(image_path)

        self.image_name = image_path
        LOG.debug("copy file :%s to %s" % (source_image, self.image_name))
        shutil.copy(source_image, image_path)
        #cmd = 'sudo cp ' + source_image + ' ' + image_path
        #subprocess.call(cmd, shell=True)


    def start(self, manage_intf, manage_ip):
        '''create tnos vm'''

        cmd = TNOSvm.kvm_cmd % {'tap0':'tap0-'+self.vmname, 'tap1':'tap1-'+self.vmname,
                                'tap2':'tap2-'+self.vmname, 'image_path':self.image_name}
        LOG.debug(cmd)
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)

        for i in range(1024):
            message = proc.stdout.readline()
            if 'Username' in message:
                break

        if i+1 == 1024:
            self.state = VIRT_STATE_MAP['crashed']

        else:
            self.state = VIRT_STATE_MAP['running']
            self.shell_pid = proc.pid + 1
            self.vm_pid = proc.pid + 2

            self.config_intf_ip(proc, manage_intf, manage_ip, '255.255.255.0')
            self.enable_http(proc, manage_intf)
            self.enable_https(proc, manage_intf)
            self.enable_ping(proc, manage_intf)
            self.enable_telnet(proc, manage_intf)

    def stop(self):
        try:
            cmd = 'sudo kill ' + str(self.vm_pid)
            #cmd = 'sudo killall qemu-system-x86_64'
            LOG.debug("exec cmd: %s" % cmd)
            subprocess.call(cmd, shell=True)

            cmd = 'sudo kill ' + str(self.shell_pid)

            LOG.debug("exec cmd: %s" % cmd)
            subprocess.call(cmd, shell=True)

            #os.kill(self.subprocess.pid+1, signal.SIGKILL)
            self.state = VIRT_STATE_MAP['shutdown']

        except OSError, e:
            LOG.info("%s stop error" % self.vmname)

    def destroy(self):
        if self.is_running():
            self.stop()

        cmd = 'sudo rm ' + self.image_name
        subprocess.call(cmd, shell=True)
        LOG.debug("Destroy %s" % self.vmname)

    def is_running(self):
        if self.state == VIRT_STATE_MAP['running']:
            return True
        else:
            return False

    def login(self, subprocess, username='admin', passward='admin'):
        subprocess.stdin.write(username+'\n')
        subprocess.stdin.write(passward+'\n')

    def into_interface(self, subprocess, intf_id):
        self.login(subprocess)
        subprocess.stdin.write('end\n')
        subprocess.stdin.write('enable\n')
        subprocess.stdin.write('config\n')
        subprocess.stdin.write('interface ethernet'+ str(intf_id) + '\n')

    def config_intf_ip(self, subprocess, intf_id, ip, mask):
        self.into_interface(subprocess, intf_id)

        subprocess.stdin.write('zone trust \n')
        cmd = 'ip address '+ ip + ' ' + mask +'\n'
        subprocess.stdin.write(cmd)

    def enable_ping(self, subprocess, intf_id):
        self.into_interface(subprocess, intf_id)
        subprocess.stdin.write('manage ping\n')

    def enable_http(self, subprocess, intf_id):
        self.into_interface(subprocess, intf_id)
        subprocess.stdin.write('manage http\n')

    def enable_https(self, subprocess, intf_id):
        self.into_interface(subprocess, intf_id)
        subprocess.stdin.write('manage https\n')

    def enable_telnet(self, subprocess, intf_id):
        self.into_interface(subprocess, intf_id)
        subprocess.stdin.write('manage telnet\n')

    def display_config(self, subprocess, line_num=1024):
        flag = True
        subprocess.stdin.write('show running-config\n')
        while line_num:
            line_num = line_num - 1
            message = subprocess.stdout.readline()
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
    tnos.config_intf_ip(0, '20.1.1.3', '255.255.255.0')
    tnos.display_config()

    #tnos.destroy()

if __name__ == "__main__":
    main()
