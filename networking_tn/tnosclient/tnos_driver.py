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
import sys

import neutron.plugins.ml2.models as ml2_db
from oslo_log import log as logging

if __name__ == '__main__':
    sys.path.append(r'/home/xiongjun/work/networking-tn/')
    LOG = logging.getLogger(None).logger
    # LOG.addHandler(streamlog)
    LOG.setLevel(logging.DEBUG)
else:
    LOG = logging.getLogger(__name__)

VIRT_STATE_MAP = {'running':'running',
                  'shutdown':'shutdown',
                  'crashed':'crashed'}

def vm_is_exist(id):
    cmd = 'sudo ps -ef'
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    proc.wait()

    msg = proc.stdout.read()
    msgs = msg.split('\n')
    for msg in msgs:
        if id in msg:
            return True

    return False


def stop_vm(id):
    try:
        cmd = 'sudo ps -ef'
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
        proc.wait()

        cmd = 'sudo kill'
        msg = proc.stdout.read()

        msgs = msg.split('\n')
        for msg in msgs:
            if id in msg:
                pid = msg.split()
                cmd = cmd+' '+pid[1]

        LOG.debug('exec cmd: %s', cmd)
        subprocess.call(cmd, shell=True)
    except OSError:
        LOG.info("stop vm error")


def destroy_vm(id, image_name):
    stop_vm(id)

    cmd = 'sudo rm ' + image_name
    subprocess.call(cmd, shell=True)
    LOG.debug("remove %s" % image_name)


class TNOSvm():
    '''
    kvm_cmd = 'sudo kvm -nographic ' \
                  + '-device e1000,netdev=eth0 -netdev tap,id=eth0,script=/opt/stack/tnos/nothing ' \
                  + '-device e1000,netdev=eth1 -netdev tap,id=eth1,script=/opt/stack/tnos/nothing ' \
                  + '-device e1000,netdev=eth2 -netdev tap,id=eth2,script=/opt/stack/tnos/nothing '
    '''

    kvm_cmd = 'sudo kvm -cpu Haswell -nographic -name %(id)s -net tap,ifname=%(tap0)s,script=no -net nic ' \
              +'-net tap,ifname=%(tap1)s,script=no -net nic ' \
              +'-net tap,ifname=%(tap2)s,script=no -net nic -m 1G %(image_path)s'

    image = 'tnos'

    def __init__(self, id, priv_id, source_image):
        self.id = id
        self.priv_id = priv_id
        self.state = VIRT_STATE_MAP['shutdown']
        self.shell_pid = None
        self.vm_pid = None

        self.image_name = TNOSvm.image + id
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

        cmd = TNOSvm.kvm_cmd % {'id':self.id, 'tap0':'tap0-'+self.priv_id, 'tap1':'tap1-'+self.priv_id,
                                'tap2':'tap2-'+self.priv_id, 'image_path':self.image_name}
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

            return self.image_name


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
    stop_vm('6af466de-926d-4338-ba4b-a9bd54430515')

if __name__ == '__main__':
    main()