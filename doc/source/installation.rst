=========================================
Tsinghuanet plugin for OpenStack Neutron
=========================================

1. General
----------

This is an installation guide for enabling Tsinghuanet support on OpenStack.

This guide does not necessarily cover all OpenStack installation steps especially
at production scale.

Please note this instruction only applies to liberty or master version of OpenStack.


2. Prerequisites
----------------
The prerequisites for installing Tsinghuanet pluggin for OpenStack are the
following:

    1. at least 3 machines, physical or vm, with at least 2 core cpu and 4G
       ram, including 1 controller, 1 compute, 1 tsinghuanet.

    2. Controller and compute nodes are installed with Ubuntu 14.04 or CentOS7.

    3. Tsinghuanet is 5.2.3 GA version and up til 5.6. Clean configuration with only control IP.

    4. 3 virtual switches(ESXI vswitch or linux bridge) or physical switches/vlans:
       1 for control plane, 1 for tenant network, 1 for external network. Vlanids are
       allowed on the switches and enable promisc mode. http and https access are allowed
       on Tsinghuanet’s control interface.

    5. Controller has at least 1 nic on control plane with Internet access.

    6. Compute node has at least 2 nics, one on control plane and the other on tenant
       network.

    7. Tsinghuanet has at least 3 nics, 1 for control plane, 1 for tenant network and 1 for
       external. There should be NO references on the ports for tenant and external network.
       Backup the clean configuration of Tsinghuanet to local machine for later restoration.

3. OpenStack+Tsinghuanet plugin Installation
---------------------------------------------

:3.1 Using devstack:

In this scenario, Tsinghuanet plugin will be installed along with OpenStack using devstack

    1. ssh to controller node with sudo privilege and install git.

    2. git clone https://git.openstack.org/openstack-dev/devstack

    3. git clone https://git.openstack.org/openstack/networking-tn

    4. cd devstack; sudo tools/create-stack-user.sh if you don’t have a stack user with sudo privilege.

    5. Use ``networking-tn/devstack/local.conf.example.controller`` and ``networking-tn/devstack/local.conf.example.compute`` as and example to create local.conf for control and compute nodes or use ``networking-tn/devstack/local.conf.example.aio`` for all-in-one node and set the required parameters in the local.conf based on the your setup. Items that need to be changed is decorated with CHANGEME.

    6. Run ./stack.sh on controller first and then compute. Remember to get Tsinghuanet ready before running stack.sh.
        

:3.2 On a setup with OpenStack already installed:

In this scenario, Tsinghuanet pluggin will be installed on a setup which has already OpenStack installed:

On the controller node:

1. pip install git+git://git.openstack.org/openstack/networking-tn

2. The following modifications are needed in:

  ::

    2.1 /etc/neutron/plugins/ml2/ml2_conf.ini

    [[ml2_tn]
    vm_image_path = /opt/stack/tnos/tnos.qcow2
    password = admin
    username = admin
    protocol = http
    port = 80
    address = 99.1.0.1

    2.2 neutron.conf:

    [DEFAULT]
    service_plugins = tn_router,tn_firewall ## If tsinghuanet is used to provide fwaas, add tn_firewall here.

4. neutron-db-manage --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini upgrade head

5. restart neutron server service. service neutron-server restart or systemctl restart neutron-server

6. If you don't have existing configuration, you are done here, but if not, you have existing configuration including networks, subnets, routers, ports and VMs based on tenant network of VLAN type and you want to preserve them, run::

   $ tn_migration

7. After the migration, shutdown network node completely if you have a seperate network node. If network node(L3 agent, DHCP agent, Metadata agent) co-exists with controller or compute node, disable L3,DHCP,Metadata agent services and reboot the node.
