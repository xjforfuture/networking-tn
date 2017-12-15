"""
Supports KVM, LXC, QEMU, UML, and XEN.
"""

import errno
import eventlet
import functools
import glob
import mmap
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import uuid

from nova.virt import driver
 
class LibvirtDriver(driver.ComputeDriver):
    capabilities = {
        "has_imagecache": True,
        "supports_recreate": True,
        }

    def __init__(self, virtapi, read_only=False):
        super(LibvirtDriver, self).__init__(virtapi)
        global libvirt
        if libvirt is None:
            libvirt = __import__('libvirt')
        self._host_state = None
        self._initiator = None
        self._fc_wwnns = None
        self._fc_wwpns = None
        self._wrapped_conn = None
        self._wrapped_conn_lock = threading.Lock()
        self._caps = None
        self._vcpu_total = 0
        self.read_only = read_only
        self.firewall_driver = firewall.load_driver(
            DEFAULT_FIREWALL_DRIVER,
            self.virtapi,
            get_connection=self._get_connection)
        vif_class = importutils.import_class(CONF.libvirt.vif_driver)
        self.vif_driver = vif_class(self._get_connection)
        self.volume_drivers = driver.driver_dict_from_config(
            CONF.libvirt.volume_drivers, self)
        self.dev_filter = pci_whitelist.get_pci_devices_filter()
        self._event_queue = None
        self._disk_cachemode = None
        self.image_cache_manager = imagecache.ImageCacheManager()
        self.image_backend = imagebackend.Backend(CONF.use_cow_images)
        self.disk_cachemodes = {}
        self.valid_cachemodes = ["default",
                                 "none",
                                 "writethrough",
                                 "writeback",
                                 "directsync",
                                 "unsafe",
                                ]

        for mode_str in CONF.libvirt.disk_cachemodes:
            disk_type, sep, cache_mode = mode_str.partition('=')
            if cache_mode not in self.valid_cachemodes:
                LOG.warn(_('Invalid cachemode %(cache_mode)s specified '
                           'for disk type %(disk_type)s.'),
                         {'cache_mode': cache_mode, 'disk_type': disk_type})
                continue
            self.disk_cachemodes[disk_type] = cache_mode
        self._volume_api = volume.API()
  
    def _get_new_connection(self):
        # call with _wrapped_conn_lock held
        LOG.debug(('Connecting to libvirt: %s'), self.uri())
        wrapped_conn = None
        try:
            wrapped_conn = self._connect(self.uri(), self.read_only)
        finally:
            # Enabling the compute service, in case it was disabled
            # since the connection was successful.
            disable_reason = DISABLE_REASON_UNDEFINED
            if not wrapped_conn:
                disable_reason = 'Failed to connect to libvirt'
            self._set_host_enabled(bool(wrapped_conn), disable_reason)
        self._wrapped_conn = wrapped_conn
        try:
            LOG.debug(_("Registering for lifecycle events %s"), self)
            wrapped_conn.domainEventRegisterAny(
                None,
                libvirt.VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                self._event_lifecycle_callback,
                self)
        except Exception as e:
            LOG.warn(_("URI %(uri)s does not support events: %(error)s"),
                     {'uri': self.uri(), 'error': e})
        try:
            LOG.debug(_("Registering for connection events: %s") %
                      str(self))
            wrapped_conn.registerCloseCallback(self._close_callback, None)
        except (TypeError, AttributeError) as e:
            # NOTE: The registerCloseCallback of python-libvirt 1.0.1+
            # is defined with 3 arguments, and the above registerClose-
            # Callback succeeds. However, the one of python-libvirt 1.0.0
            # is defined with 4 arguments and TypeError happens here.
            # Then python-libvirt 0.9 does not define a method register-
            # CloseCallback.
            LOG.debug(_("The version of python-libvirt does not support "
                        "registerCloseCallback or is too old: %s"), e)
        except libvirt.libvirtError as e:
            LOG.warn(_("URI %(uri)s does not support connection"
                       " events: %(error)s"),
                     {'uri': self.uri(), 'error': e})
        return wrapped_conn

    @staticmethod
    def uri():
        if CONF.libvirt.virt_type == 'uml':
            uri = CONF.libvirt.connection_uri or 'uml:///system'
        elif CONF.libvirt.virt_type == 'xen':
            uri = CONF.libvirt.connection_uri or 'xen:///'
        elif CONF.libvirt.virt_type == 'lxc':
            uri = CONF.libvirt.connection_uri or 'lxc:///'
        else:
            uri = CONF.libvirt.connection_uri or 'qemu:///system'
        return uri

    @staticmethod
    def _connect(uri, read_only):
        def _connect_auth_cb(creds, opaque):
            if len(creds) == 0:
                return 0
            LOG.warning(
                _("Can not handle authentication request for %d credentials")
                % len(creds))
            raise exception.NovaException(
                _("Can not handle authentication request for %d credentials")
                % len(creds))
        auth = [[libvirt.VIR_CRED_AUTHNAME,
                 libvirt.VIR_CRED_ECHOPROMPT,
                 libvirt.VIR_CRED_REALM,
                 libvirt.VIR_CRED_PASSPHRASE,
                 libvirt.VIR_CRED_NOECHOPROMPT,
                 libvirt.VIR_CRED_EXTERNAL],
                _connect_auth_cb,
                None]
        try:
            flags = 0
            if read_only:
                flags = libvirt.VIR_CONNECT_RO
            # tpool.proxy_call creates a native thread. Due to limitations
            # with eventlet locking we cannot use the logging API inside
            # the called function.
            return tpool.proxy_call(
                (libvirt.virDomain, libvirt.virConnect),
                libvirt.openAuth, uri, auth, flags)
        except libvirt.libvirtError as ex:
            LOG.exception(_("Connection to libvirt failed: %s"), ex)
            payload = dict(ip=LibvirtDriver.get_host_ip_addr(),
                           method='_connect',
                           reason=ex)
            rpc.get_notifier('compute').error(nova_context.get_admin_context(),
                                              'compute.libvirt.error',
                                              payload)
            raise exception.HypervisorUnavailable(host=CONF.host)


    def get_num_instances(self):
        '''
                Efficient override of base instance_exists method.
        '''
        return self._conn.numOfDomains()


    def instance_exists(self, instance_name):
        """Efficient override of base instance_exists method."""
        try:
            self._lookup_by_name(instance_name)
            return True
        except exception.NovaException:
            return False

    # TODO(Shrews): Remove when libvirt Bugzilla bug # 836647 is fixed.
    def list_instance_ids(self):
        if self._conn.numOfDomains() == 0:
            return []
        return self._conn.listDomainsID()


    def list_instances(self):
        names = []
        for domain_id in self.list_instance_ids():
            try:
                # We skip domains with ID 0 (hypervisors).
                if domain_id != 0:
                    domain = self._lookup_by_id(domain_id)
                    names.append(domain.name())
            except exception.InstanceNotFound:
                # Ignore deleted instance while listing
                continue
        # extend instance list to contain also defined domains
        names.extend([vm for vm in self._conn.listDefinedDomains()
                    if vm not in names])
        return names

    def list_instance_uuids(self):
        uuids = set()
        for domain_id in self.list_instance_ids():
            try:
                # We skip domains with ID 0 (hypervisors).
                if domain_id != 0:
                    domain = self._lookup_by_id(domain_id)
                    uuids.add(domain.UUIDString())
            except exception.InstanceNotFound:
                # Ignore deleted instance while listing
                continue
        # extend instance list to contain also defined domains
        for domain_name in self._conn.listDefinedDomains():
            try:
                uuids.add(self._lookup_by_name(domain_name).UUIDString())
            except exception.InstanceNotFound:
                # Ignore deleted instance while listing
                continue
        return list(uuids)

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        for vif in network_info:
            self.vif_driver.plug(instance, vif)


    def unplug_vifs(self, instance, network_info, ignore_errors=False):
        """Unplug VIFs from networks."""
        for vif in network_info:
            try:
                self.vif_driver.unplug(instance, vif)
            except exception.NovaException:
                if not ignore_errors:
                    raise


    def _teardown_container(self, instance):
        inst_path = libvirt_utils.get_instance_path(instance)
        container_dir = os.path.join(inst_path, 'rootfs')
        container_root_device = instance.get('root_device_name')
        disk.teardown_container(container_dir, container_root_device)


    def _undefine_domain(self, instance):
        try:
            virt_dom = self._lookup_by_name(instance['name'])
        except exception.InstanceNotFound:
            virt_dom = None
        if virt_dom:
            try:
                try:
                    virt_dom.undefineFlags(
                        libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE)
                except libvirt.libvirtError:
                    LOG.debug(_("Error from libvirt during undefineFlags."
                        " Retrying with undefine"), instance=instance)
                    virt_dom.undefine()
                except AttributeError:
                    # NOTE(vish): Older versions of libvirt don't support
                    #             undefine flags, so attempt to do the
                    #             right thing.
                    try:
                        if virt_dom.hasManagedSaveImage(0):
                            virt_dom.managedSaveRemove(0)
                    except AttributeError:
                        pass
                    virt_dom.undefine()
            except libvirt.libvirtError as e:
                with excutils.save_and_reraise_exception():
                    errcode = e.get_error_code()
                    LOG.error(_('Error from libvirt during undefine. '
                                'Code=%(errcode)s Error=%(e)s') %
                              {'errcode': errcode, 'e': e}, instance=instance)


    def _cleanup_rbd(self, instance):
        pool = CONF.libvirt.images_rbd_pool
        volumes = libvirt_utils.list_rbd_volumes(pool)
        pattern = instance['uuid']
        def belongs_to_instance(disk):
            return disk.startswith(pattern)
        volumes = filter(belongs_to_instance, volumes)
        if volumes:
            libvirt_utils.remove_rbd_volumes(pool, *volumes)


    def _cleanup_lvm(self, instance):
        """Delete all LVM disks for given instance object."""
        disks = self._lvm_disks(instance)
        if disks:
            libvirt_utils.remove_logical_volumes(*disks)


    @staticmethod
    def _get_disk_xml(xml, device):
        """Returns the xml for the disk mounted at device."""
        try:
            doc = etree.fromstring(xml)
        except Exception:
            return None
        ret = doc.findall('./devices/disk')
        for node in ret:
            for child in node.getchildren():
                if child.tag == 'target':
                    if child.get('dev') == device:
                        return etree.tostring(node)


    def _get_existing_domain_xml(self, instance, network_info,
                                 block_device_info=None):
        try:
            virt_dom = self._lookup_by_name(instance['name'])
            xml = virt_dom.XMLDesc(0)
        except exception.InstanceNotFound:
            disk_info = blockinfo.get_disk_info(CONF.libvirt.virt_type,
                                                instance,
                                                block_device_info)
            xml = self.to_xml(nova_context.get_admin_context(),
                              instance, network_info, disk_info,
                              block_device_info=block_device_info)
        return xml