# Copyright 2018 Tsinghuanet, Inc.
# All rights reserved.
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


"""Tsinghuanet specific database schema/model."""

import copy
from neutron_lib.db import model_base
from oslo_db import exception as os_db_exception
import six
import sqlalchemy as sa
from sqlalchemy.inspection import inspect
from sqlalchemy import orm

from networking_tn.common import constants as const


OPS = ["ADD", "UPDATE", "DELETE", "QUERY"]


def add_record(context, cls, **kwargs):
    try:
        return cls.add_record(context, **kwargs)
    except os_db_exception.DBDuplicateEntry:
        pass
    return {}


def delete_record(context, cls, **kwargs):
    return cls.delete_record(context, kwargs)


def update_record(context, record, **kwargs):
    session = get_session(context)
    try:
        for key, value in six.iteritems(kwargs):
            if getattr(record, key, None) != value:
                setattr(record, key, value)
        with session.begin(subtransactions=True):
            session.add(record)
            return record
    except Exception as e:
        raise os_db_exception.DBError(e)


def query_record(context, cls, **kwargs):
    return db_query(cls, context, **kwargs).first()


def query_records(context, cls, **kwargs):
    return db_query(cls, context, **kwargs).all()


def query_count(context, cls, **kwargs):
    return db_query(cls, context, **kwargs).count()


def get_session(context):
    return context.session if getattr(context, 'session', None) else context


def primary_keys(cls):
    """
    :param cls: Object or instance derived from the class ModelBase
                in the library sqlalchemy
    :return: list of primary keys
    """
    if not isinstance(cls, type):
        cls = cls.__class__
    return [key.name for key in inspect(cls).primary_key]


def db_query(cls, context, lockmode=False, **kwargs):
    """
    :param cls:
    :param context:
    :param kwargs:
    :return:
    """
    session = get_session(context)
    query = session.query(cls)
    if lockmode:
        query = query.with_lockmode('update')
    for key, value in six.iteritems(kwargs):
        kw = {key: value}
        query = query.filter_by(**kw)
    return query


class DBbase(object):
    @classmethod
    def init_records(cls, context, **kwargs):
        """Add records to be allocated into the table."""
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query_one(context, **kwargs)
            if not record:
                record = cls()
                for key, value in six.iteritems(kwargs):
                    if hasattr(record, key):
                        setattr(record, key, value)
                session.add(record)

    @classmethod
    def add_record(cls, context, **kwargs):
        """Add vlanid to be allocated into the table."""
        session = get_session(context)
        _kwargs = copy.copy(kwargs)
        for key in _kwargs:
            if not hasattr(cls, key):
                kwargs.pop(key, None)
        with session.begin(subtransactions=True):
            record = cls.query_one(context, **kwargs)
            if not record:
                record = cls()
                for key, value in six.iteritems(kwargs):
                    setattr(record, key, value)
                session.add(record)
                rollback = cls._prepare_rollback(context,
                                                 cls.delete_record,
                                                 **kwargs)
            else:
                rollback = {}
                #raise os_db_exception.DBDuplicateEntry
        ## TODO(samsu): kwargs would be better if only include class cls
        ## related primary keys
        #return {'result': record, 'rollback': rollback}
        return record

    @staticmethod
    def update_record(context, record, **kwargs):
        """Add vlanid to be allocated into the table."""
        return update_record(context, record, **kwargs)

    @classmethod
    def delete_record(cls, context, kwargs):
        """
        Notes: kwargs is a dictionary as a variable, no wrapped as
        **kwargs because of the requirements of rollback process.
        Delete the record with the value of kwargs from the database,
        kwargs is a dictionary variable, here should not pass into a
        variable like **kwargs
        """
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query_one(context, lockmode=True, **kwargs)
            if record:
                session.delete(record)
        return record

    @classmethod
    def query_one(cls, context, lockmode=False, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        query = db_query(cls, context, lockmode=lockmode, **kwargs)
        return query.first()

    @classmethod
    def query_all(cls, context, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        query = db_query(cls, context, **kwargs)
        return query.all()

    @classmethod
    def query_count(cls, context, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        query = db_query(cls, context, **kwargs)
        return query.count()

    @classmethod
    def query_like(cls, context, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        session = get_session(context)
        query = session.query(cls)
        for key, value in six.iteritems(kwargs):
            if getattr(cls, key, None):
                query = query.filter(getattr(cls, key, None).like(value))
        return query.all()

    @staticmethod
    def _prepare_rollback(context, func, **kwargs):
        if not func:
            raise ValueError
        rollback = {
            'func': func,
            'params': (context, kwargs)
        }
        return rollback

class Tn_Router(model_base.BASEV2, DBbase):
    """Schema for tn network."""
    id = sa.Column(sa.String(64), primary_key=True)
    priv_id = sa.Column(sa.String(32))
    tenant_id = sa.Column(sa.String(64))
    name = sa.Column(sa.String(64))
    manage_ip = sa.Column(sa.String(32))
    image_name = sa.Column(sa.String(128))
    snat_inner_use = sa.Column(sa.String(128))

class Tn_Interface(model_base.BASEV2, DBbase):
    """Schema for tn network."""
    id = sa.Column(sa.String(64), primary_key=True)
    router_id = sa.Column(sa.String(64))
    inner_id = sa.Column(sa.Integer)
    extern_name = sa.Column(sa.String(64))
    inner_name = sa.Column(sa.String(32))
    state = sa.Column(sa.String(16), default='down')
    type = sa.Column(sa.String(16))
    mac = sa.Column(sa.String(32))
    vlan_id = sa.Column(sa.Integer)
    ip_prefix = sa.Column(sa.String(32))
    is_manage = sa.Column(sa.String(16), default='False')
    is_gw = sa.Column(sa.String(16), default='False')
    is_sub = sa.Column(sa.String(16), default='False')

class Tn_Static_Route(model_base.BASEV2, DBbase):
    """Schema for tn network."""
    router_id = sa.Column(sa.String(64), primary_key=True)
    dest = sa.Column(sa.String(32))
    prefix = sa.Column(sa.String(32))
    next_hop = sa.Column(sa.String(32))

class Tn_Address(model_base.BASEV2, DBbase):
    """Schema for tn network."""
    rule_id = sa.Column(sa.String(64), primary_key=True)
    name = sa.Column(sa.String(64), primary_key=True)
    ip_prefix = sa.Column(sa.String(32))

class Tn_Service(model_base.BASEV2, DBbase):
    """Schema for tn network."""
    rule_id = sa.Column(sa.String(64), primary_key=True)
    name = sa.Column(sa.String(64))
    protocol = sa.Column(sa.String(16))
    src_port_min = sa.Column(sa.Integer)
    src_port_max = sa.Column(sa.Integer)
    dst_port_min = sa.Column(sa.Integer)
    dst_port_max = sa.Column(sa.Integer)


class Tn_Snat_rule(model_base.BASEV2, DBbase):
    """Schema for tn network."""
    router_id = sa.Column(sa.String(64), primary_key=True)
    inner_id = sa.Column(sa.Integer, primary_key=True)
    srcaddr = sa.Column(sa.String(32))
    dstaddr = sa.Column(sa.String(32))
    trans_addr = sa.Column(sa.String(32))
    srcaddr_name = sa.Column(sa.String(32))
    dstaddr_name = sa.Column(sa.String(32))
    trans_addr_name = sa.Column(sa.String(32))
    trans =sa.Column(sa.String(16))

class Tn_Rule(model_base.BASEV2, DBbase):
    """Schema for tn network."""
    id = sa.Column(sa.String(64), primary_key=True)
    policy_id = sa.Column(sa.String(64))
    inner_id = sa.Column(sa.Integer)
    name = sa.Column(sa.String(32))
    desc = sa.Column(sa.String(32))
    protocol = sa.Column(sa.String(16))
    action = sa.Column(sa.String(16))
    enable = sa.Column(sa.String(16))
    srcaddr = sa.Column(sa.String(64), default='Any')
    dstaddr = sa.Column(sa.String(64), default='Any')
    service = sa.Column(sa.String(64), default='Any')

class Tn_Policy(model_base.BASEV2, DBbase):
    """Schema for tn network."""
    id = sa.Column(sa.String(64), primary_key=True)
    name = sa.Column(sa.String(32))
    desc = sa.Column(sa.String(32))
    rule_inner_use = sa.Column(sa.String(1024))
    reference_count = sa.Column(sa.Integer)

class Tn_Firewall(model_base.BASEV2, DBbase):
    """Schema for tn network."""
    id = sa.Column(sa.String(64), primary_key=True)
    name = sa.Column(sa.String(32))
    desc = sa.Column(sa.String(32))
    policy_id = sa.Column(sa.String(64))
    router_ids = sa.Column(sa.String(1024))
