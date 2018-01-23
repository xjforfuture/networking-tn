import shelve

from oslo_log import log as logging

LOG = logging.getLogger(__name__)

TN_ROUTER_DB_NAME = '/opt/stack/tnos/tn_router_db'


def tn_db_lock(fd):
    #fcntl.flock(fd, fcntl.LOCK_EX)
    pass

def tn_db_unlock(fd):
    #fcntl.flock(fd, fcntl.lock_un)
    pass

def tn_db_add(key, obj):
    tn_db = shelve.open(TN_ROUTER_DB_NAME)

    tn_db_lock(tn_db)
    tn_db[key] = obj
    tn_db_unlock(tn_db)
    tn_db.close()


def tn_db_modify(key, obj):
    tn_db_add(key, obj)

def tn_db_get(key=None):
    tn_db = shelve.open(TN_ROUTER_DB_NAME)
    if key == None:
        return tn_db

    tn_db_lock(tn_db)
    try:
        obj = tn_db[key]
    except:
        obj = None
    finally:
        tn_db.close()
        tn_db_unlock(tn_db)

    return obj

def tn_db_del(key):

    tn_db = shelve.open(TN_ROUTER_DB_NAME)
    try:
        del tn_db[key]
    finally:
        tn_db.close()
