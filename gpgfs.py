#!/usr/bin/env python

from fuse import FUSE, FuseOSError, Operations
import errno
import stat
import os
import sys
import logging
import struct
import time
from io import BytesIO
import gpgstore
from contextlib import contextmanager
from threading import Lock

magic = b'GPGFS1\n'

log = logging.getLogger('gpgfs')

class Entry:
    '''
    Filesystem object, either file or directory.
    '''
    def __init__(self, **kwargs):
        for k,v in kwargs.items():
            setattr(self, k, v)

def read_index(store, path):
    if not store.exists(path):
        now = time.time()
        root = Entry(children={}, nlink=3, size=0,
                     mode=stat.S_IFDIR | 0o755,
                     mtime=now, ctime=now)
        write_index(store, path, root)
        log.info('created %s', path)
        return root
    data = store.get(path, format=gpgstore.FMT_GPG)
    buf = BytesIO(data)
    temp = buf.read(len(magic))
    if temp != magic:
        raise IOError('index parse error: %s' % path)
    read_atom(buf)
    root = Entry(**read_dict(buf))
    return root

def write_index(store, path, root):
    buf = BytesIO()
    buf.write(magic)
    header = b''
    write_atom(buf, header)
    write_dict(buf, root)
    store.put(buf.getvalue(), path=path, format=gpgstore.FMT_GPG)

def write_dict(fd, dct):
    # breadth-first
    children = []
    buf = BytesIO()
    if not isinstance(dct, dict):
        dct = dct.__dict__
    for key in dct:
        write_atom(buf, key.encode('utf-8'))
        val = dct[key]
        if isinstance(val, dict):
            buf.write(b'D')
            children.append(val)
        elif isinstance(val, Entry):
            buf.write(b'E')
            children.append(val)
        elif isinstance(val, (int)):
            if val < 2**32:
                buf.write(b'I')
                buf.write(struct.pack('<I', val))
            else:
                buf.write(b'L')
                buf.write(struct.pack('<Q', val))
        elif isinstance(val, float):
            buf.write(b'F')
            buf.write(struct.pack('<d', val))
        elif isinstance(val, bytes):
            buf.write(b'')
            write_atom(buf, val)
        elif isinstance(val, str):
            buf.write(b'S')
            write_atom(buf, val.encode('utf-8'))
        else:
            raise TypeError(type(val))
    write_atom(fd, buf.getvalue())
    for c in children:
        write_dict(fd, c)

def read_dict(fd):
    dct = {}
    buf = read_atom(fd)
    buflen = len(buf)
    buf = BytesIO(buf)
    while buf.tell() < buflen:
        key = read_atom(buf).decode('utf-8')
        tag = buf.read(1)
        if tag == b'D':    val = read_dict(fd)
        elif tag == b'E':  val = Entry(**read_dict(fd))
        elif tag == b'I':  val = struct.unpack('<I', buf.read(4))[0]
        elif tag == b'L':  val = struct.unpack('<Q', buf.read(8))[0]
        elif tag == b'F':  val = struct.unpack('<d', buf.read(8))[0]
        elif tag == b'':  val = read_atom(buf)
        elif tag == b'S':  val = read_atom(buf).decode('utf-8')
        else:             raise TypeError(tag)
        dct[key] = val
    return dct

def write_atom(fd, atom):
    assert isinstance(atom, bytes)
    fd.write(struct.pack('<I', len(atom)))
    fd.write(atom)

def read_atom(fd):
    return fd.read(struct.unpack('<I', fd.read(4))[0])

class LoggingMixIn:

    def __call__(self, op, path, *args):
        if op=='write':
            atxt = ' '.join([repr(args[0])[:10], repr(args[1]), repr(args[2])])
        else:
            atxt = ' '.join(map(repr, args))
        log.debug('-> %s %s %s', op, repr(path), atxt)
        ret = '[Unhandled Exception]'
        try:
            ret = getattr(self, op)(path, *args)
            return ret
        except OSError as e:
            ret = str(e)
            raise
        except:
            log.exception('unhandled error in %s:', op)
            raise
        finally:
            rtxt = repr(ret)
            if op=='read':
                rtxt = rtxt[:10]
            log.debug('<- %s %s', op, rtxt)

class GpgFs(LoggingMixIn, Operations):
#class GpgFs(Operations):

    def __init__(self, encroot, keyid):
        '''
        :param encroot: Encrypted root directory
        '''
        self.encroot = encroot.rstrip('/')
        assert os.path.exists(self.encroot)
        assert os.path.isdir(self.encroot)
        #self.cache = cache
        self.store = gpgstore.GpgStore(self.encroot, keyid)
        self.index_path = 'index'
        self.root = read_index(self.store, self.index_path)
        self.txlock = Lock()
        self.fd = 0
        self._clear_write_cache()

    def _find(self, path, parent=False):
        assert path.startswith('/')
        if path == '/':
            return self.root
        node = self.root
        path = path[1:].split('/')
        if parent:
            basename = path[-1]
            path = path[:-1]
        for name in path:
            if name not in node.children:
                raise FuseOSError(errno.ENOENT)
            node = node.children[name]
        if parent:
            return node, basename
        return node

    def _clear_write_cache(self):
        self.write_path = None
        self.write_buf = []
        self.write_len = 0
        self.write_dirty = False

    @contextmanager
    def transaction(self):
        paths = {'old': None, 'new': None}
        def putx(data, old_path = None):
            paths['new'] = self.store.put(data)
            paths['old'] = old_path
            return paths['new']
        with self.txlock:
            try:
                yield putx
                # commit
                write_index(self.store, self.index_path, self.root)
            except:
                # rollback
                try:
                    log.warning('starting rollback')
                    self.root = read_index(self.store, self.index_path)
                    if paths['new']:
                        self.store.delete(paths['new'])
                    log.warning('rollback done')
                except:
                    log.exception('rollback failed')
                raise
            if paths['old']:
                self.store.delete(paths['old'])

    def chmod(self, path, mode):
        # sanitize mode (clear setuid/gid/sticky bits)
        mode &= 0o777
        with self.transaction():
            ent = self._find(path)
            ent.mode = mode | (ent.mode & 0o170000)

    def chown(self, path, uid, gid):
        raise FuseOSError(errno.ENOSYS)

    def create(self, path, mode):
        mode &= 0o777
        mode |= stat.S_IFREG
        with self.transaction() as putx:
            parent, name = self._find(path, parent=True)
            if name in parent.children:
                raise FuseOSError(errno.EEXIST)
            now = time.time()
            encpath = putx('')
            parent.children[name] = Entry(mode=mode, encpath=encpath, size=0,
                                          nlink=1, ctime=now, mtime=now,
                                          encformat=gpgstore.FMT_GPG)
            parent.mtime = now
            log.debug('new path %s => %s', path, encpath)
            self.fd += 1
            return self.fd

    def flush(self, path, fh):
        if not self.write_dirty:
            log.debug('nothing to flush')
            return 0
        with self.transaction() as putx:
            buf = b''.join(self.write_buf)
            self.write_buf = [buf]
            ent = self._find(self.write_path)
            ent.size = len(buf)
            ent.encpath = putx(buf, ent.encpath)
            self.write_dirty = False
            log.debug('flushed %d bytes to %s', len(buf), self.write_path)
            return 0

    def fsync(self, path, datasync, fh):
        self.flush(path, fh)
        return 0

    def getattr(self, path, fh = None):
        # don't do full blown transaction
        with self.txlock:
            ent = self._find(path)
            return dict(st_mode = ent.mode, st_size = ent.size,
                        st_ctime = ent.ctime, st_mtime = ent.mtime,
                        st_atime = 0, st_nlink = ent.nlink)

    def getxattr(self, path, name, position = 0):
        raise FuseOSError(errno.ENODATA) # ENOATTR

    def listxattr(self, path):
        return []

    def mkdir(self, path, mode):
        mode &= 0o777
        mode |= stat.S_IFDIR
        with self.transaction():
            parent, name = self._find(path, parent=True)
            if name in parent.children:
                raise FuseOSError(errno.EEXIST)
            now = time.time()
            parent.children[name] = Entry(children={}, mode=mode, nlink=2,
                                          size=0, mtime=now, ctime=now)
            parent.mtime = now

    def open(self, path, flags):
        return 0

    def read(self, path, size, offset, fh):
        self.flush(path, 0)
        ent = self._find(path)
        assert ent.mode & stat.S_IFREG
        data = self.store.get(ent.encpath, format=ent.encformat)
        return data[offset:offset + size]

    def readdir(self, path, fh):
        dirent = self._find(path)
        return ['.', '..'] + list(dirent.children)

    def readlink(self, path):
        raise FuseOSError(errno.ENOSYS)

    def removexattr(self, path, name):
        raise FuseOSError(errno.ENOSYS)

    def rename(self, old, new):
        self.flush(old, 0)
        self._clear_write_cache()
        if new.startswith(old):
            raise FuseOSError(errno.EINVAL)
        with self.transaction():
            old_dir, old_name = self._find(old, parent=True)
            if old_name not in old_dir.children:
                raise FuseOSError(errno.ENOENT)
            new_dir, new_name = self._find(new, parent=True)
            old_ent = old_dir.children[old_name]
            new_ent = new_dir.children.get(new_name)
            if new_ent:
                if new_ent.mode & stat.S_IFDIR:
                    if not old_ent.mode & stat.S_IFDIR:
                        raise FuseOSError(errno.EISDIR)
                    if new_ent.children:
                        raise FuseOSError(errno.ENOTEMPTY)
                elif old_ent.mode & stat.S_IFDIR:
                    raise FuseOSError(errno.ENOTDIR)
            new_dir.children[new_name] = old_dir.children.pop(old_name)
            old_dir.mtime = new_dir.mtime = time.time()
        if new_ent != None and new_ent.mode & stat.S_IFREG:
            self.store.delete(new_ent.encpath)

    def rmdir(self, path):
        with self.transaction():
            parent, name = self._find(path, parent=True)
            if name not in parent.children:
                raise FuseOSError(errno.ENOENT)
            ent = parent.children[name]
            if not ent.mode & stat.S_IFDIR:
                raise FuseOSError(errno.ENOTDIR)
            if ent.children:
                raise FuseOSError(errno.ENOTEMPTY)
            del parent.children[name]
            parent.mtime = time.time()

    def setxattr(self, path, name, value, options, position = 0):
        raise FuseOSError(errno.ENOSYS)

    def statfs(self, path):
        raise FuseOSError(errno.ENOSYS)

    def symlink(self, target, source):
        raise FuseOSError(errno.ENOSYS)

    def truncate(self, path, length, fh = None):
        self.flush(path, 0)
        self._clear_write_cache()
        with self.transaction() as putx:
            ent = self._find(path)
            if length == 0:
                buf = b''
            else:
                buf = self.store.get(ent.encpath, format=ent.encformat)
                buf = buf[:length]
            ent.encpath = putx(buf, ent.encpath)
            ent.size = length

    def unlink(self, path):
        with self.transaction():
            if self.write_path == path:
                # no need to flush afterwards
                self._clear_write_cache()
            parent, name = self._find(path, parent=True)
            if name not in parent.children:
                raise FuseOSError(errno.ENOENT)
            ent = parent.children.pop(name)
            parent.mtime = time.time()
        self.store.delete(ent.encpath)

    def utimens(self, path, times = None):
        if times is None:
            mtime = time.time()
        else:
            mtime = times[1]
        with self.transaction():
            ent = self._find(path)
            ent.mtime = mtime

    def write(self, path, data, offset, fh):
        if path != self.write_path:
            self.flush(self.write_path, None)
            ent = self._find(path)
            buf = self.store.get(ent.encpath, format=ent.encformat)
            self.write_buf = [buf]
            self.write_len = len(buf)
        self.write_path = path
        if offset == self.write_len:
            self.write_buf.append(data)
            self.write_len += len(data)
        else:
            buf = b''.join(self.write_buf)
            buf = buf[:offset] + data + buf[offset + len(data):]
            self.write_buf = [buf]
            self.write_len = len(buf)
        self.write_dirty = True
        return len(data)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.stderr.write('Usage: gpgfs <gpg_keyid> <encrypted_root> <mountpoint>\n')
        sys.exit(1)
    logpath = os.path.join(os.path.dirname(__file__), 'gpgfs.log')
    log.addHandler(logging.FileHandler(logpath, 'w'))
    log.setLevel(logging.DEBUG)
    fs = GpgFs(sys.argv[2], sys.argv[1])
    FUSE(fs, sys.argv[3], foreground=True)
