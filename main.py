#!/bin/env python3

import sys
import os
import subprocess
from subprocess import PIPE, TimeoutExpired
from unshare import unshare, CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWPID
import ctypes
import ctypes.util
import os

from urllib.parse import urlparse
import requests
import shutil


import logging

# ------------
# -- CONFig --

# MNT_DIR = "alpine-minirootfs"



# -------------
# -- LOGGING --


class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"  # (%(filename)s:%(lineno)d)

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


# create logger with 'spam_application'
logger = logging.getLogger("PyContainer")
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

ch.setFormatter(CustomFormatter())

logger.addHandler(ch)


# -----------------
# -- FILE SYSTEM --

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
# libc.mount.argtypes = (
#     ctypes.c_char_p,
#     ctypes.c_char_p,
#     ctypes.c_char_p,
#     ctypes.c_ulong,
#     ctypes.c_char_p,
# )

libc.syscall.argtypes = [ctypes.c_int, ctypes.c_int]
libc.umount.argtypes = [ctypes.c_char_p, ctypes.c_int]
libc.mount.argtypes = [
    ctypes.c_char_p,  # source
    ctypes.c_char_p,  # target
    ctypes.c_char_p,  # filesystem_type
    ctypes.c_ulong,  # mount_flags
    ctypes.c_void_p,
]  # data

SYS_unshare = 272  # from asm/unistd_64.h
CLONE_NEWNS = 0x20000  # from linux/sched.h

MS_RDONLY = 1
MS_REMOUNT = 32
MS_BIND = 4096  # from linux/fs.h
MS_REC = 16384  # from linux/fs.h
MS_PRIVATE = 1 << 18

MNT_DETACH = 2  # from sys/mount.h


def sethostname(hostname):
    ret = libc.sethostname(
        hostname.encode(), len(hostname)
    )
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(
            errno,
            f"Error setting hostname {hostname}: {os.strerror(errno)}",
        )

def mount(source, target, fs, flags=0, options=""):
    ret = libc.mount(
        source.encode(), target.encode(), fs.encode(), flags, options.encode()
    )
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(
            errno,
            f"Error mounting {source} ({fs}) on {target} with options '{options}': {os.strerror(errno)}",
        )


def umount(source):
    ret = libc.umount2(source.encode(), MNT_DETACH)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(
            errno,
            f"Error unmounting {source}: {os.strerror(errno)}",
        )


def pivot_root(new_root, old_root):
    ret = libc.pivot_root(new_root, old_root)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(
            errno,
            f"Error pivotting root. Pivot to {new_root}, placing old root at {old_root}: {os.strerror(errno)}",
        )

def unsharenamespaces():
    """
    Use Linux namespaces to add the current process to a new UTS (hostname) namespace, new
    mount namespace and new PID namespace.
    """
    unshare(CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS)
    sethostname("alpine-container")
    mount("none", "/", "", MS_REC | MS_PRIVATE) # Not sure why we need this

def pivot_root_routine(mnt_dir):
    OLD_ROOT = "./oldroot"

    # Setup the filesystem
    mount(mnt_dir, mnt_dir, "", MS_BIND | MS_REC | MS_PRIVATE)
    os.chdir(mnt_dir)
    try:
        os.mkdir(OLD_ROOT, mode=755)
    except FileExistsError as e:
        pass
    print("[I] Pivot setup ok")
    pivot_root(".", OLD_ROOT)
    os.chdir("/")
    # umount(OLD_ROOT)
    # os.rmdir(OLD_ROOT)

def mount_proc():
    try:
        os.mkdir("/proc", 755)
    except FileExistsError as e:
        pass
    mount("proc", "/proc", "proc", 0)

cache_dir = '.cache'
volume_dir = '.volumes'

def setup_container_volume(def_file):
    c_name = def_file.split('.')[0]
    with open(def_file, 'r') as f:
        lines = f.readlines()
        if (lines[0][:4] != 'FROM'):
            print('First line should specify source url: FROM https://.../myimage.tar.gz', file=sys.stderr)
        img_source_url = lines[0][5:]
        o = urlparse(img_source_url)
        img_name = o.path.rsplit('/', 1)[1]
        img_source_archive_path = cache_dir + '/' + img_name
        img_source_path = cache_dir + '/' + img_name + "-source"
        
        # Download image if not exists
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

        if not os.path.exists(img_source_archive_path):
            print(f"Downloading image: {img_name}")
            r = requests.get(o.geturl(), allow_redirects=True)
            open(img_source_archive_path, 'wb').write(r.content)
        else:
            print(f"Using cached image archive: {img_source_archive_path}")

        # if not os.path.exists(img_source_path):
        #     print(f"Extracting image source")
        #     shutil.unpack_archive(img_source_archive_path, img_source_path)
        # else:
        #     print(f"Using cached image source: {img_source_path}")

        # Setup volume
        if not os.path.exists(volume_dir):
            os.makedirs(volume_dir)
        c_volume_path = volume_dir + '/' + c_name
        if not os.path.exists(c_volume_path):
            print(f"Extracting image to new volume: {c_volume_path}")
            shutil.unpack_archive(img_source_archive_path, c_volume_path)
            # shutil.copytree(img_source_path, c_volume_path)
        else:
            print(f"Existing volume found: {c_volume_path}")

        return c_volume_path

def read_build_file(def_file):
    with open(def_file, 'r') as f:
        return f.readlines()

def build_container(volume_dir, def_file_content):
    lines = def_file_content

    for line in lines[1:]:
            if line.split(" ")[0] == "RUN":
                print(f"[I] Build step: RUN {line.split(' ')[1]}", flush=True)
                subprocess.check_call(line.split(" ")[1:])

# --------------------
# -- PARENT PROCESS --


def parent():
    print("Running parent")
    print(sys.argv)

    c_def_file = sys.argv[2]
    mnt_dir = setup_container_volume(c_def_file)

    # Setup the namespaces
    unsharenamespaces()

    # Start the subprocess in the namespaces
    proc = subprocess.Popen(
        [sys.argv[0], "child", mnt_dir, c_def_file] + sys.argv[3:], shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE
    )
    print("Started child process (pid: {})".format(proc.pid))
    try:
        outs, errs = proc.communicate() # timeout = 5
    except TimeoutExpired:
        proc.kill()
        outs, errs = proc.communicate()

    for line in outs.decode("utf-8").strip().split("\n"):
        logger.info(line)
    for line in errs.decode("utf-8").strip().split("\n"):
        logger.error(line)

    proc.wait()  # Wait for the process to complete
    print(f"child process exited with code {proc.returncode}")


# -------------------------------
# -- CHILD / CONTAINER PROCESS --


def child():
    print(sys.argv)
    mnt_dir = sys.argv[2] 
    c_def_file = sys.argv[3]

    c_file_content = read_build_file(c_def_file)
    pivot_root_routine(sys.argv[2])
    mount_proc()

    build_container(sys.argv[2], c_file_content)

    print(f"[I] Running: {sys.argv[4:]}")
    proc = subprocess.Popen(
        sys.argv[4:], shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE
    )
    print(f"[I] pid: {proc.pid}")

    while proc.poll() is None:
        try:
            stdin = sys.stdin.readline()
            outs, errs = proc.communicate(stdin, timeout=15)
        except TimeoutExpired:
            proc.kill()
            outs, errs = proc.communicate()

        print(outs.decode("utf-8"), end="", file=sys.stdout)
        print(errs.decode("utf-8"), end="", file=sys.stderr)

    # outs, errs = proc.communicate()        
    # print(outs.decode("utf-8"), end="", file=sys.stdout)
    # print(errs.decode("utf-8"), end="", file=sys.stderr)

    exit(proc.returncode)


def main():
    if len(sys.argv) < 1:
        print("Need at least 1 argument")
        exit(1)

    if sys.argv[1] == "run":
        parent()
    elif sys.argv[1] == "child":
        child()
    else:
        print("What should I do?")
        exit(1)


if __name__ == "__main__":
    main()
