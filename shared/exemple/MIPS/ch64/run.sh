#! /bin/sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

cd /challenge/app-systeme/ch64/

env -i QEMU_LD_PREFIX=. timeout --foreground -k 10s 600s /opt/qemu/mips-linux-user/qemu-mips -noaslr -nx ./ch64
