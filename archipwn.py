  ######################
 #### Dependencies ####
######################
import shutil
import sys
import os, time, subprocess

import pwnlib.shellcraft

def check_dependencies():
    missing = []
    libs_path={}
    required_cmds = [
        ("qemu-aarch64", "QEMU for ARM64", "sudo apt-get install qemu-aarch64"),
        ("qemu-arm", "QEMU for ARM (32-bit)", "sudo apt-get install qemu-arm"),
        ("qemu-i386", "QEMU for x86 (i386)", "sudo apt-get install qemu-i386"),
        ("qemu-x86_64", "QEMU for x86_64 (amd64)", "sudo apt-get install qemu-x86_64"),
        ("qemu-mips", "QEMU for MIPS", "sudo apt-get install qemu-mips"),
        ("qemu-riscv64", "QEMU for RISC-V 64-bit", "sudo apt-get install qemu-riscv64"),
        ("gdb-multiarch", "GDB Multiarch", "sudo apt-get install gdb-multiarch"),
        ("tmux", "tmux terminal", "sudo apt-get install tmux"),
    ]
    required_libs = [
        ("arm", "arm-linux-gnueabihf", "sudo apt-get install libc6-dev-armhf-cross"),
        ("aarch64", "aarch64-linux-gnu",    "sudo apt-get install libc6-dev-arm64-cross"),
        ("mips", "mips-linux-gnu",       "sudo apt-get install libc6-dev-mips-cross"),
        ("riscv64", "riscv64-linux-gnu",    "sudo apt-get install libc6-dev-riscv64-cross"),
        ("i386", "i386-linux-gnu",       "sudo apt-get install libc6-dev-i386-cross"),
        ("amd64", "x86_64-linux-gnu",     "sudo apt-get install libc6-dev-amd64-cross"),
    ]
    for util in required_cmds:
        if shutil.which(util[0]) is None:
            missing.append(util)
    for lib in required_libs:
        usr_path = os.path.join("/usr",lib[1])
        usr_lib_path = os.path.join("/usr/lib",lib[1])
        if os.path.isdir(usr_path):
            libs_path[lib[0]]=usr_path
            print(f"{lib[0] } -> {usr_path}")
        elif os.path.isdir(usr_lib_path):
            libs_path[lib[0]]=usr_lib_path
            print(f"{lib[0] } -> {usr_lib_path}")
        else :
            missing.append(lib)
        
    if missing:
        dependencies_tips="\n".join([i[2] for i in missing])

        sys.exit("Missing required dependencies: " + ", ".join([i[1] for i in missing]) + "\nHow to install them ?\n"+dependencies_tips)
    else:
        print("All required dependencies are installed.")

        return libs_path

LIBS_PATH=check_dependencies()


  ##########################################
 ### Auto Arch pwntools based Debugger ####
##########################################

from pwn import *

# Binary config
BINARY = "./exemple"  ################## <- change this parametter ################## # -> you should copy the env of your remote target to align stack -> https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it/17775966#17775966
ELF_BINARY = ELF(BINARY)
DISABLE_ASLR = True

# Set the architecture 
context.arch = ELF_BINARY.arch
context.binary = BINARY
log.info(f"=== Context\n> arch : {context.arch}\n> binary :{context.binary}")


# Setup for QEMU
mapping = {
    "arm":       "qemu-arm",
    "aarch64":   "qemu-aarch64",
    "mips":      "qemu-mips",
    "riscv64":   "qemu-riscv64",
    "i386":      "qemu-i386",
    "amd64":     "qemu-x86_64",
}
if context.arch not in mapping:
    log.info(f"[!] ERROR in qemu setup : {context.arch} not in mapping")
    exit(1)

QEMU = mapping[context.arch]
GDB_PORT = 1235

# Configure the terminal (use tmux for split view) -> see https://www.redhat.com/en/blog/introduction-tmux-linux
if "TMUX" not in os.environ:
    sys.exit("Error: Please run this script inside a tmux session.")
context.terminal = ["tmux", "splitw", "-h"]

# Start the binary inside QEMU using the appropriate lib path
quemu_start = [QEMU, "-g", str(GDB_PORT), "-L", LIBS_PATH[context.arch] ,BINARY] 

disable_aslr=["setarch", os.uname().machine, "-R"] + quemu_start

if DISABLE_ASLR :
  qemu_process = disable_aslr
else :
  qemu_process = quemu_start


p = process(qemu_process)
log.info(" ".join(quemu_start))
time.sleep(1)
log.info("Started QEMU process; waiting for gdb to attach...")

# GDB script to connect to QEMU

user_script=["b*0x00400174",
    "continue"
]

gdb_version = "gdb-multiarch"
# Attach gdb-multiarch
gdb_cmd = [
    f"{gdb_version} ", #-> must use gdb-multiarch
    f" -ex 'symbol-file {BINARY}' ",
    f" -ex 'set solib-search-path {LIBS_PATH[context.arch]}' ",
    f" -ex 'set architecture {context.arch}' ",
    f" -ex 'target remote localhost:{GDB_PORT}' ", 
    f" -ex 'unset env LINES' ", # for stack alignement -> https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it/17775966#17775966
    f" -ex 'unset env COLUMNS' ", #for stack alignement -> https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it/17775966#17775966
    " \n ".join([f"-ex '{user_line}'" for user_line in user_script])                  
]
gdb_cmd_line = "".join(gdb_cmd)
subprocess.Popen(context.terminal + [gdb_cmd_line])
log.info(f"GDB debugger attached to {GDB_PORT} :\n$ " + gdb_cmd_line)

receive = p.recvuntil(b" name :",timeout=3600) # <- you must be waiting for something, or just do p.interactive()
print("<",receive)
