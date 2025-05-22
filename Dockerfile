FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# 1) Autoriser i386 + installer paquets
RUN dpkg --add-architecture i386

RUN apt-get update && apt-get install -y --no-install-recommends \
      # émulation
      binfmt-support \
      qemu-user-static \
      qemu-user \
      # toolchains & dev headers (cross)
      build-essential \
      gcc \
      libc6-dev \
      # ARM32/ARMHF (hard-float)
      gcc-arm-linux-gnueabihf \
      libc6-dev-armhf-cross \
      # ARM64/AARCH64
      gcc-aarch64-linux-gnu \
      libc6-dev-arm64-cross \
      # MIPS
      gcc-mips-linux-gnu \
      libc6-dev-mips-cross \
      # RISC-V64
      gcc-riscv64-linux-gnu \
      libc6-dev-riscv64-cross \
      # x86 i386 (native multilib)
      gcc-multilib \
      g++-multilib \
      libc6-dev:i386 \
      # Windows PE (x86_64)
      mingw-w64 \
      # Debuggers & outils
      tmux \
      gdb \
      gdb-multiarch \
      # Python3 & pwntools
      python3 \
      python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Installer pwntools + pycryptodome avec timeout/retries
RUN python3 -m pip install --upgrade pip setuptools wheel \
 && pip install --no-cache-dir \
      --default-timeout=100 \
      --retries=5 \
      pycryptodome pwntools

# Symlinks manquants pour i386-linux-gnu
RUN ln -s /usr/i686-linux-gnu       /usr/i386-linux-gnu \
 && mkdir -p /usr/lib/i386-linux-gnu \
 && ln -s /usr/lib32               /usr/lib/i386-linux-gnu

VOLUME ["/shared"]
WORKDIR /shared
CMD ["bash"]

