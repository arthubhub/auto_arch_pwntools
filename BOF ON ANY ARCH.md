# BOF ON ANY ARCH

This script automates the process of setting up the environment for binary exploitation on foreign architectures.

## Requirements

- python3 and pwntools
    
    I use `python3.9`, you can install pwntools with pip :
    
    `pip3.9 install pwntools`
    
- Other
    
    For the other dependencies, just run the program, it will help you.
    

## Program

```
See "archipwn.py"
```

Here are the common path for the versions of qemu :

- **x86:** `/usr/bin/qemu-i386`
- **x86_64:** `/usr/bin/qemu-x86_64`
- **ARM:**
    - 32‑bit: `/usr/bin/qemu-arm`
    - 64‑bit: `/usr/bin/qemu-aarch64`
- **MIPS:** `/usr/bin/qemu-mips`
- **RISC‑V:**
    - 32‑bit: `/usr/bin/qemu-riscv32`
    - 64‑bit: `/usr/bin/qemu--riscv64`
- Full list here
    
    ```python
    qemu-aarch64
    qemu-arm
    qemu-i386
    qemu-mips
    qemu-mips64
    qemu-mips64el
    qemu-mipsel
    qemu-riscv32
    qemu-riscv64
    qemu-x86_64
    ```
    
- Get a list of files on each arch
    
    ### Requirements
    
    ```bash
    sudo apt-get install gcc-multilib libc6-dev-i386
    sudo apt-get install gcc-arm-linux-gnueabi
    sudo apt-get install gcc-aarch64-linux-gnu
    sudo apt-get install gcc-mips-linux-gnu
    sudo apt-get install gcc-riscv64-linux-gnu
    sudo apt-get install mingw-w64
    
    ```
    
    ### Script
    
    ```bash
    #!/bin/bash
    
    SOURCE="hello_word.c"
    compile() {
        local compiler="$1"
        local flags="$2"
        local output="$3"
    
        if command -v "$compiler" &> /dev/null; then
            echo "Compiling for $output using $compiler..."
            "$compiler" $flags "$SOURCE" -o "$output"
            if [ $? -eq 0 ]; then
                echo "Successfully built $output"
            else
                echo "Failed to build $output"
            fi
        else
            echo "Compiler $compiler not found. Skipping $output."
        fi
    }
    
    compile gcc "-m32" "hello_word_x86"
    compile gcc "-m64" "hello_word_x86_64"
    compile arm-linux-gnueabi-gcc "" "hello_word_arm"
    compile aarch64-linux-gnu-gcc "" "hello_word_arm64"
    compile mips-linux-gnu-gcc "" "hello_word_mips"
    compile riscv64-linux-gnu-gcc "" "hello_word_riscv64"
    compile x86_64-w64-mingw32-gcc "" "hello_word_PE.exe"
    echo "Compilation finished."
    ```
    
    ### Result
    
    ```
    hello_word_arm
    hello_word_mips
    hello_word_PE.exe
    hello_word_riscv64
    hello_word_x86
    hello_word_x86_64
    ```
    

## What is context.arch depending on files ?

hello_word_arm → `arm` 

hello_word_arm64 → `aarch64` 

hello_word_mips → `mips`

~~hello_word_PE.exe~~

hello_word_riscv64 → `riscv64`

hello_word_x86 → `i386`

hello_word_x86_64 → `amd64`

---

## Errors

If you get errors linked to the **ld-linux.so.3** : `/lib/ld-linux.so.3: No such file or directory` 

→ `sudo apt-get install libc6-armhf-cross`

→ `sudo ln -s /usr/arm-linux-gnueabihf/lib/ld-linux-armhf.so.3 /lib/ld-linux.so.3`

→ `tree /usr/arm-linux-gnueabihf/lib`

→ `qemu-arm -g 1234 -L /usr/arm-linux-gnueabihf hello_word_arm`

When you give a path to qemu, it will try to retrieve libraries as if it was the real file system. So the libraries must be in DIR/lib/ path and you must give the DIR to qemu.
