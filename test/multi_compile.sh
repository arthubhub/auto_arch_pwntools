#!/bin/bash

SOURCE="vuln.c"
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

compile gcc "-m32" "vuln_x86"
compile gcc "-m64" "vuln_x86_64"
compile arm-linux-gnueabi-gcc "" "vuln_arm"
compile aarch64-linux-gnu-gcc "" "vuln_arm64"
compile mips-linux-gnu-gcc "" "vuln_mips"
compile riscv64-linux-gnu-gcc "" "vuln_riscv64"
compile x86_64-w64-mingw32-gcc "" "vuln_PE.exe"
echo "Compilation finished."
