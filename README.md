# miner 🅱️ - stripped down fork of cpuminer that runs only in benchmark mode

This is a multi-threaded CPU miner for Litecoin and Bitcoin,
fork of pooler's cpuminer which is a fork of Jeff Garzik's
reference cpuminer.

## Why?
When built statically, it's a small program for generating stable workloads
and testing the system stability. Suits well for a tiny Linux `initramfs`.

## Building dependencies
GNU autotools and some compiler toolchain. For crosscompiling I recommend
any fresh toolchain based on `musl` libc which could be conveniently
downloaded here: https://toolchains.bootlin.com/

## Build instructions for static binary
```
# Clone the repository
git clone 'https://github.com/arzam16/minerb' && cd 'minerb'

# Checkout the latest version
git checkout v2.5.1b

# Run autogen
./autogen.sh

# Set the CROSS_COMPILE variable if crosscompiling
# Use your path prefix, mine is here for example
export CROSS_COMPILE="/mnt/hdd/toolchain/musl-10.2.1/bin/arm-linux-musleabihf-"

# Export paths to toolchain programs. Leave as is even if not
# crosscompiling, ${CROSS_COMPILE} will evaluate to an empty string.
export CC="${CROSS_COMPILE}gcc"
export LD="${CROSS_COMPILE}ld"

# In case the assembler doesn't support macros
# (most likely this isn't your case)
./nomacro.pl

# Run configure...
# ... for Linux x86_64:
./configure CFLAGS="-O3 -static"
# ... for Linux ARMv7:
./configure CFLAGS="-O3 -mfpu=neon -static" --host=arm-linux-musleabihf --target=arm-linux-musleabihf

# Compile the miner
make
```

## Reducing the size of executable (optional)
Why? Saving some space will allow the program to fit into smaller initramfs.

File sizes are specified for commit `3491b5e`.

- Original `minerb` built for ARM with musl-10.2.1 toolchain: **186800** bytes
- Strip the original binary `${CROSS_COMPILE}strip minerb`: **144716** bytes
- Pack the original binary with UPX 3.96: `upx --best --ultra-brute minerb`: **57084** bytes

## Architecture-specific notes
**ARM**: No runtime CPU detection. The miner can take advantage
of some instructions specific to ARMv5E and later processors,
but the decision whether to use them is made at compile time,
based on compiler-defined macros.
To use NEON instructions, add `-mfpu=neon` to CFLAGS.

**PowerPC**: No runtime CPU detection.
To use AltiVec instructions, add `-maltivec` to CFLAGS.

**x86**: The miner checks for SSE2 instructions support at runtime,
and uses them if they are available.

**x86-64**:	The miner can take advantage of AVX, AVX2 and XOP instructions,
but only if both the CPU and the operating system support them.

* Linux supports AVX starting from kernel version 2.6.30.
* FreeBSD supports AVX starting with 9.1-RELEASE.
* Mac OS X added AVX support in the 10.6.8 update.
* Windows supports AVX starting from Windows 7 SP1 and Windows Server 2008 R2 SP1.

The configure script outputs a warning if the assembler
doesn't support some instruction sets. In that case, the miner
can still be built, but unavailable optimizations are left off.
The miner uses the VIA Padlock Hash Engine where available.

## Usage instructions
Run `minerb --help` to see options but usually it's ok to just `./minerb`

## Credits
This fork of minerb is created by [arzam16](https://github.com/arzam16).

Most of the code in the current version of minerb was written by
Pooler <pooler@litecoinpool.org> with contributions from others.

The original minerd was written by Jeff Garzik <jeff@garzik.org>.
