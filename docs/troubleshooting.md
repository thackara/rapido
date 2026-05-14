# Troubleshooting

## Compile fixes
* [GCC >= 15] typedef \_Bool bool (true/false related errors)
```
include/linux/stddef.h:11:9: error: cannot use keyword 'false' as enumeration constant
   11 |         false   = 0,
      |         ^~~~~
include/linux/stddef.h:11:9: note: 'false' is a keyword with '-std=c23' onwards
include/linux/types.h:35:33: error: 'bool' cannot be defined via 'typedef'
   35 | typedef _Bool                   bool;
      |                                 ^~~~
```
More fixes, some are architecture specific.

  * [`8ba14d9f490ae ("efi: libstub: Use '-std=gnu11' to fix build with GCC 15")`](
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8ba14d9f490aef9fd535c04e9e62e1169eb7a055)
  * `x86_64`: [`ee2ab467bddfb ("x86/boot: Use '-std=gnu11' to fix build with GCC 15") # v6.14-rc2`](
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ee2ab467bddfb2d7f68d996dbab94d7b88f8eaf7)
(backported: 5.10.235, 5.15.179, 6.6.78, 6.1.129, 6.12.14, 6.13.3; required to older kernels, at least >= 4.5)

## Runtime fixes
* [binutils >= 2.31] QEMU loops in SeaBIOS during boot

[`e3d03598e8ae7 ("x86/build/64: Force the linker to use 2MB page size") # v4.16-rc7`](
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e3d03598e8ae7d195af5d3d049596dec336f569f)
(backported: 4.4.125, 4.14.31, 4.15.14, 4.9.91)
