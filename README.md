<div align='center'>
  <h1><code>addr-symbolizer-rs</code></h1>
  <p>
    <strong>A <a href="https://en.wikipedia.org/wiki/KISS_principle">KISS</a> Rust crate to symbolize function addresses using Windows <a href="https://en.wikipedia.org/wiki/Program_database">PDB</a> files</strong>
  </p>
  <p>
    <a href="https://crates.io/crates/addr-symbolizer-rs"><img src="https://img.shields.io/crates/v/addr-symbolizer-rs.svg" /></a>
    <img src='https://github.com/0vercl0k/addr-symbolizer-rs/workflows/Builds/badge.svg'/>
  </p>
  <p>
    <img src='https://github.com/0vercl0k/addr-symbolizer-rs/raw/main/pics/addr-symbolizer-rs.webp'/>
  </p>
</div>

## Overview

[addr-symbolizer-rs](https://github.com/0vercl0k/addr-symbolizer-rs) allows you to symbolize (`0xfffff8053b9ca5c0` -> `nt!KiPageFault+0x0`) function addresses (from an execution trace for example); it is the crate that powers [symbolizer-rs](https://github.com/0vercl0k/symbolizer-rs). Here is an example of a raw execution trace..:

```text
0xfffff8053b9ca5c0
0xfffff8053b9ca5c1
0xfffff8053b9ca5c8
0xfffff8053b9ca5d0
0xfffff8053b9ca5d4
0xfffff8053b9ca5d8
0xfffff8053b9ca5dc
0xfffff8053b9ca5e0
```

..transformed into a full symbolized trace:

```text
ntoskrnl.exe!KiPageFault+0x0
ntoskrnl.exe!KiPageFault+0x1
ntoskrnl.exe!KiPageFault+0x8
ntoskrnl.exe!KiPageFault+0x10
ntoskrnl.exe!KiPageFault+0x14
ntoskrnl.exe!KiPageFault+0x18
ntoskrnl.exe!KiPageFault+0x1c
ntoskrnl.exe!KiPageFault+0x20
```

It needs to know where modules (user & kernel) are in *memory* and how to read that *memory*. With those in hands, it is able to parse PE files, read the Export Address Table, extract the PDB identifier (if possible), attempt to download the PDB file from a symbol server, store it into a symbol cache and finally parse it to extract function boundaries.

## Authors

* Axel '[0vercl0k](https://twitter.com/0vercl0k)' Souchet

## Contributors

[ ![contributors-img](https://contrib.rocks/image?repo=0vercl0k/addr-symbolizer-rs) ](https://github.com/0vercl0k/addr-symbolizer-rs/graphs/contributors)
