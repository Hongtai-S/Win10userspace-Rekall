# Win10userspace

print the user address space layout of Windows 10 64-bit system

for live response

Usage
Live (Memory) > win10userspace <pid>
  
  
Tested Operating Systems
Windows 10x64 14393



Output Example
    start           end            used           size            protect         type   description
-------------- -------------- -------------- -------------- -------------------- ------- -----------------------------------
       0x10000        0x1ffff         0x1000        0x10000 READWRITE            Shared  Heap 1 NT Heap
       0x20000        0x2cfff         0x1000         0xd000 READWRITE            Private Segment 1 of Heap 2
       0x30000        0x45fff        0x16000        0x16000 READONLY             Shared  ApiSetMap
       0x50000        0x53fff         0x4000         0x4000 READONLY             Shared
       0x60000        0x61fff         0x2000         0x2000 READWRITE            Private pShimData
       0xb0000        0xbffff         0x7000        0x10000 READWRITE            Private Heap 2 NT Heap
       0xe0000       0x1dffff         0x6000       0x100000 READWRITE            Private Heap 0 NT Heap
      0x200000       0x3fffff         0x5000       0x200000 READWRITE            Private PEB0x23e000 TEB0x23f000 TEB0x241000
      0x400000       0x421fff        0x13000        0x22000 EXECUTE_WRITECOPY    Shared  C:\Users\sht\Desktop\maloc.exe
      0x430000       0x62ffff         0x3000       0x200000 READWRITE            Private Stack of Thread 0
      0x630000       0x6f0fff        0x2d000        0xc1000 READONLY             Shared  C:\Windows\System32\locale.nls
      0x700000       0x8fffff         0x1000       0x200000 READWRITE            Private Stack of Thread 1
      0x900000       0x9fffff        0x82000       0x100000 READWRITE            Private Segment 0 of Heap 2
    0x7ffe0000     0x7ffeffff         0x1000        0x10000 READONLY             Private
0x7ff5fffc0000 0x7ff5ffff2fff        0x14000        0x33000 READONLY             Shared  CodePage
0x7ff5ffec0000 0x7ff5fffbffff         0x5000       0x100000 READONLY             Shared  Heap 3 (Shared) NT Heap
0x7ffe69e70000 0x7ffe6a08cfff        0x4e000       0x21d000 EXECUTE_WRITECOPY    Shared  C:\Windows\System32\KernelBase.dll
0x7ffe6b450000 0x7ffe6b4edfff        0x33000        0x9e000 EXECUTE_WRITECOPY    Shared  C:\Windows\System32\msvcrt.dll
0x7ffe6cb60000 0x7ffe6cc0bfff        0x2b000        0xac000 EXECUTE_WRITECOPY    Shared  C:\Windows\System32\kernel32.dll
0x7ffe6d900000 0x7ffe6dad1fff        0xb8000       0x1d2000 EXECUTE_WRITECOPY    Shared  C:\Windows\System32\ntdll.dll
