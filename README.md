# pwn_debug

**pwn_debug** -- An auxiliary debugging tool for ctf pwns based on pwntools

It is suggested you get the full description with **Usage** and **Installation** at [wiki](https://github.com/ray-cp/pwn_debug/wiki).

Here is just a simple description.

## Getting Started

* Install pwn_debug
```
git clone https://github.com/ray-cp/pwn_debug.git
cd pwn_debug
sudo python setup.py install 
# or python setup.py install --user
```

* Compile glibc with debug symbols

compile a specific version.
```
# ./build.sh $(version)
./build.sh 2.23
```

compile all the version(no parameter means compile all)
```
# ./build.sh  
./build.sh 
```


### normal usage

```
from pwn_debug import *

## step 1
pdbg=pwn_debug("binary")

pdbg.context.terminal=['tmux', 'splitw', '-h']

## step 2
pdbg.local("libc.so.6")
pdbg.debug("2.23")
pdbg.remote('34.92.96.238',10000)
## step 3
#p=pdbg.run("local")
#p=pdbg.run("debug")
p=pdbg.run("remote")

pdbg.bp([0x9aa])

elf=pdbg.elf
print hex(elf.got['printf'])
print hex(elf.plt['printf'])

libc=pdbg.libc
print libc.symbols['system']
p.interactive()

```

### IO FILE

```
from pwn_debug import *

fake_file=IO_FILE_plus()
fake_file._IO_write_ptr=1 # set _IO_write_ptr
fake_file._IO_write_base=0

fake_file.show()   # show the IO FILE

fake_file.orange_check() # check if the IO FILE can attack `house of orange`

fake_file.str_finish_check() # check if the IO FILE can attack hajck the `_IO_finish` in `_IO_str_jumps` vtable

fake_file.arbitrary_read_check("stdout") # check if the IO FILE can arbitrary read in stdout handle

fake_file.arbitrary_write_check("stdin") # check if the IO FILE can arbitrary write in stdin handle

fake_file.arbitrary_write_check("stdout") # check if the IO FILE can arbitrary write in stdout handle

print str(fake_file)
```

### ret2dl_resolve

x86 with fake reloc_arg:
```
ret2dl_resolve=pdbg.ret2dl_resolve()

addr,resolve_data,resovle_call=ret2dl_resolve.build_normal_resolve(bss_addr,'system',bss_addr+0x400)

payload=resolve_data+'a'*0x44+resovle_call
```

x64 with fake link_map:

```
offset=libc.symbols['system']-libc.symbols['__libc_start_main']
got_libc_address=elf.got['__libc_start_main']
ret2dl_resolve=pdbg.ret2dl_resolve()
# fake_link_map address is addr+0x100 
fake_link_map=ret2dl_resolve.build_link_map(addr+0x100,1,offset,got_libc_address)
payload+=fake_link_map
```

### format_string

```
payload=pdbg.fmtstr_payload(offset, writes, write_size='short',numbwritten):

payload=pdbg.fmtstr_hn_complete(offset,write_payload)

payload=pdbg.fmtstr_hn_payload(self,offset,write_payload)
```

## Update Log
2020.4.21: Add sym feature, eg. pdbg.sym={'chunk':0x202020}, regardless of PIE or not.
