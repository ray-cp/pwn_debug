from pwn import *

class membp(object):
    def __init__(self,process):
        self.wordSz=4
        self.hwordSz=2
        self.bits=32
        self.pie=0
        self.pid=0
        self.process=process
        self.set_basic_info()
        

    def leak(self,address, size):
        with open('/proc/%s/mem' % self.pid) as mem:
            mem.seek(address)
            return mem.read(size)

    def get_libc_base(self):
        with open('/proc/%s/maps' % self.pid) as maps:
            for line in maps:
                #print line
                name=line.split("/")[-1]
                if "libc" in name and "so" in name:
                    addr = int(line.split('-')[0], 16)
                    libc_header=self.leak(addr,0x20)
                    if libc_header[:4] == "\x7fELF":
                        self.libc_base=addr
                        log.info("libc base: %s"%hex(self.libc_base))
                        return
        log.info("can't not found libc base!!")
                    
    def set_basic_info(self):
         
        self.pid=proc.pidof(self.process)[0]
        self.get_elf_base()
        self.get_libc_base()
        self.get_stack_base()

    
    def get_stack_base(self):
        with open('/proc/%s/maps' % self.pid) as maps:
            for line in maps:
                #print line
                name=line.split("/")[-1]
                if "[stack]" in name:
                    addr = int(line.split('-')[0], 16)
                    self.stack_base=addr
                    log.info("stack base: %s"%hex(self.stack_base))
                    return
        log.info("can't not found stack base!!")

    def get_elf_base(self):
        name = os.readlink('/proc/%s/exe' % self.pid)
        with open('/proc/%s/maps' % self.pid) as maps:
            for line in maps:
                if name in line:
                    addr = int(line.split('-')[0], 16)
                    #mem.seek(addr)
                    #print hex(addr)
                    elf_header=self.leak(addr,0x20)
                    if elf_header[:4] == "\x7fELF":
                        bitFormat = u8(elf_header[4:5])
                        if bitFormat == 0x2:
                            self.wordSz = 8
                            self.hwordSz = 4
                            self.bits = 64
                        bitFormat=u16(elf_header[16:18])
                        if bitFormat == 0x3:
                            self.pie=1
                            log.info("PIE ENABLED")
                        elif bitFormat==0x2:
                            self.pie=0
                            log.info("PIE DISABLED")
                        else:
                            log.error("unknown pie")
                        self.elf_base=addr
                        log.info("programe base: %s"%hex(self.elf_base))
                        return
        log.error("Module's base address not found.")
        exit(1)

    
    def breakpoint(self,address_list,fork_follow="child",command=[]):
        
        debug_stri="set follow-fork-mode %s\n"%fork_follow
        
        if 'int' in str(type(address_list)):
            if self.pie:
                address_list=self.elf_base+address_list
            debug_stri+='b* '+hex(address_list)+'\n'
        elif 'list' in str(type(address_list)):
            if self.pie:
                for i in range(0,len(address_list)):
                    address_list[i]=self.elf_base+address_list[i]
            for addr in address_list:
                debug_stri+='b* '+hex(addr)+'\n'
        
        for com in command:
            debug_stri+=com+"\n"
        gdb.attach(self.process, debug_stri)

