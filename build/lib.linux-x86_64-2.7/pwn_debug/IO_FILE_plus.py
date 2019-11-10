from pwn import *


_IO_FILE_plus_size = {
	'i386':0x98,
	'amd64':0xe0
}
_IO_FILE_plus = {
    'i386':{
        0x0:'_flags',
        0x4:'_IO_read_ptr',
        0x8:'_IO_read_end',
        0xc:'_IO_read_base',
        0x10:'_IO_write_base',
        0x14:'_IO_write_ptr',
        0x18:'_IO_write_end',
        0x1c:'_IO_buf_base',
        0x20:'_IO_buf_end',
        0x24:'_IO_save_base',
        0x28:'_IO_backup_base',
        0x2c:'_IO_save_end',
        0x30:'_markers',
        0x34:'_chain',
        0x38:'_fileno',
        0x3c:'_flags2',
        0x40:'_old_offset',
        0x44:'_cur_column',
        0x46:'_vtable_offset',
        0x47:'_shortbuf',
        0x48:'_lock',
        0x4c:'_offset',
        0x54:'_codecvt',
        0x58:'_wide_data',
        0x5c:'_freeres_list',
        0x60:'_freeres_buf',
        0x64:'__pad5',
        0x68:'_mode',
        0x6c:'_unused2',
        0x94:'vtable'
    },

    'amd64':{
        0x0:'_flags',
        0x8:'_IO_read_ptr',
        0x10:'_IO_read_end',
        0x18:'_IO_read_base',
        0x20:'_IO_write_base',
        0x28:'_IO_write_ptr',
        0x30:'_IO_write_end',
        0x38:'_IO_buf_base',
        0x40:'_IO_buf_end',
        0x48:'_IO_save_base',
        0x50:'_IO_backup_base',
        0x58:'_IO_save_end',
        0x60:'_markers',
        0x68:'_chain',
        0x70:'_fileno',
        0x74:'_flags2',
        0x78:'_old_offset',
        0x80:'_cur_column',
        0x82:'_vtable_offset',
        0x83:'_shortbuf',
        0x88:'_lock',
        0x90:'_offset',
        0x98:'_codecvt',
        0xa0:'_wide_data',
        0xa8:'_freeres_list',
        0xb0:'_freeres_buf',
        0xb8:'__pad5',
        0xc0:'_mode',
        0xc4:'_unused2',
        0xd8:'vtable'
    }
}



class IO_FILE_plus(dict):
    arch = None
    endian = None
    fake_file = None
    size  = 0
    FILE_struct = []
	

    @LocalContext
    def __init__(self):
        self.arch = context.arch
        self.endian = context.endian

        if self.arch != 'i386' and self.arch != 'amd64':
            log.error('architecture not supported!')
            #success('arch: '+str(self.arch))

        self.FILE_struct = [_IO_FILE_plus[self.arch][i] for i  in sorted(_IO_FILE_plus[self.arch].keys())]
        self.update({r:0 for r in self.FILE_struct})
        self.size = _IO_FILE_plus_size[self.arch]
            

    def __setitem__(self, item, value):
        if item not in self.FILE_struct:
            log.error("Unknown item %r (not in %r)" % (item, self.FILE_struct))
        super(IO_FILE_plus, self).__setitem__(item, value)

    def __setattr__(self, attr, value):
        if attr in IO_FILE_plus.__dict__:
            super(IO_FILE_plus, self).__setattr__(attr, value)
        else:
            self[attr]=value

    def __getattr__(self, attr):
        return self[attr]

    def __str__(self):
        fake_file = ""
        with context.local(arch=self.arch):
            for item_offset in sorted(self.item_offset):
                if len(fake_file) < item_offset:
                    fake_file += "\x00"*(item_offset - len(fake_file))
                fake_file += pack(self[_IO_FILE_plus[self.arch][item_offset]],word_size='all')
            fake_file += "\x00"*(self.size - len(fake_file))
        
        return fake_file

    @property
    def item_offset(self):
        return _IO_FILE_plus[self.arch].keys()
    def offset(self,key):
        return list(_IO_FILE_plus[self.arch].keys())[list(_IO_FILE_plus[self.arch].values()).index(key)]
    def show(self):
        print "IO_FILE_plus struct:"
        print "{"
        for item_offset in sorted(self.item_offset):
            print "\t"+_IO_FILE_plus[self.arch][item_offset]+": "+hex(self[_IO_FILE_plus[self.arch][item_offset]])
        print "}"

    def IO_flush_all_lokcp_overflow_check(self):
        """
        check condition1:
            fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
        """
        cond1=0
        if self['_mode']>0 and self['_mode']<0x80000000:
            cond1|=0x1
        if self['_IO_write_ptr']<=self['_IO_write_base']:
            cond1|=0x2
        if cond1!=0:
            return False
        else:
            return True
    def finish_table_call_check(self):
        """
        check condition:
            fp->_flag&0x1=0 && fp->_IO_buf_base!=0
        """
        cond=0
        if self['_flags']&0x1 !=0:
            cond|=0x1
        if self['_IO_buf_base']==0:
            cond|=0x2
        if cond!=0:
            return False
        else:
            return True

    def str_finish_check(self):
        if self.IO_flush_all_lokcp_overflow_check() and self.finish_table_call_check():
            log.success("_IO_str_jumps __finish call build success")
        
        else:
            log.warn("_IO_str_jumps __finish call unsatisfied")
            log.warn("condition:")
            log.warn("\t_flags&0x1==0")
            log.warn("\t_mode<=0") 
            log.warn("\t_IO_write_ptr>_IO_write_base")
            log.warn("\t_IO_buf_base!=0")
            
            log.warn("right now:")
            log.warn("\t_flags&0x1==%s"%(hex(self['_flags']&0x1)))
            log.warn("\t_mode=%s"%hex(self['_mode']))
            log.warn("\t_IO_write_ptr=%s"%hex(self['_IO_write_ptr']))
            log.warn("\t_IO_write_base=%s"%hex(self['_IO_write_base']))
            log.warn("\t_IO_buf_base=%s"%(hex(self['_IO_buf_base'])))
            #log.warn("\tYou shoud satisfy house of orange first"
            


    def orange_check(self):
        if context.arch=="i386" or context.arch=="amd64":
            if self.IO_flush_all_lokcp_overflow_check():
                log.success("house of orange IO FILE build success")
            else:
                log.warn( "house of orange unsatisfied")
                log.warn("condition:")
                log.warn("\t_mode<=0") 
                log.warn("\t_IO_write_ptr>_IO_write_base")
                log.warn("right now:")
                log.warn("\t_mode=%s"%hex(self['_mode']))
                log.warn("\t_IO_write_ptr=%s"%hex(self['_IO_write_ptr']))
                log.warn("\t_IO_write_base=%s"%hex(self['_IO_write_base']))
        else:
            log.error("unknow arch, no house of orange check")
            exit(0)


    def stdin_arbitrary_write_check(self):
        """
        check condition:
            _flags | _IO_NO_READS(0x4)==0
            _fileno==0
            _IO_read_ptr==_IO_read_end
            _IO_buf_base<_IO_buf_end
            the target addr should be _IO_buf_base and size should be _IO_buf_end-_IO_buf_base
        """
        cond=0
        if self['_flags']&0x4!=0:
            cond|=1
        if self['_fileno']!=0:
            cond|=2
        if self['_IO_read_ptr']!=self['_IO_read_end']:
            cond|=4
        if self['_IO_buf_base']>=self['_IO_buf_end']:
            cond|=8
        if cond==0:
            log.info("stdin arbitrary write IO FILE struct build success")
            log.info("\twrite address is %s"%(hex(self['_IO_buf_base'])))
            log.info("\tsize is %s"%(hex(self['_IO_buf_end']-self['_IO_buf_base'])))
        else:
            log.warn("stdin arbitrary write unsatisfied")
            log.warn("condition:")
            log.warn("\t_flags&0x4==0") 
            log.warn("\t_fileno==0")
            log.warn("\t_IO_read_ptr==_IO_read_end")
            log.warn("\t_IO_buf_base<_IO_buf_end")
            log.warn("\twrite address should be _IO_buf_base with size (_IO_buf_end-_IO_buf_base)")
            log.warn("right now:")
            log.warn("\t_flags=%s"%hex(self['_flags']))
            log.warn("\t_fileno=%s"%hex(self['_fileno']))
            log.warn("\t_IO_read_ptr: %s"%(hex(self['_IO_read_ptr'])))
            log.warn("\t_IO_read_end: %s"%(hex(self['_IO_read_end'])))
            log.warn("\t_IO_buf_base: %s"%(hex(self['_IO_buf_base'])))
            log.warn("\t_IO_buf_end: %s"%(hex(self['_IO_buf_end'])))
        



    def stdout_arbitrary_write_check(self):
        """
        check condition:
            _IO_write_ptr<_IO_write_end
            the target addr should be _IO_write_ptr and size should be _IO_write_end-_IO_write_ptr
        """
        cond=0
        if self['_IO_write_ptr']>=self['_IO_write_end']:
            cond|=1
        if cond==0:
            log.info("stdout arbitrary write IO FILE struct build success")
            log.info("\twrite address is %s"%(hex(self['_IO_write_ptr'])))
            log.info("\tsize is %s"%(hex(self['_IO_write_end']-self['_IO_write_ptr'])))
        else:
            log.warn("stdout arbitrary write unsatisfied")
            log.warn("condition:")
            log.warn("\t_IO_write_ptr<_IO_write_end")
            log.warn("\twrite address should be _IO_write_ptr with size (_IO_write_end-_IO_write_ptr)")
            log.warn("right now:")
            log.warn("\t_IO_write_ptr: %s"%(hex(self['_IO_write_ptr'])))
            log.warn("\t_IO_write_end: %s"%(hex(self['_IO_write_end'])))
        

    def stdout_arbitrary_read_check(self):
        """
        check condition:
            _flags | _IO_NO_WRITES(0x8)==0
            _flags | _IO_CURRENTLY_PUTTING(0x800)==0
            _fileno==1
            _IO_read_end==_IO_write_base
            _IO_write_base<_IO_write_ptr
            the target addr should be _IO_write_base and size should be _IO_write_ptr-_IO_write_base
        """
        cond=0
        if self['_flags']&0x8!=0:
            cond|=1
        if self['_flags']&0x800==0:
            cond|=2
        if self['_fileno']!=1:
            cond|=4
        if self['_IO_read_end']!=self['_IO_write_base']:
            cond|=8
        if self['_IO_write_base']>=self['_IO_write_ptr']:
            cond|=16
        if cond==0:
            log.info("stdout arbitrary read IO FILE struct build success")
            log.info("\tread address is %s"%(hex(self['_IO_write_base'])))
            log.info("\tsize is %s"%(hex(self['_IO_write_ptr']-self['_IO_write_base'])))
        else:
            log.warn("stdout arbitrary write unsatisfied")
            log.warn("condition:")
            log.warn("\t_flags&0x8==0") 
            log.warn("\t_flags&0x800!=0") 
            log.warn("\t_fileno==1")
            log.warn("\t_IO_read_end==_IO_write_base")
            log.warn("\t_IO_write_base<_IO_write_ptr")
            log.warn("\tread address should be _IO_write_base with size (_IO_write_ptr-_IO_write_base)")
            log.warn("right now:")
            log.warn("\t_flags=%s"%hex(self['_flags']))
            log.warn("\t_fileno=%s"%hex(self['_fileno']))
            log.warn("\t_IO_read_end: %s"%(hex(self['_IO_read_end'])))
            log.warn("\t_IO_write_base: %s"%(hex(self['_IO_write_base'])))
            log.warn("\t_IO_write_ptr: %s"%(hex(self['_IO_write_ptr'])))
        
        

    def arbitrary_read_check(self,handle):
        if handle=="stdout":
            self.stdout_arbitrary_read_check()
        else:
            log.error("no %s arbitrary read module"%(handle))

    def arbitrary_write_check(self,handle):
        if handle=="stdin":
            self.stdin_arbitrary_write_check()
        elif handle=="stdout":
            self.stdout_arbitrary_write_check()
        else:
            log.error("no %s arbitrary write module"%(handle))


