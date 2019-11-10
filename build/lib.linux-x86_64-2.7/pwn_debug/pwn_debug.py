from pwn import *
import shutil
#import time
import os
from membp import membp
from ret2dl_resolve import ret2dl_resolve
import fmtstr

class pwn_debug(object):
    def __init__(self,pwn_name=""):
        self.pwn_name=pwn_name
        self.pwn_path="/tmp/"+pwn_name 
        #context.terminal = ['tmux', 'splitw', '-h']
        self.get_basic_info()
        #log.info("ELF arch: %s"%self.arch)
        #log.info("ELF endian: %s"%self.endian)

        ## get some class from pwn
        self.get_pwn_class()
        self.context.arch=self.arch
        self.context.endian=self.endian
        #self.set_default()

    # get class from pwn including: context
    def get_pwn_class(self):
        #log.info("some class")
        self.context=context
    def __getattr__(self,item):
        #print "******"
        #print item
        if item=="membp" and self.p_type=="remote":
            log.error("Can't use membp in remote mode")

            return None
        
            
        
        log.error("No %s in pwn_debug"%item)
        exit(0)


    def get_basic_info(self):
        if self.pwn_name:
            pwn_name=self.pwn_name
        else:
            pwn_name="/bin/dash"
        with open(pwn_name) as fd:
            if fd.read(4) =='\x7fELF':
                arch=u8(fd.read(1))
                if arch==2:
                    self.arch="amd64"
                elif arch==1:
                    self.arch="x86"
                else:
                    log.error("elf with a unknow arch")
                endian=u8(fd.read(1))
                if endian==2:
                    self.endian="big"
                elif endian==1:
                    self.endian="little"
                else:
                    log.error("elf with a unknow endian")

            else:
                log.error("not a elf file")
                exit(0)
        
    def debug(self,libc_version,env={}):
        self.debug_libc_version=libc_version
        self.build_debug_info(libc_version,env)
    def local(self,libc_path="",ld_path="",env={}):
        self.build_local_info(libc_path,ld_path,env)
    def remote(self,host="",port="",libc_path=""):
        self.build_remote_info(host,port,libc_path)
    # set type of pwn, which should be: debug, local or remote.
    def set_ptype(self,p_type):
        #print len(p_type)
        if p_type=="debug":
            #print '22'
            self.p_type=p_type
        elif p_type=="local":
            #print "33"
            self.p_type=p_type
        elif p_type=="remote":
            self.p_type=p_type
        else:
            log.error("pwn type should be given")
            exit(1)
    def build_debug_info(self,libc_version,env):
        if self.arch=='amd64':
            self.debug_ld_path='/glibc/x64/'+libc_version+'/lib/ld-'+libc_version+'.so'
            self.debug_libc_path='/glibc/x64/'+libc_version+'/lib/libc-'+libc_version+'.so'
            #self.debug_env=env
            #self.debug_env["LD_PRELOAD"]=self.debug_libc_path
        else:
            self.debug_ld_path='/glibc/x86/'+libc_version+'/lib/ld-'+libc_version+'.so'
            self.debug_libc_path='/glibc/x86/'+libc_version+'/lib/libc-'+libc_version+'.so'
            #log.info("x86, under developing...")
            #exit(0)
        if not os.path.exists(self.debug_ld_path) or not os.path.exists(self.debug_libc_path):
            log.error("the libc %s is not exist, you can't use debug mode\nplease see the installation manual"%libc_version)
            exit(0)

        self.debug_env=env
        self.debug_env["LD_PRELOAD"]=self.debug_libc_path

    def build_local_info(self,libc_path,ld_path,env):
        self.local_ld_path=ld_path
        self.local_libc_path=libc_path
        self.local_env=env
        self.local_env["LD_PRELOAD"]=self.local_libc_path
    def build_remote_info(self,host,port,libc_path):
        self.remote_host=host
        self.remote_port=port
        self.remote_libc_path=libc_path

    # according to the type of pwn, start the process.
    def run(self,p_type):
        #print p_type
        self.set_ptype(p_type)
        #print self.p_type
        if self.p_type=="debug":
            #print "123"
            self.run_debug()
        elif self.p_type=="local":
            #print "44"
            self.run_local()
        elif self.p_type=="remote":
            #self.membp=membp(self.process)
            self.run_remote()
        if self.p_type!="remote":   
            self.membp=membp(self.process)
            return self.process
        else:
            return self.remote

    ## debug run
    def run_debug(self):
        ## copy the binary to tmp dir, and patch with the conresponding libc
        shutil.copyfile(self.pwn_name,self.pwn_path)
        sleep(0.2)
        os.chmod(self.pwn_path,0o770)
        cmd='patchelf --set-interpreter '+self.debug_ld_path+' '+self.pwn_path
        os.system(cmd)
        sleep(0.2)
        self.elf=ELF(self.pwn_path,checksec=False)
        self.libc=ELF(self.debug_libc_path,checksec=False)
        
        self.process = process( self.pwn_path, env=self.debug_env)
        return self.process
    ## local run
    def run_local(self):
        ### copy to tmp dir 
        shutil.copyfile(self.pwn_name,self.pwn_path)
        sleep(0.2)
        os.chmod(self.pwn_path,0o770)
        ### change ld.so if need
        #print self.local_ld_path,self.pwn_path
        if self.local_ld_path:
            #print "here"
            cmd='patchelf --set-interpreter '+self.local_ld_path+' '+self.pwn_path
            os.system(cmd)
            sleep(0.2)
        ### set libc library
        self.elf=ELF(self.pwn_path,checksec=False)
        if self.local_libc_path:
            self.libc=ELF(self.local_libc_path,checksec=False)
        else:
            if self.arch=="amd64":
                self.libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
            elif self.arch=="x86":
                self.libc=ELF("/lib/i386-linux-gnu/libc.so.6",checksec=False)
        ### start process
        self.process=process(self.pwn_path,env=self.local_env)
        return self.process

        ## remote run
    def run_remote(self):
        ### set libc library
        if self.pwn_name:
            self.elf=ELF(self.pwn_name,checksec=False)
        if self.remote_libc_path:
            self.libc=ELF(self.remote_libc_path,checksec=False)
        else:
            if self.arch=="amd64":
                self.libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
            elif self.arch=="x86":
                self.libc=ELF("/lib/i386-linux-gnu/libc.so.6",checksec=False)

        ### start remote connect
        self.remote=remote(self.remote_host,self.remote_port)
        return self.remote

    def bp(self,address_list=[],fork_follow="child",command=[]):
        if self.p_type=="remote":
            log.info("breakpoint ignored for remote connect")
            return
        #self.membp=membp(self.process)
        self.membp.breakpoint(address_list=address_list,fork_follow=fork_follow,command=command,sym=self.sym)

    def sym(self,sym):
    	self.sym=sym

    def ret2dl_resolve(self):
        self.ret2dl_resolve=ret2dl_resolve(self)
        return self.ret2dl_resolve

     
    def fmtstr_payload(self,offset, writes, write_size='byte',numbwritten=0):
        return fmtstr.fmtstr_payload(offset,writes,write_size,numbwritten)

    def fmtstr_hn_complete(self,offset,write_payload):
        return fmtstr.fmtstr_hn_complete(offset,write_payload)

    
    def fmtstr_hn_payload(self,offset,write_payload):
        return fmtstr.fmtstr_hn_payload(offset,write_payload)




