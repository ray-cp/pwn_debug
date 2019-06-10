#!/usr/bin/env python
# encoding: utf-8

from random import randint
from pwn import *

def confused_pack(payload,length):
    r'''
    confused traffic data by adding some junk data
    '''

    n=length-len(payload)
    c_list=['\x5f','\x6f','\x4f','\x8f','\x9f','\xaf']

    rstr = ['ls\x00','cat\x00','flag\x00','whoami\x00','tail\x00','head\x00','sh\x00','bin\x00','system\x00','cat<flag\x00','x=`cat<flag\x00`','echo\x00','/bin/sh\x00']
    rnum = [p64(randint(0,0xffffffffff)+0x7f0000000000), p64(randint(0x100000000000,0xffffffffffff)&0xffffffffff00)]
    #npad = [8 * '\x44']
    npad='\x44'
    rlist = [rstr,rnum,npad,rnum,rstr]

    padding = ''
    while len(padding)<n:
        ritem = rlist[randint(0,len(rlist)-1)]
        padding += ritem[randint(0,len(ritem)-1)]
    

    padding = padding.replace("\x00", c_list[randint(0,len(c_list)-1)] )
    padding = padding.replace("\n",c_list[randint(0,len(c_list)-1)])
    padding = padding.replace("\r",c_list[randint(0,len(c_list)-1)])
    padding = padding.replace("\t",c_list[randint(0,len(c_list)-1)])
    padding = padding.replace(" ",c_list[randint(0,len(c_list)-1)])

    payload=payload+padding
    
    return payload[:length]
