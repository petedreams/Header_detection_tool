#!/usr/bin/env python
# -*- coding: utf-8 -*-

#tkiwa.py
'''Malicious Packet detection tool with protocol header.'''


from optparse import OptionParser, OptionValueError
from signal import signal, SIGPIPE, SIG_DFL, SIGINT, SIG_DFL
import os
import sys
import dpkt
import json
import datetime
import binascii
import urllib2
import ctypes
import platform
import socket
import time
import struct

try:
    import pcapy
except ImportError:
    print 'using [-i] requiers install pcapy'

ETH_P_IP = 0x800
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
SCRIPT_DIR=os.path.abspath(os.path.dirname(__file__))
SIG_FILE=os.path.join(SCRIPT_DIR,'..','data','signature.json')
SIG_URL = 'http://ipsr.ynu.ac.jp/tkiwa/download/signature.json'

def print_line_result(obj,print_data,options):
    if not obj.sig_name:
        sig = 'None'
    else:
        sig = obj.sig_name
    if options.time:
        print '%s %s [%s]'%(obj.ts_date,print_data,sig)
    else:
        print '%s [%s]'%(print_data,sig)

class IPHeader:
    def __init__(self):
        self.ts = None
        self.ip = None
        self.src_addr = None
        self.dst_addr = None
        self.ts_date = None
        self.ipid = None
        self.off = None
        self.ttl = None
        self.ver = None
        self.sig_name = None
        self.hdr = {}

    def set_header(self,ts,ip):
        self.ts = ts
        self.ip = ip
        self.src_addr = socket.inet_ntoa(ip.src)
        self.dst_addr = socket.inet_ntoa(ip.dst)
        self.ts_date = ts
        self.ipid = ip.id
        self.off = ip.off
        self.ttl = ip.ttl
        self.ver = None
        self.sig_name = None
        self.hdr = {'ipid':self.ipid,'off':self.off,'ttl':self.ttl}
        
    def masscan(self,ip,tcpudp,massid):
        addr_10 = int(binascii.b2a_hex(ip.dst),16)
        cal= addr_10^tcpudp.dport^massid
        if ctypes.c_ushort(cal).value==ip.id:
            return True

    def ptn_match(self,sig,proto):
        for s in sig[proto]:
            if s['signature']=='masscan_tcp':
                if not self.masscan(self.ip,self.tcp,self.tcp.seq):
                    continue
            if s['signature']=='masscan_dns':
                if not self.masscan(self.ip,self.udp,self.dnsid):
                    continue
            if s['signature']=='masscan_ntb':
                if proto == "udp" and self.ntbid:
                    if not self.masscan(self.ip,self.udp,self.ntbid):
                        continue
                else:
                    continue
            if s['signature']=='masscan_snmp':
                if proto == "udp" and self.snmpid:
                    if not self.masscan(self.ip,self.udp,self.snmpid):
                        continue
                else:
                    continue
            flag = True
            #単一値の判定
            for k, v in s['s_data'].items():
                flag = s_match(self.hdr[k],v)
                if not flag:
                    break
            if not flag:
                continue
            #範囲値の判定   
            for k,v in s['r_data'].items():
                flag = r_match(self.hdr[k],v)
                if not flag:
                    break
            if not flag:
                continue
            #複数値の判定
            for k, v in s['m_data'].items():
                flag = m_match(self.hdr[k],v)
                if not flag:
                    break
            if flag:
                self.sig_name,self.ver = s['signature'],s.get('description',None)
                break

class TCPHeader(IPHeader):
    def __init__(self):
        IPHeader.__init__(self)
        self.tcp = None
        self.seq = None
        self.ack = None
        self.sport = None
        self.dport = None
        self.win = None
        self.opts = None
        self.len = None
        self.flags = None

    def set_header(self,ts,ip,tcp):
        IPHeader.set_header(self,ts,ip)
        self.tcp = tcp
        self.seq = tcp.seq
        self.ack = tcp.ack
        self.sport = tcp.sport
        self.dport = tcp.dport
        self.win = tcp.win
        self.opts = binascii.b2a_hex(tcp.opts)
        self.len = len(tcp.data)
        self.flags = tcp_flags(tcp.flags)
        self.hdr.update({'seq':self.seq,'ack':self.ack,'sport':self.sport,'dport':self.dport,'win':self.win,'option':self.opts,'len':self.len})

    def print_result(self,options):
        def print_tcp(ver = None):
            if ver:
                s = '\n| information = %s'%ver
            else:
                s = ''
            str = '''
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff):%s(seq):%s(ack):%s(win)%s
|
---'''
            print str%(print_data,self.ts_date,self.sig_name,self.ipid,self.ttl,self.off,self.seq,self.ack,self.win,s)

        print_data = '[TCP %s] %s:%d -> %s:%d'%(self.flags,self.src_addr,self.sport,self.dst_addr,self.dport)#TCP書式
        if options.line:
            print_line_result(self,print_data,options)
        else:
            if options.verbose:
                print_tcp(self.ver)
            else:
                print_tcp()

class ICMPHeader(IPHeader):
    def __init__(self):
        IPHeader.__init__(self)
        self.icmp = None
        self.icmpid = None
        self.icmpseq = None

    def set_header(self,ts,ip,icmp):
        IPHeader.set_header(self,ts,ip)
        self.icmp = icmp
        self.icmpid = icmp.data.id
        self.icmpseq = icmp.data.seq
        self.hdr.update({'icmpseq':self.icmpseq,'icmpid':self.icmpid})

    def print_result(self,options):
        def print_icmp(ver = None):
            if ver:
                s = '\n| information = %s'%ver
            else:
                s = ''
            str = '''
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff):%s(icmpid):%s(icmpseq)%s
|
---'''
            print str%(print_data,self.ts_date,self.sig_name,self.ipid,self.ttl,self.off,self.icmpid,self.icmpseq,s)
        if self.icmp.type == dpkt.icmp.ICMP_ECHO:
            print_data = '[ICMP Echo Req] %s -> %s'%(self.src_addr,self.dst_addr)#ICMP書式
        elif self.icmp.type == dpkt.icmp.ICMP_ECHOREPLY:
            print_data = '[ICMP Echo Rep] %s -> %s'%(self.src_addr,self.dst_addr)#ICMP書式
        if options.line:
            print_line_result(self,print_data,options)
        else:
            if options.verbose:
                print_icmp(self.ver)
            else:
                print_icmp()

class UDPHeader(IPHeader):
    def __init__(self):
        IPHeader.__init__(self)
        self.udp = None
        self.sport = None
        self.dport = None
        self.ntbid = None
        self.snmpid = None

    def set_header(self,ts,ip,udp):
        IPHeader.set_header(self,ts,ip)
        self.udp = udp
        self.sport = udp.sport
        self.dport = udp.dport
        self.hdr.update({'sport':self.sport,'dport':self.dport})
        if udp.sport == 137 or udp.dport == 137:
            try:
                ntbid = udp.data[0:2]
                ntbid = struct.unpack('>H', ntbid)[0]
                self.ntbid = ntbid
            except struct.error:
                pass
        elif udp.sport == 161 or udp.dport == 161:
            try:
                snmpid = udp.data[17:21]
                snmpid = struct.unpack('>I', snmpid)[0]
                self.snmpid = snmpid
            except struct.error:
                pass

    def print_result(self,options):
        def print_udp(ver = None):
            if ver:
                s = '\n| information = %s'%ver
            else:
                s = ''
            str = '''
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff)%s
|
---'''
            print str%(print_data,self.ts_date,self.sig_name,self.ipid,self.ttl,self.off,s)

        print_data = '[UDP] %s:%d -> %s:%d'%(self.src_addr,self.sport,self.dst_addr,self.dport)#DNS_R書式
        if options.line:
            print_line_result(self,print_data,options)
        else:
            if options.verbose:
                print_udp(self.ver)
            else:
                print_udp()

class DNSHeader(UDPHeader):
    def __init__(self):
        UDPHeader.__init__(self)
        self.dns = None
        self.dnsid = None

    def set_header(self,ts,ip,udp,dns):
        UDPHeader.set_header(self,ts,ip,udp)
        self.dns = dns
        self.dnsid=dns.id
        self.hdr.update({'dnsid':self.dnsid})

    def dns_type(self,dns_t):
        types = {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',13:'HINFO',15:'MX',16:'TXT',28:'AAAA',33:'SRV'}
        dnstype = types.get(dns_t,None)
        return dnstype

    def dns_class(self,dns_c):
        classes = {1:'IN',3:'CHAOS',4:'HESIOD',255:'ANY'}
        dnscls = classes.get(dns_c,None)
        return dnscls

    def print_result(self,options):
        def print_dns(qa,ver = None):
            if ver:
                line_ver = '\n| information = %s'%ver
            else:
                line_ver = ''
            if self.dns.qd and qa:
                line_query = '\n| query:'
                for a in self.dns.qd:
                    line_query += '\n|  %s, type%s, cls%s'%(self.dns.qd[0].name,self.dns_type(self.dns.qd[0].type),self.dns_class(self.dns.qd[0].cls))
            else:
                line_query = ''
            if self.dns.an and qa:
                line_ans = '\n| answer:'
                for q in self.dns.an:
                    line_ans += '\n|  %s: type%s, cls%s => %s'%(q.name,self.dns_type(q.type),self.dns_class(q.cls),socket.inet_ntoa(q.rdata))
            else:
                line_ans = ''
            
            str = '''
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff):%s(dnsid)%s%s%s
|
---'''
            print str%(print_data,self.ts_date,self.sig_name,self.ipid,self.ttl,self.off,self.dnsid,line_query,line_ver,line_ans)
        if self.dns.qr == dpkt.dns.DNS_Q:   #DNS query
            print_data = '[DNS Query] %s:%d -> %s:%d'%(self.src_addr,self.sport,self.dst_addr,self.dport)#DNS_Q書式
        elif  self.dns.qr == dpkt.dns.DNS_R:    #DNS response
            print_data = '[DNS Response] %s:%d -> %s:%d'%(self.src_addr,self.sport,self.dst_addr,self.dport)#DNS_R書式
        else:
            print_data = 'test dns'
        if options.line:
            print_line_result(self,print_data,options)
        else:
            if options.verbose:
                print_dns(options.qa,self.ver)
            else:
                print_dns(options.qa)

#IPヘッダオフセット判定
def ip_off(ip_off):
    off = {0x8000:'RF',0x4000:'DF',0x2000:'MF',0x1fff:'0FFMASK',0x0000:'0'}
    try:
        ipoff = off[ip_off]
    except:
        ipoff = None
    return ipoff
    
def check_signature_file():
#シグネチャファイル確認
    try:
        sig_f=open(SIG_FILE)
    except IOError:
        print 'Error: "%s" cannot be opened.' %SIG_FILE
        sys.exit()
    else:
        sig = json.load(sig_f)
        sig_f.close()
        return sig

#TCPフラグ判定
def tcp_flags(flags):
    ret = ''
    if flags & dpkt.tcp.TH_FIN:
        ret = ret + 'F'
    if flags & dpkt.tcp.TH_SYN:
        ret = ret + 'S'
    if flags & dpkt.tcp.TH_RST:
        ret = ret + 'R'
    if flags & dpkt.tcp.TH_PUSH:
        ret = ret + 'P'
    if flags & dpkt.tcp.TH_ACK:
        ret = ret + '.'
    if flags & dpkt.tcp.TH_URG:
        ret = ret + 'U'
    if flags & dpkt.tcp.TH_ECE:
        ret = ret + 'E'
    if flags & dpkt.tcp.TH_CWR:
        ret = ret + 'C'
    return ret

#単一値の判定
def s_match(obj,s):
    if s != '*':
        if obj == s:
            return True
        else:
            return False
    else:
        return True

#範囲値の判定
def r_match(obj,r):
    if r[0] <= obj <= r[1]:
        return True
    else:
        return False

#複数値の判定
def m_match(obj,m):
    if obj in m:
        return True
    else:
        return False

def packet_parse(options,buf,ts,sig):
#パケット解析
    #try:
    eth = dpkt.ethernet.Ethernet(buf)
    #except:
    #    return
        
    #IP Header
    if type(eth.data) == dpkt.ip.IP:
        ip = eth.data
        ts_date =  datetime.datetime.utcfromtimestamp(ts)

        #TCP Header
        if type(ip.data) == dpkt.tcp.TCP:
            tcp = ip.data
            tcp_h = TCPHeader()
            tcp_h.set_header(ts_date,ip,tcp)
            tcp_h.ptn_match(sig,'tcp')
            tcp_h.ver
            tcp_h.print_result(options)

        #ICMP Header
        if type(ip.data) == dpkt.icmp.ICMP:
            icmp = ip.data
            #ICMP Echo Request
            if type(icmp.data) == dpkt.icmp.ICMP.Echo:
                if icmp.type == dpkt.icmp.ICMP_ECHO or icmp.type == dpkt.icmp.ICMP_ECHOREPLY:
                    icmp_h = ICMPHeader()
                    icmp_h.set_header(ts_date,ip,icmp)
                    icmp_h.ptn_match(sig,'icmp')
                    icmp_h.print_result(options)

        #UDP Header
        if type(ip.data) == dpkt.udp.UDP:
            udp = ip.data       
            #DNS
            if udp.sport == 53 or udp.dport == 53:
                try:
                    dns = dpkt.dns.DNS(udp.data)
                    dns_h = DNSHeader()
                    dns_h.set_header(ts_date,ip,udp,dns)
                    dns_h.ptn_match(sig,'dns')
                    dns_h.print_result(options)
                    return
                except:
                    #broken DNS or not DNS packet
                    pass
            #UDP
            udp_h = UDPHeader()
            udp_h.set_header(ts_date,ip,udp)
            udp_h.ptn_match(sig,'udp')
            udp_h.print_result(options)

def main():
    #BrokenPipeエラーを表示しない
    signal(SIGPIPE,SIG_DFL) 
    #keyboadinterrupt
    signal(SIGINT, SIG_DFL)
    
    #オプション設定
    usage = 'usage: %prog [options] file'
    version = '2.0'
    
    parser = OptionParser(usage=usage,version=version)

    #入力ファイルチェック
    def check_file(option, opt, value, parser):
        if os.path.isfile(value):
            parser.values.file = value
        else:
            raise OptionValueError('option -r: "%s" was not found' % value)

    #入力ファイル
    parser.add_option(
        '-r', 
        action='callback',
        callback=check_file,
        type='string',
        dest='file',
        #default='./',
        help='read packets from file'
        )
    #詳細表示
    parser.add_option(
       '-v','--verbose',
        action='store_true',
        dest='verbose',
        default=False,
        help='print verbose output'
        )
    #一行表示
    parser.add_option(
        '-l', '--line',
        action='store_true',
        dest='line',
        default=False,
        help='print single line'
        )
    #時間表示
    parser.add_option(
        '-t', '--time',
        action='store_true',
        dest='time',
        default=False,
        help='print time'
        )
    #シグネチャアップデート
    parser.add_option(
        '-u', '--update',
        action='store_true',
        dest='update',
        default=False,
        help='update signature'
        )
    '''parser.set_defaults(
        file - './'
    )'''
    #DNS表示
    parser.add_option(
        '-q',
        action='store_true',
        dest='qa',
        default=False,
        help='print dns query and answer'
        )
    #入力NIC
    parser.add_option(
        '-i', 
        action='store',
        type='string',
        dest='dev',
        default=None,
        help='listen on interface'
        )

    options,args = parser.parse_args() #オプションのパース

    #シグネチャアップデート
    if options.update:
        while True:
            try:
                i = raw_input('Do you want to update the signature? [yes/no]: ')
            except KeyboardInterrupt:
                return False
            if i.lower() in ('yes','y'): 
                print 'connecting to the server...' 
                break
            elif i.lower() in ('no','n'): 
                sys.exit()
        
        print 'signature file <%s> was downloaded'%SIG_URL
        sig = check_signature_file()
        try:
            f = urllib2.urlopen(SIG_URL,timeout=10)
        except:
            print 'Error: cannot connect to the server'
            sys.exit()
        down_sig = json.load(f)
        if down_sig['version']['version'] > sig['version']['version']:
        #シグネチャバージョン確認
            with open(SIG_FILE,'w') as new_sig_f:
                f2 = urllib2.urlopen(SIG_URL)
                new_sig_f.write(f2.read())
                print 'Signature update was completed. <signature version: %s>'%down_sig['version']['version']
        else:
            print 'This signature file is the latest version.'
    else:
        sig = check_signature_file()
        if options.dev:
            p = pcapy.open_live(options.dev, 65536, True, 100)
            while(True):
                try:
                    ts = time.time()
                    (header,data) = p.next()
                    packet_parse(options,data,ts,sig) #pcapをパース、パターンマッチング
                except pcapy.PcapError:
                    continue


        else:
            if not options.file:
                parser.error('file is required')
                sys.exit()
            pcap_f=open(options.file,'rb')
            try:
                pcap = dpkt.pcap.Reader(pcap_f)
                for ts,buf in pcap:
                    packet_parse(options,buf,ts,sig) #pcapをパース、パターンマッチング
            except ValueError as e:
                print 'Error: unknown file format'
                print e
                sys.exit()

if __name__ == '__main__':
    main()
