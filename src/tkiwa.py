#!/usr/bin/env python
# -*- coding: utf-8 -*-

#tkiwa.py
"""Malicious Packet detection tool with protocol header."""

from optparse import OptionParser, OptionValueError
from signal import signal, SIGPIPE, SIG_DFL
import os,sys,dpkt,socket,json,datetime,binascii,urllib2,ctypes

SCRIPT_DIR=os.path.abspath(os.path.dirname(__file__))
SIG_FILE=os.path.join(SCRIPT_DIR,"..","data","signature.json")
SIG_URL = "http://ipsr.ynu.ac.jp/tkiwa/download/signature.json"

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
    if s != "*":
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

def masscan(ip,tcp):
    addr_10 = int(binascii.b2a_hex(ip.dst),16)
    cal= addr_10^tcp.dport^tcp.seq
    if ctypes.c_ushort(cal).value==ip.id:
        return True

#TCPヘッダのマッチング
def pattern_match_tcp(ip,tcp,sig):
    #シグネチャを1つずつ調査
    for s in sig["tcp"]:
        flag = True
        if s["signature"]=="masscan":
            if not masscan(ip,tcp):
                continue
        #単一値の判定
        for k, v in s["s_data"].items():
            if k == "ipid":
                flag = s_match(ip.id,v)
            elif k == "flags":
                flag = s_match(ip.off,v)
            elif k == "seq":
                flag = s_match(tcp.seq,v)
            elif k == "ack":
                flag = s_match(tcp.ack,v)
            elif k == "sport":
                flag = s_match(tcp.sport,v)
            elif k == "dport":
                flag = s_match(tcp.dport,v)
            elif k == "win":
                flag = s_match(tcp.win,v)
            elif k == "option":
                tcp_option = binascii.b2a_hex(tcp.opts)
                sig_option = v
                flag = s_match(tcp_option,sig_option)
            elif k == "len":
                flag = s_match(len(tcp.data),v)
            if not flag:
                break
        if not flag:
            continue
        #範囲値の判定   
        for k,v in s["r_data"].items():
            if k == "ipid":
                flag = r_match(ip.id,v)
            if k == "ttl":
                flag = r_match(ip.ttl,v)
            if k == "seq":
                flag = r_match(tcp.seq,v)
            if k == "ack":
                flag = r_match(tcp.ack,v)
            if k == "sport":
                flag = r_match(tcp.sport,v)
            if k == "dport":
                flag = r_match(tcp.dport,v)
            if k == "win":
                flag = r_match(tcp.win,v)
            if k == "len":
                flag = r_match(len(tcp.data),v)
            if not flag:
                break
        if not flag:
            continue
        #複数値の判定
        for k, v in s["m_data"].items():
            if k == "ipid":
                flag = m_match(ip.id,v)
            if k == "flags":
                flag = m_match(tcp.flags,v)
            if k == "seq":
                flag = m_match(tcp.seq,v)
            if k == "ack":
                flag = m_match(tcp.ack,v)
            if k == "sport":
                flag = m_match(tcp.sport,v)
            if k == "dport":
                flag = m_match(tcp.dport,v)
            if k == "win":
                flag = m_match(tcp.win,v)
            if k == "option":
                flag = m_match(tcp.opts,v)
            if k == "len":
                flag = m_match(len(tcp.data),v)
            if not flag:
                break
        if flag:
            return s["signature"],s.get("description","")
        else:
            return None,''
    return None,''

#ICMPヘッダのマッチング
def pattern_match_icmp(ip,icmp,sig):
    for s in sig["icmp"]:
        flag = True
        #単一値の判定
        for k, v in s["s_data"].items():
            if k == "ipid":
                flag = s_match(ip.id,v)
            if k == "off":
                flag = s_match(ip.off,v)
            if k == "icmpid":
                flag = s_match(icmp.id,v)
            if k == "icmpseq":
                flag = s_match(icmp.seq,v)
            if not flag:
                break
        if not flag:
            continue
        #範囲値の判定
        for k, v in s["r_data"].items():
            if k == "ipid":
                flag = r_match(ip.id,v)
            if k == "off":
                flag = r_match(ip.off,v)
            if k == "ttl":
                flag = r_match(ip.ttl,v)
            if k == "icmpid":
                flag = r_match(icmp.id,v)
            if k == "icmpseq":
                flag = r_match(icmp.seq,v)
            if not flag:
                break
        if not flag:
            continue
        #複数値の判定
        for k, v in s["m_data"].items():
            if k == "ipid":
                flag = m_match(ip.id,v)
            if k == "off":
                flag = m_match(ip.off,v)
            if k == "icmpid":
                flag = m_match(icmp.id,v)
            if k == "icmpseq":
                flag = m_match(icmp.seq,v)
            if not flag:
                break
        if flag:
            return s["signature"],s.get("description","")
        else:
            return None,''
    return None,''

#DNS・UDPヘッダのマッチング
def pattern_match_dns(ip,udp,dns,sig):
    for s in sig["dns"]:
        flag = True
        #単一値の判定
        for k, v in s["s_data"].items():
            if k == "ipid":
                flag = s_match(ip.id,v)
            if k == "off":
                flag = s_match(ip.off,v)
            if k == "sport":
                flag = s_match(udp.sport,v)
            if k == "dport":
                flag = s_match(udp.dport,v)
            if k == "dnsid":
                flag = s_match(dns.id,v)
            if not flag:
                break
        if not flag:
            continue
        #範囲値の判定
        for k, v in s["r_data"].items():
            if k == "ipid":
                flag = r_match(ip.id,v)
            if k == "off":
                flag = r_match(ip.off,v)
            if k == "ttl":
                flag = r_match(ip.ttl,v)
            if k == "sport":
                flag = r_match(udp.sport,v)
            if k == "dport":
                flag = r_match(udp.dport,v)
            if k == "dnsid":
                flag = r_match(dns.id,v)
            if not flag:
                break
        if not flag:
            continue
        #複数値の判定
        for k, v in s["m_data"].items():
            if k == "ipid":
                flag = m_match(ip.id,v)
            if k == "off":
                flag = m_match(ip.off,v)
            if k == "sport":
                flag = m_match(udp.sport,v)
            if k == "dport":
                flag = m_match(udp.dport,v)
            if k == "dnsid":
                flag = m_match(dns.id,v)
            if not flag:
                break
        if flag:
            return s["signature"],s.get("description","")
        else:
            return None,''
    return None,''

#UDPヘッダのマッチング
def pattern_match_udp(ip,udp,sig):
    for s in sig["udp"]:
        flag = True
        #単一値の判定
        for k, v in s["s_data"].items():
            if k == "ipid":
                flag = s_match(ip.id,v)
            if k == "off":
                flag = s_match(ip.off,v)
            if k == "sport":
                flag = s_match(udp.sport,v)
            if k == "dport":
                flag = s_match(udp.dport,v)
            if not flag:
                break
        if not flag:
            continue
        #範囲値の判定
        for k, v in s["r_data"].items():
            if k == "ipid":
                flag = r_match(ip.id,v)
            if k == "off":
                flag = r_match(ip.off,v)
            if k == "ttl":
                flag = r_match(ip.ttl,v)
            if k == "sport":
                flag = r_match(udp.sport,v)
            if k == "dport":
                flag = r_match(udp.dport,v)
            if not flag:
                break
        if not flag:
            continue
        #複数値の判定
        for k, v in s["m_data"].items():
            if k == "ipid":
                flag = m_match(ip.id,v)
            if k == "off":
                flag = m_match(ip.off,v)
            if k == "sport":
                flag = m_match(udp.sport,v)
            if k == "dport":
                flag = m_match(udp.dport,v)
            if not flag:
                break
        if flag:
            return s["signature"],s.get("description","")
        else:
            return None,''
    return None,''

#一行出力
def print_line_result(print_data,options,ts_date,sig_name):
    if not sig_name:
        sig_name = "None"
    if options.time:
        print "%s %s [%s]"%(ts_date,print_data,sig_name)
    else:
        print "%s [%s]"%(print_data,sig_name)

#IPヘッダオフセット判定
def ip_off(ip_off):
    off = {0x8000:"RF",0x4000:"DF",0x2000:"MF",0x1fff:"0FFMASK",0x0000:"0"}
    try:
        ipoff = off[ip_off]
    except:
        ipoff = None
    return ipoff
    
#DNS type判定
def dns_type(dns_t):
    t = {1:"DNS_A",2:"DNS_NS",5:"DNS_CNAME",6:"DNS_SOA",12:"DNS_PTR",13:"DNS_HINFO",15:"DNS_MX",16:"DNS_TXT",28:"DNS_AAAA",33:"DNS_SRV"}
    try:
        dnstype = t[dns_t]
    except:
        dnstype = None
    return dnstype

#TCP出力
def print_tcp_result(print_data,ts_date,ip,tcp,sig_name,ver=None):
    ipoff = ip_off(ip.off)
    if ver:
        s = "\n| information = %s"%ver
    else:
        s = ""
    str = """
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff):%s(seq):%s(ack):%s(win)%s
|
---"""
    print str%(print_data,ts_date,sig_name,ip.id,ip.ttl,ipoff,tcp.seq,tcp.ack,tcp.win,s)

#ICMP出力
def print_icmp_result(print_data,ts_date,ip,icmp,sig_name,ver=None):
    ipoff = ip_off(ip.off)
    if ver:
        s = "\n| information = %s"%ver
    else:
        s = ""
    str = """
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff):%s(icmpid):%s(icmpseq)%s
|
---"""
    print str%(print_data,ts_date,sig_name,ip.id,ip.ttl,ipoff,icmp.id,icmp.seq,s)
    
#DNS出力
def print_dns_result(print_data,ts_date,ip,udp,dns,sig_name,ver=None):
    ipoff = ip_off(ip.off)
    try:
        dnstype = dns_type(dns.qd[0].type)
    except:
        dnstype = None

    try:
        dnsname = dns.qd[0].name
    except:
        dnsname = None

    if ver:
        s = "\n| information = %s"%ver
    else:
        s = ""
    str = """
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff):%s(dnsid)
| type = %s
| name = %s%s
|
---"""
    print str%(print_data,ts_date,sig_name,ip.id,ip.ttl,ipoff,dns.id,dnstype,dnsname,s)

#UDP出力
def print_udp_result(print_data,ts_date,ip,udp,sig_name,ver=None):
    ipoff = ip_off(ip.off)
    if ver:
        s = "\n| information = %s"%ver
    else:
        s = ""
    str = """
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff)%s
|
---"""
    print str%(print_data,ts_date,sig_name,ip.id,ip.ttl,ipoff,s)

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

def packet_parse(options):
#パケット解析
    pcap_f=open(options.file)
    try:
        pcap = dpkt.pcap.Reader(pcap_f)
    except:
        print "Error: unknown file format"
        sys.exit()
    
    sig = check_signature_file()
        
    for ts,buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue
            
        sig_name = False #検知結果のリセット

        #IP Header
        if type(eth.data) == dpkt.ip.IP:
            ip = eth.data
            src_addr=socket.inet_ntoa(ip.src)
            dst_addr=socket.inet_ntoa(ip.dst)
            ts_date =  datetime.datetime.utcfromtimestamp(ts)
            
            #TCP Header
            if type(ip.data) == dpkt.tcp.TCP:
                tcp = ip.data
                flags =  tcp_flags(tcp.flags)
                sig_name,ver = pattern_match_tcp(ip,tcp,sig) #パターンマッチング
                print_data = "[TCP %s] %s:%d -> %s:%d"%(flags,src_addr,tcp.sport,dst_addr,tcp.dport)#TCP書式
                #オプションの16進出力print binascii.b2a_hex(tcp.opts)
                if options.line:
                    print_line_result(print_data,options,ts_date,sig_name)
                else:
                    if options.verbose:
                        print_tcp_result(print_data,ts_date,ip,tcp,sig_name,ver)
                    else:
                        print_tcp_result(print_data,ts_date,ip,tcp,sig_name)
            #UDP Header
            if type(ip.data) == dpkt.udp.UDP:
                udp = ip.data       
                #DNS Query
                if udp.dport == 53:
                    try:
                        dns = dpkt.dns.DNS(udp.data)
                    except:
                        print "broken DNS packet"
                    if dns.opcode == dpkt.dns.DNS_QUERY:#DNS query
                        print_data = "[DNS Query] %s:%d -> %s:%d"%(src_addr,udp.sport,dst_addr,udp.dport)#DNS_Q書式
                        sig_name,ver = pattern_match_dns(ip,udp,dns,sig)
                    if options.line:
                        print_line_result(print_data,options,ts_date,sig_name)
                    else:
                        if options.verbose:
                            print_dns_result(print_data,ts_date,ip,udp,dns,sig_name,ver)
                        else:
                            print_dns_result(print_data,ts_date,ip,udp,dns,sig_name)
                #DNS Response
                elif udp.sport ==53:
                    try:
                        dns = dpkt.dns.DNS(udp.data)
                    except:
                        print "broken DNS packet"
                    if dns.qr == dpkt.dns.DNS_R:#DNS response
                        print_data = "[DNS Response] %s:%d -> %s:%d"%(src_addr,udp.sport,dst_addr,udp.dport)#DNS_R書式
                        sig_name,ver = pattern_match_dns(ip,udp,dns,sig)
                    if options.line:
                        print_line_result(print_data,options,ts_date,sig_name)
                    else:
                        if options.verbose:
                            print_dns_result(print_data,ts_date,ip,udp,dns,sig_name,ver)
                        else:
                            print_dns_result(print_data,ts_date,ip,udp,dns,sig_name)
                #UDP
                else:
                    sig_name,ver = pattern_match_udp(ip,udp,sig)
                    print_data = "[UDP] %s:%d -> %s:%d"%(src_addr,udp.sport,dst_addr,udp.dport)#DNS_R書式
                    if options.line:
                        print_line_result(print_data,options,ts_date,sig_name)
                    else:
                        if options.verbose:
                            print_udp_result(print_data,ts_date,ip,udp,sig_name,ver)
                        else:
                            print_udp_result(print_data,ts_date,ip,udp,sig_name)
            #ICMP Header
            if type(ip.data) == dpkt.icmp.ICMP:
                icmp = ip.data
                #ICMP Echo Request
                if type(icmp.data) == dpkt.icmp.ICMP.Echo:
                    sig_name,ver = pattern_match_icmp(ip,icmp.data,sig) #パターンマッチング
                    if icmp.type == dpkt.icmp.ICMP_ECHO:
                        print_data = "[ICMP Echo Req] %s -> %s"%(src_addr,dst_addr)#ICMP書式
                    if icmp.type == dpkt.icmp.ICMP_ECHOREPLY:
                        print_data = "[ICMP Echo Rep] %s -> %s"%(src_addr,dst_addr)#ICMP書式
                    icmp_data = icmp.data
                    if options.line:
                        print_line_result(print_data,options,ts_date,sig_name)
                    else:
                        if options.verbose:
                            print_icmp_result(print_data,ts_date,ip,icmp_data,sig_name,ver)
                        else:
                            print_icmp_result(print_data,ts_date,ip,icmp_data,sig_name)
    pcap_f.close()

def main():
    #BrokenPipeエラーを表示しない
    signal(SIGPIPE,SIG_DFL) 
    
    #オプション設定
    usage = "usage: %prog [options] file"
    version = "1.0.1"
    
    parser = OptionParser(usage=usage,version=version)

    #入力ファイルチェック
    def check_file(option, opt, value, parser):
        if os.path.isfile(value):
            parser.values.file = value
        else:
            raise OptionValueError("option -r: '%s' was not found" % value)

    #入力ファイル
    parser.add_option(
        "-r", 
        action="callback",
        callback=check_file,
        type="string",
        dest="file",
        #default="./",
        help="read packets from file"
        )
    #詳細表示
    parser.add_option(
       "-v","--verbose",
        action="store_true",
        dest="verbose",
        default=False,
        help="print verbose output"
        )
    #一行表示
    parser.add_option(
        "-l", "--line",
        action="store_true",
        dest="line",
        default=False,
        help="print single line"
        )
    #時間表示
    parser.add_option(
        "-t", "--time",
        action="store_true",
        dest="time",
        default=False,
        help="print time"
        )
    #シグネチャアップデート
    parser.add_option(
        "-u", "--update",
        action="store_true",
        dest="update",
        default=False,
        help="update signature"
        )
    """parser.set_defaults(
        file - "./"
    )"""

    options,args = parser.parse_args() #オプションのパース

    #シグネチャアップデート
    if options.update:
        while True:
            try:
                i = raw_input("Do you want to update the signature? [yes/no]: ")
            except KeyboardInterrupt:
                return False
            if i.lower() in ('yes','y'): 
                print "connecting to the server..." 
                break
            elif i.lower() in ('no','n'): 
                sys.exit()
        
        print "signature file <%s> was downloaded"%SIG_URL
        sig = check_signature_file()
        try:
            f = urllib2.urlopen(SIG_URL,timeout=10)
        except:
            print "Error: cannot connect to the server"
            sys.exit()
        down_sig = json.load(f)
        if down_sig["version"]["version"] > sig["version"]["version"]:
        #シグネチャバージョン確認
            with open(SIG_FILE,"w") as new_sig_f:
                f2 = urllib2.urlopen(SIG_URL)
                new_sig_f.write(f2.read())
                print "Signature update was completed. <signature version: %s>"%down_sig["version"]["version"]
        else:
            print "This signature file is the latest version."
    elif not options.file:
        parser.error("file is required")
        sys.exit()
    else:
        packet_parse(options) #pcapをパース、パターンマッチング


if __name__ == '__main__':
    main()

