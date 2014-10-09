#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Header_detection_tool.py
#pcapを読み込んでパターンマッチング
#使い方 ./detect_tool.py *.pcap

from optparse import OptionParser, OptionValueError
import os,sys,dpkt,socket,json,binascii,datetime

SIG_FILE="signature.json"

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

#TCPパケットのマッチング
def pattern_match_tcp(ip,tcp,sig):
    #シグネチャを1つずつ調査
    for s in sig["tcp"]:
        flag = True
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
                #print dpkt.tcp.parse_opts(tcp.opts)
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
            return s["signature"]
        else:
            return False

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
            return s["signature"]
        else:
            return False

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
            return s["signature"]
        else:
            return False

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
            return s["signature"]
        else:
            return False

def print_line_result(print_data,options,ts_date,sig_name):
    if not sig_name:
        sig_name = "None"
    if options.time:
        print "%s %s [%s]"%(ts_date,print_data,sig_name)
    else:
        print "%s [%s]"%(print_data,sig_name)

def ip_off(ip_off):
    off = {0x8000:"RF",0x4000:"DF",0x2000:"MF",0x1fff:"0FFMASK",0x0000:"0"}
    try:
        ipoff = off[ip_off]
    except:
        ipoff = None
    return ipoff
    
def dns_type(dns_t):
    t = {1:"DNS_A",2:"DNS_NS",5:"DNS_CNAME",6:"DNS_SOA",12:"DNS_PTR",13:"DNS_HINFO",15:"DNS_MX",16:"DNS_TXT",28:"DNS_AAAA",33:"DNS_SRV"}
    try:
        dnstype = t[dns_t]
    except:
        dnstype = None
    return dnstype

def print_tcp_result(print_data,ts_date,ip,tcp,sig_name):
    ipoff = ip_off(ip.off)
    str = """
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff):%s(seq):%s(ack):%s(win)
|
---"""
    print str%(print_data,ts_date,sig_name,ip.id,ip.ttl,ipoff,tcp.seq,tcp.ack,tcp.win)

def print_icmp_result(print_data,ts_date,ip,icmp,sig_name):
    ipoff = ip_off(ip.off)
    str = """
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff):%s(icmpid):%s(icmpseq)
|
---"""
    print str%(print_data,ts_date,sig_name,ip.id,ip.ttl,ipoff,icmp.id,icmp.seq)
    
def print_dns_result(print_data,ts_date,ip,udp,dns,sig_name):
    ipoff = ip_off(ip.off)
    dnstype = dns_type(dns.qd[0].type)
    str = """
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff):%s(dnsid)
| type = %s
| name = %s
|
---"""
    print str%(print_data,ts_date,sig_name,ip.id,ip.ttl,ipoff,dns.id,dnstype,dns.qd[0].name)

def print_udp_result(print_data,ts_date,ip,udp,sig_name):
    ipoff = ip_off(ip.off)
    str = """
<< %s >>
|
| date       = %s
| signature  = %s
| parameters = %s(ipid):%s(ttl):%s(ipoff)
|
---"""
    print str%(print_data,ts_date,sig_name,ip.id,ip.ttl,ipoff)

def packet_parse(options):
    
    pcap_f=open(options.filepath)
    try:
        pcap = dpkt.pcap.Reader(pcap_f)
    except:
        print "Error: unknown file format"
        sys.exit()
    
    #シグネチャファイル確認
    try:
        sig_f=open(SIG_FILE)
    except IOError:
        print 'Error: "%s" cannot be opened.' %SIG_FILE
        sys.exit()
    else:
        sig = json.load(sig_f)
        sig_f.close()
        
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
                sig_name = pattern_match_tcp(ip,tcp,sig) #パターンマッチング
                print_data = "[TCP %s] %s:%d -> %s:%d"%(flags,src_addr,tcp.sport,dst_addr,tcp.dport)#TCP書式
                #オプションの16進数表示print binascii.b2a_hex(tcp.opts)
                if options.line:
                    print_line_result(print_data,options,ts_date,sig_name)
                else:
                    print_tcp_result(print_data,ts_date,ip,tcp,sig_name)
            #UDP Header
            if type(ip.data) == dpkt.udp.UDP:
                udp = ip.data       
                #DNS Query
                dns = dpkt.dns.DNS(udp.data)
                if udp.dport == 53:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.opcode == dpkt.dns.DNS_QUERY:#DNS query
                        #print dns.qd[0].name
                        print_data = "[DNS Query] %s:%d -> %s:%d"%(src_addr,udp.sport,dst_addr,udp.dport)#DNS_Q書式
                        sig_name = pattern_match_dns(ip,udp,dns,sig)
                    if options.line:
                        print_line_result(print_data,options,ts_date,sig_name)
                    else:
                        print_dns_result(print_data,ts_date,ip,udp,dns,sig_name)
                #DNS Response
                elif udp.sport ==53:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.qr == dpkt.dns.DNS_R:#DNS response
                        print_data = "[DNS Response] %s:%d -> %s:%d"%(src_addr,udp.sport,dst_addr,udp.dport)#DNS_R書式
                        sig_name = pattern_match_dns(ip,udp,dns,sig)
                    if options.line:
                        print_line_result(print_data,options,ts_date,sig_name)
                    else:
                        print_dns_result(print_data,ts_date,ip,udp,dns,sig_name)
                #UDP
                else:
                    sig_name = pattern_match_udp(ip,udp,sig)
                    print_data = "[UDP] %s:%d -> %s:%d"%(src_addr,udp.sport,dst_addr,udp.dport)#DNS_R書式
                    if options.line:
                        print_line_result(print_data,options,ts_date,sig_name)
                    else:
                        print_udp_result(print_data,ts_date,ip,udp,sig_name)
            #ICMP Header
            if type(ip.data) == dpkt.icmp.ICMP:
                icmp = ip.data
                #ICMP Echo Request
                if type(icmp.data) == dpkt.icmp.ICMP.Echo:
                    sig_name = pattern_match_icmp(ip,icmp.data,sig) #パターンマッチング
                    print_data = "[ICMP Echo Req] %s -> %s"%(src_addr,dst_addr)#ICMP書式
                    icmp_data = icmp.data
                    if options.line:
                        print_line_result(print_data,options,ts_date,sig_name)
                    else:
                        print_icmp_result(print_data,ts_date,ip,icmp_data,sig_name)

    pcap_f.close()

if __name__ == '__main__':
    
    #オプション設定
    usage = "usage: %prog [options] file"
    version = "1.0"
    
    parser = OptionParser(usage=usage,version=version)

    #入力ファイルチェック
    def check_file(option, opt, value, parser):
        if os.path.isfile(value):
            parser.values.filepath = value
        else:
            raise OptionValueError("option -f: '%s' was not found" % value)

    #入力ファイル
    parser.add_option(
        "-r", "--file", 
        action="callback",
        callback=check_file,
        type="string",
        dest="filepath",
        #default="./",
        help="filepath"
        )
    #VirusTotal結果
    parser.add_option(
        "-v", "--VirusTotal",
        action="store_true",
        dest="vt",
        default=False,
        help="VirusTotal"
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
        help="print single line"
        )
    """parser.set_defaults(
        filepath - "./"
    )"""

    options,args = parser.parse_args() #オプションのパース
    if not options.filepath:
        #print usage
        parser.error("file is required")
        #parser.print_help()
        sys.exit()
    else:
        packet_parse(options) #pcapをパース、パターンマッチング
