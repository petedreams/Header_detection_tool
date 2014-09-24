#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Header_detection_tool.py
#pcapを読み込んでパターンマッチング
#使い方 ./detect_tool.py *.pcap

from optparse import OptionParser, OptionValueError
import os,sys,dpkt,socket,json,binascii

SIG_FILE="signature.json"

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
            if k == "flags":
                flag = s_match(ip.off,v)
            if k == "seq":
                flag = s_match(tcp.seq,v)
            if k == "ack":
                flag = s_match(tcp.ack,v)
            if k == "sport":
                flag = s_match(tcp.sport,v)
            if k == "dport":
                flag = s_match(tcp.dport,v)
            if k == "win":
                flag = s_match(tcp.win,v)
            if k == "option":
                tcp_option = binascii.b2a_hex(tcp.opts)
                #dpkt.tcp.parse_opts(tcp.opts)
                sig_option = v
                flag = s_match(tcp_option,sig_option)
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
            if not flag:
                break
        if flag:
            return s["signature"]
        else:
            return false

def pattern_match_icmp():
    pass

def packet_parse(filepath):
    
    pcap_f=open(filepath)
    pcap = dpkt.pcap.Reader(pcap_f)
    
    #シグネチャファイル確認
    try:
        sig_f=open(SIG_FILE)
    except IOError:
        print 'Error : "%s" cannot be opened.' %SIG_FILE
        sys.exit()
    else:
        sig = json.load(sig_f)
        sig_f.close()
        
    for ts,buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue
        
        #IP Header
        if type(eth.data) == dpkt.ip.IP:
            ip = eth.data
            
            #TCP Header
            if type(ip.data) == dpkt.tcp.TCP:
                tcp = ip.data
                if tcp.flags!=2:#SYN flag
                    continue
                print "header:",(ip.id,ip.ttl,ip.off,tcp.seq,tcp.ack,tcp.sport,tcp.dport,tcp.win,tcp.opts)
                sig_name = pattern_match_tcp(ip,tcp,sig) #パターンマッチング
                if sig_name:
                    print "signame,",sig_name
                #signature(ip,tcp,src_addr,dst_addr)
                
            #UDP Header
            if type(ip.data) == dpkt.udp.UDP:
                udp = ip.data
                
            #ICMP Header
            if type(ip.data) == dpkt.icmp.ICMP:
                icmp = ip.data
                #ICMP Echo Request
                if type(icmp.data) == dpkt.icmp.ICMP.Echo:
                    print "aaaaaaaaa",icmp.data.id
    pcap_f.close()

if __name__ == '__main__':
    
    #オプション設定
    usage = "usage: %prog [options] keyword"
    version = "1.0"
    
    parser = OptionParser(usage=usage,version=version)

    #入力ファイルチェック
    def check_file(option, opt, value, parser):
        if os.path.isfile(value):
            parser.values.filepath = value
        else:
            raise OptionValueError("option -f: '%s' was not found" % value)

    parser.add_option(
        "-f", "--file", 
        action="callback",
        callback=check_file,
        type="string",
        dest="filepath",
        #default="./",
        help="filepath"
        )
    parser.add_option(
        "-x", "--VirusTotal",
        action="store_true",
        dest="vt",
        default=False,
        help="VirusTotal"
        )

    (options,args) = parser.parse_args() #オプションのパース
    packet_parse(options.filepath) #pcapをパース、パターンマッチング
