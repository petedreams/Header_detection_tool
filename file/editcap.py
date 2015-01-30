#!/usr/bin/env python
# -*- coding: utf-8 -*-

#20150128
#editcap.py
#pcapを時間分割
#使い方 ./editcap.py <infile> <outfile> <sec>

import os,sys,dpkt,datetime,time

def writefilepath(d,outfile,counter):
    timestr=d.strftime("%Y%m%d%H%M%S")
    path, outfilename = os.path.split(outfile)
    name, ext = os.path.splitext(outfilename)
    writefile=path+'/'+name+'_'+str(counter).zfill(5)+'_'+timestr+ext
    return writefile

def editcap(infile,outfile,sp):
#pcap読み込み
    s_time=None#基準時間
    counter=0
    f= open(infile,'rb')
    pcap = dpkt.pcap.Reader(f)
    try:
        for ts,buf in pcap:
            writedflag=True
            eth = dpkt.ethernet.Ethernet(buf)
            if not s_time:
                init_d = datetime.datetime.fromtimestamp(int(ts))#mirosecond切り捨て
                writefile = writefilepath(init_d,outfile,counter)
                f=open(writefile,'wb')
                writefile = dpkt.pcap.Writer(open(writefile,'wb'))
                writefile.writepkt(eth,ts)
                s_time = int(ts)
                g_time = s_time+sp
                counter+=1
            elif ts < g_time:
                pass
                writefile.writepkt(eth,ts)
            elif g_time <= ts:
                if ts < g_time+sp:
                    d = datetime.datetime.fromtimestamp(g_time)
                    writefile = writefilepath(d,outfile,counter)
                    writefile = dpkt.pcap.Writer(open(writefile,'wb'))
                    writefile.writepkt(eth,ts)
                    g_time += sp
                    counter+=1
                else:
                    while writedflag:
                        d = datetime.datetime.fromtimestamp(g_time)
                        writefile = writefilepath(d,outfile,counter)
                        writefile = dpkt.pcap.Writer(open(writefile,'wb'))
                        g_time+=sp
                        counter+=1
                        if g_time+sp <= ts:
                            continue
                        else:
                            d = datetime.datetime.fromtimestamp(g_time)
                            writefile = writefilepath(d,outfile,counter)
                            writefile = dpkt.pcap.Writer(open(writefile,'wb'))
                            g_time+=sp
                            counter+=1
                            writefile.writepkt(eth,ts)
                            writedflag=False
    except:
        pass

if __name__ == '__main__':
    try:
        infile = sys.argv[1]
        outfile = sys.argv[2]
        sp = int(sys.argv[3])
        editcap(infile,outfile,sp)
    except IOError:
        print '[IOError] usage: editcap.py <infile> <outfile> <sec>'
