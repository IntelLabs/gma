//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : Header.h

#pragma once
#ifndef _HEADER_H
#define _HEADER_H

#include <cstdint>
#include <string>

#if defined(__unix__) || defined(__APPLE__)
typedef int GMASocket;
#define GMA_INVALID_SOCKET -1

#elif defined(_WIN32) || defined(_WIN64) 
#include <WinSock2.h>
#include <WS2tcpip.h>
typedef SOCKET GMASocket;
#define GMA_INVALID_SOCKET INVALID_SOCKET
#endif


class GMAMessageHeader
{

private:
    unsigned char *mData;
    int mOffset;

public:
    GMAMessageHeader();
    void init(unsigned char *buf, int offset);
    void setGMAMessageHeader(short flag);
    void setGmaClientId(short id);
    unsigned char getFlow();
};

class GMADataHeader
{

private:
    unsigned char *mData;
    int mOffset;

public:
    GMADataHeader();
    void init(unsigned char *buf, int offset);
    void setUlParams(short flag, unsigned char flowID, unsigned char ppp, int timeStamp, int gSN);
    short getFlag();
    int getDlClientId();
    short getDlFlowId();
    short getDlPpp();
    short getDlLSeqNum();
    int getDlGSeqNum();
    int getDlTimeStampMillis();
    unsigned char *getPacket();
};

class IPHeader
{
public:
    static const unsigned char ICMP = 1;
    static const unsigned char TCP = 6;
    static const unsigned char UDP = 17;

    static const unsigned char offset_ver_ihl = 0;  
    static const unsigned char offset_tos = 1;      
    static const short offset_len = 2;              
    static const short offset_id = 4;               
    static const short offset_off = 6;              
    static const unsigned char offset_ttl = 8;      
    static const unsigned char offset_protocol = 9; 
    static const short offset_sum = 10;             
    static const int offset_src_ip = 12;            
    static const int offset_dest_ip = 16;           
    static const int offset_dest_port = 2;
    static const int offset_op_pad = 20; 

    unsigned char *mData;
    int mOffset;

    IPHeader();
    void init(unsigned char *data, int offset);
    int getDataLength();
    int getVersion();
    int getHeaderLength();
    void setHeaderLength(int value);
    unsigned char getTos();
    void setTos(unsigned char value);
    int getTotalLength();
    void setTotalLength(int value);
    int getIdentification();
    void setIdentification(int value);
    short getFlagsAndOffset();
    void setFlagsAndOffset(short value);
    unsigned char getTTL();
    void setTTL(unsigned char value);
    unsigned char getProtocol();
    void setProtocol(unsigned char value);
    short getSum();
    void setSum(short value);
    int getSourceIP();
    void setSourceIP(int value);
    int getDestinationIP();
    void setDestinationIP(int value);
    int getDestinationPort();

    static short readShort(unsigned char *data, int offset);
    static void writeShort(unsigned char *data, int offset, short value);
    static int readInt(unsigned char *data, int offset);
    static void writeInt(unsigned char *data, int offset, int value);
    static int ipStringToInt(std::string ip);
    static short checksum(long sum, unsigned char *buf, int offset, int len);
    static long getsum(unsigned char *buf, int offset, int len);
};

class UDPHeader
{

public:
    static const short offset_src_port = 0;  
    static const short offset_dest_port = 2; 
    static const short offset_len = 4;       
    static const short offset_sum = 6;       

    unsigned char *mData;
    int mOffset;

    UDPHeader();
    void init(unsigned char *data, int offset);
    short getSourcePort();
    void setSourcePort(short value);
    short getDestinationPort();
    void setDestinationPort(short value);
    int getTotalLength();
    void setTotalLength(int value);
    short getSum();
    void setSum(short value);

    static short readShort(unsigned char *data, int offset);
    static void writeShort(unsigned char *data, int offset, short value);
};

/**
 * vnic ack format
 * 0                                                                                                                             13
 * | -----------------------------------------------------------------------------------------------------------------------------|
 * |  1 byte     |   1 byte     |       4 byte        |      2 byte             |                4 byte             |   1 byte    |
 * |   type      |    CID       |        key          |      sn or ack number   |          start sn or time stamp   | req type    |
 * |------------------------------------------------------------------------------------------------------------------------------|
 **/

class VnicAck
{

public:
    unsigned char *mData;
    int mOffset;

    VnicAck();
    void init(unsigned char *data, int offset);
    int getType();
    unsigned char getCID();
    int getKey();
    int getAckNum();
    int getTimeStampMillis();
    int getReqType();
};

/**
 * req message format
 * 0                                                                          6
 * | -------------------------------------------------------------------------|
 * |  1 byte     |   2 byte           |       1 byte        |      2 byte     |
 * |   type      |    vendor-ID       |     sub-type        |      len        |
 * |--------------------------------------------------------------------------|
 **/

class ReqMessage
{
public:
    unsigned char *mData;
    int mOffset;

    void init(unsigned char *data, int offset);
    int getSubType();
};

class TSCMessage
{
public:
    unsigned char *mData;
    int mOffset;

    void init(unsigned char *data, int offset);
    int getType();
    int getVendorID();
    int getSubType();
    int getLen();
    unsigned char getULDuplicationEnabled();
    unsigned char getDLDynamicSplittingEnabled();
    unsigned char getFlowID();
    unsigned char getK1();
    unsigned char getK2();
    unsigned char getL();
};

class TFCMessage
{
public:
    unsigned char *mData;
    int mOffset;

    void init(unsigned char *data, int offset);
    int getType();
    int getVendorID();
    int getSubType();
    unsigned char getFlowID();
    unsigned char getProtoType();
    int getPortStart();
    int getPortEnd();
};


class TrafficSplitAck{
public:
    unsigned char* mData;
    int mOffset;

    void init(unsigned char* data, int offset);
    unsigned char getType();
    unsigned char getCID();
    int getKey();
    int getAckNum();
    int getTimeStampMillis();
    unsigned char getFlowID1();
    unsigned char getStartLsn1();
    int getStartSn1();
    unsigned char getFlowID2();
    unsigned char getStartLsn2();
    int getStartSn2();
    int getWiFiTxOffset();
    int getLteTxOffset();
    
};



#endif