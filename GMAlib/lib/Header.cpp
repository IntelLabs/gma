//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : Header.cpp

#include "../include/Header.h"
#include <cstdint>
#include <string>
#include <sstream>
#include <vector>

//GMAMessageHeader Class
GMAMessageHeader::GMAMessageHeader()
{
    mData = NULL;
    mOffset = 0;
}

void GMAMessageHeader::init(unsigned char *buf, int offset)
{
    mData = buf;
    mOffset = offset;
}

void GMAMessageHeader::setGMAMessageHeader(short flag)
{
    mData[mOffset] = (unsigned char)((flag & 0xFF00) >> 8);
    mData[mOffset + 1] = (unsigned char)(flag & 0x00FF);
}

void GMAMessageHeader::setGmaClientId(short id)
{
    mData[mOffset + 2] = (unsigned char)((id & 0xFF00) >> 8);
    mData[mOffset + 3] = (unsigned char)(id & 0x00FF);
}

unsigned char GMAMessageHeader::getFlow()
{
    return mData[mOffset + 2];
}

//GMADataHeader Class
GMADataHeader::GMADataHeader()
{
    mData = NULL;
    mOffset = 0;
}

void GMADataHeader::init(unsigned char *data, int offset)
{
    mData = data;
    mOffset = offset;
}

void GMADataHeader::setUlParams(short flag, unsigned char flowID, unsigned char ppp, int timeStamp, int gSN)
{ //this function is called to set the gma headers for uplink data

    //use network byte order, high -> low
    mData[mOffset] = (unsigned char)((flag & 0xFF00) >> 8);
    mData[mOffset + 1] = (unsigned char)(flag & 0x00FF);

    mData[mOffset + 2] = (unsigned char)flowID; //flow id
    mData[mOffset + 3] = (unsigned char)ppp;    //priority bit

    mData[mOffset + 4] = (unsigned char)0; //lsn not used for ul

    mData[mOffset + 5] = (unsigned char)((gSN & 0x00FF0000) >> 16);
    mData[mOffset + 6] = (unsigned char)((gSN & 0x0000FF00) >> 8);
    mData[mOffset + 7] = (unsigned char)(gSN & 0x000000FF); //g sn

    mData[mOffset + 8] = (unsigned char)((timeStamp & 0xFF000000) >> 24);
    mData[mOffset + 9] = (unsigned char)((timeStamp & 0x00FF0000) >> 16);
    mData[mOffset + 10] = (unsigned char)((timeStamp & 0x0000FF00) >> 8);
    mData[mOffset + 11] = (unsigned char)(timeStamp & 0x000000FF); //time stamp
}

short GMADataHeader::getFlag()
{
    return (short)((mData[mOffset] << 8) | (mData[mOffset + 1]));
}

int GMADataHeader::getDlClientId()
{
    //this is used for dl only!!
    return ((unsigned int)(mData[mOffset + 2]) << 8 | (unsigned int)(mData[mOffset + 3]));
}

short GMADataHeader::getDlFlowId()
{
    //this is used for dl only!!
    return (short)(mData[mOffset + 4] & 0xFF);
}

short GMADataHeader::getDlPpp()
{
    //this is used for dl only!!
    return (short)(mData[mOffset + 5] & 0xFF);
}

short GMADataHeader::getDlLSeqNum()
{
    //this is used for dl only!!
    return (short)(mData[mOffset + 6] & 0xFF);
}

int GMADataHeader::getDlGSeqNum()
{
    //this is used for dl only!!
    return (int)(((unsigned int)(mData[mOffset + 7]) << 16) + ((unsigned int)(mData[mOffset + 8]) << 8) + (unsigned int)(mData[mOffset + 9]));
}

int GMADataHeader::getDlTimeStampMillis()
{
    //this is used for dl only!!
    return ((unsigned int)(mData[mOffset + 10]) << 24 | (unsigned int)(mData[mOffset + 11]) << 16 | (unsigned int)(mData[mOffset + 12]) << 8 | (unsigned int)(mData[mOffset + 13]));
}

unsigned char *GMADataHeader::getPacket()
{
    return mData;
}

//IPHeader Class*******************************************
IPHeader::IPHeader()
{
    mData = NULL;
    mOffset = 0;
}

void IPHeader::init(unsigned char *data, int offset)
{
    mData = data;
    mOffset = offset;
}

int IPHeader::getDataLength()
{
    return this->getTotalLength() - this->getHeaderLength();
}

int IPHeader::getVersion()
{
    return (mData[mOffset + offset_ver_ihl] & 0XF0) >> 4;
}

int IPHeader::getHeaderLength()
{
    return (mData[mOffset + offset_ver_ihl] & 0x0F) * 4;
}

void IPHeader::setHeaderLength(int value)
{
    mData[mOffset + offset_ver_ihl] = (unsigned char)((4 << 4) | (value / 4));
}

unsigned char IPHeader::getTos()
{
    return mData[mOffset + offset_tos];
}

void IPHeader::setTos(unsigned char value)
{
    mData[mOffset + offset_tos] = value;
}

int IPHeader::getTotalLength()
{

    return this->readShort(mData, mOffset + offset_len) & 0XFFFF;
}

void IPHeader::setTotalLength(int value)
{
    return this->writeShort(mData, mOffset + offset_len, (short)value);
}

int IPHeader::getIdentification()
{
    return this->readShort(mData, mOffset + offset_id) & 0xFFFF;
}

void IPHeader::setIdentification(int value)
{
    return this->writeShort(mData, mOffset + offset_id, (short)value);
}

short IPHeader::getFlagsAndOffset()
{
    return this->readShort(mData, mOffset + offset_off);
}

void IPHeader::setFlagsAndOffset(short value)
{
    this->writeShort(mData, mOffset + offset_off, value);
}

unsigned char IPHeader::getTTL()
{
    return mData[mOffset + offset_ttl];
}

void IPHeader::setTTL(unsigned char value)
{
    mData[mOffset + offset_ttl] = value;
}

unsigned char IPHeader::getProtocol()
{
    return mData[mOffset + offset_protocol];
}

void IPHeader::setProtocol(unsigned char value)
{
    mData[mOffset + offset_protocol] = value;
}

short IPHeader::getSum()
{
    return this->readShort(mData, mOffset + offset_sum);
}

void IPHeader::setSum(short value)
{
    this->writeShort(mData, mOffset + offset_sum, value);
}

int IPHeader::getSourceIP()
{
    return this->readInt(mData, mOffset + offset_src_ip);
}

void IPHeader::setSourceIP(int value)
{
    this->writeInt(mData, mOffset + offset_src_ip, value);
}

int IPHeader::getDestinationIP()
{
    return this->readInt(mData, mOffset + offset_dest_ip);
}

void IPHeader::setDestinationIP(int value)
{
    this->writeInt(mData, mOffset + offset_dest_ip, value);
}

int IPHeader::getDestinationPort()
{
    return this->readShort(mData, mOffset + getHeaderLength() + offset_dest_port) & 0xFFFF;
}

short IPHeader::readShort(unsigned char *data, int offset)
{
    int r = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    return (short)r;
}

void IPHeader::writeShort(unsigned char *data, int offset, short value)
{
    data[offset] = (unsigned char)(value >> 8);
    data[offset + 1] = (unsigned char)(value);
}

int IPHeader::readInt(unsigned char *data, int offset)
{
    int r = ((data[offset] & 0xFF) << 24) | ((data[offset + 1] & 0xFF) << 16) | ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
    return r;
}

void IPHeader::writeInt(unsigned char *data, int offset, int value)
{
    data[offset] = (unsigned char)(value >> 24);
    data[offset + 1] = (unsigned char)(value >> 16);
    data[offset + 2] = (unsigned char)(value >> 8);
    data[offset + 3] = (unsigned char)value;
}

int IPHeader::ipStringToInt(std::string ip)
{
    std::istringstream iss(ip);
    std::vector<std::string> tokens;
    std::string token;
    while (std::getline(iss, token, '.'))
    {
        if (!token.empty())
        {
            tokens.push_back(token);
        }
    }
    int r = (std::stoi(tokens[0]) << 24) | (std::stoi(tokens[1]) << 16) | (std::stoi(tokens[2]) << 8) | (std::stoi(tokens[3]));
    return r;
}

short IPHeader::checksum(long sum, unsigned char *buf, int offset, int len)
{
    sum += getsum(buf, offset, len);
    while ((sum >> 16) > 0)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (short)~sum;
}

long IPHeader::getsum(unsigned char *buf, int offset, int len)
{
    long sum = 0;
    while (len > 1)
    {
        sum += readShort(buf, offset) & 0xFFFF;
        offset += 2;
        len -= 2;
    }

    if (len > 0)
    {
        sum += (buf[offset] & 0xFF) << 8;
    }

    return sum;
}

//UDPHeader Class********************************************************
UDPHeader::UDPHeader()
{
    mData = NULL;
    mOffset = 0;
}
void UDPHeader::init(unsigned char *data, int offset)
{
    mData = data;
    mOffset = offset;
}

short UDPHeader::getSourcePort()
{
    return this->readShort(mData, mOffset + offset_src_port);
}

void UDPHeader::setSourcePort(short value)
{
    this->writeShort(mData, mOffset + offset_src_port, value);
}

short UDPHeader::getDestinationPort()
{
    return this->readShort(mData, mOffset + offset_dest_port);
}

void UDPHeader::setDestinationPort(short value)
{
    this->writeShort(mData, mOffset + offset_dest_port, value);
}

int UDPHeader::getTotalLength()
{
    return this->readShort(mData, mOffset + offset_len) & 0xFFFF;
}

void UDPHeader::setTotalLength(int value)
{
    this->writeShort(mData, mOffset + offset_len, (short)value);
}

short UDPHeader::getSum()
{
    return this->readShort(mData, mOffset + offset_sum);
}

void UDPHeader::setSum(short value)
{
    this->writeShort(mData, mOffset + offset_sum, value);
}

short UDPHeader::readShort(unsigned char *data, int offset)
{
    int r = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    return (short)r;
}

void UDPHeader::writeShort(unsigned char *data, int offset, short value)
{
    data[offset] = (unsigned char)(value >> 8);
    data[offset + 1] = (unsigned char)(value);
}

//VnicAck Class *******************

VnicAck::VnicAck()
{
    mData = NULL;
    mOffset = 0;
}

void VnicAck::init(unsigned char *data, int offset)
{
    mData = data;
    mOffset = offset;
}

int VnicAck::getType()
{
    return (unsigned int)(mData[mOffset]);
}

unsigned char VnicAck::getCID()
{
    return mData[mOffset + 1];
}

int VnicAck::getKey()
{
    return ((unsigned int)(mData[mOffset + 2]) << 24 | (unsigned int)(mData[mOffset + 3]) << 16 | (unsigned int)(mData[mOffset + 4]) << 8 | (unsigned int)(mData[mOffset + 5]));
}

int VnicAck::getAckNum()
{
    return ((unsigned int)(mData[mOffset + 6]) << 8 | (unsigned int)(mData[mOffset + 7]));
}

int VnicAck::getTimeStampMillis()
{
    return ((unsigned int)(mData[mOffset + 8]) << 24 | (unsigned int)(mData[mOffset + 9]) << 16 | (unsigned int)(mData[mOffset + 10]) << 8 | (unsigned int)(mData[mOffset + 11]));
}

int VnicAck::getReqType()
{
    return (unsigned int)(mData[mOffset + 12]);
}

//ReqMessage Class
void ReqMessage::init(unsigned char *data, int offset)
{
    mData = data;
    mOffset = offset;
}

int ReqMessage::getSubType()
{
    return (unsigned int)(mData[mOffset + 3]);
}

//TSCMessage Class
void TSCMessage::init(unsigned char *data, int offset)
{
    mData = data;
    mOffset = offset;
}

int TSCMessage::getType()
{
    return (unsigned int)(mData[mOffset]);
}

int TSCMessage::getVendorID()
{
    return (unsigned int)(mData[mOffset + 1]) << 8 | (unsigned int)(mData[mOffset + 2]);
}

int TSCMessage::getSubType()
{
    return mData[mOffset + 3];
}

int TSCMessage::getLen()
{
    return (unsigned int)(mData[mOffset + 4]) << 8 | (unsigned int)(mData[mOffset + 5]);
}

unsigned char TSCMessage::getULDuplicationEnabled()
{
    return mData[mOffset + 6];
}

unsigned char TSCMessage::getDLDynamicSplittingEnabled()
{
    return mData[mOffset + 7];
}

unsigned char TSCMessage::getFlowID()
{
    return mData[mOffset + 8];
}

unsigned char TSCMessage::getK1()
{
    return mData[mOffset + 9];
}
unsigned char TSCMessage::getK2()
{
    return mData[mOffset + 10];
}
unsigned char TSCMessage::getL()
{
    return mData[mOffset + 11];
}

//TFCMessage Class
void TFCMessage::init(unsigned char *data, int offset)
{
    mData = data;
    mOffset = offset;
}

int TFCMessage::getType()
{
    return (unsigned int)(mData[mOffset]);
}

int TFCMessage::getVendorID()
{
    return (unsigned int)(mData[mOffset + 1]) << 8 | (unsigned int)(mData[mOffset + 2]);
}

int TFCMessage::getSubType()
{
    return mData[mOffset + 3];
}
unsigned char TFCMessage::getFlowID()
{
    return mData[mOffset + 4];
}
unsigned char TFCMessage::getProtoType()
{
    return mData[mOffset + 5];
}
int TFCMessage::getPortStart()
{
    return (unsigned int)(mData[mOffset + 6]) << 8 | (unsigned int)(mData[mOffset + 7]);
}
int TFCMessage::getPortEnd()
{
    return (unsigned int)(mData[mOffset + 8]) << 8 | (unsigned int)(mData[mOffset + 9]);
}

//TrafficSplitAck Class

void TrafficSplitAck::init(unsigned char *data, int offset)
{
    mData = data;
    mOffset = offset;
 }

unsigned char TrafficSplitAck::getType()
{
    return mData[mOffset];
}

unsigned char TrafficSplitAck::getCID()
{
    return mData[mOffset + 1];
}

int TrafficSplitAck::getKey()
{
    return ((unsigned int)(mData[mOffset + 2]) << 24 | (unsigned int)(mData[mOffset + 3]) << 16 | (unsigned int)(mData[mOffset + 4]) << 8 | (unsigned int)(mData[mOffset + 5]));
}

int TrafficSplitAck::getAckNum()
{
    return ((unsigned int)(mData[mOffset + 6]) << 8) | ((unsigned int)(mData[mOffset + 7]));
}
int TrafficSplitAck::getTimeStampMillis()
{

    int x = (int)(mData[mOffset + 8]) << 24 | (int)(mData[mOffset + 9]) << 16 | (int)(mData[mOffset + 10]) << 8 | (int)(mData[mOffset + 11]); 
    //printf("\n **** TSA Timestamp %d \n", x);
    return (x);
}

unsigned char TrafficSplitAck::getFlowID1()
{
    return mData[mOffset + 12];
}

unsigned char TrafficSplitAck::getStartLsn1()
{
    return mData[mOffset + 13];
}

int TrafficSplitAck::getStartSn1()
{
    int x = (int)(mData[mOffset + 14]) << 16 | (int)(mData[mOffset + 15]) << 8 | (int)(mData[mOffset + 16]); 
    //printf("\n **** TSA Start SN %d \n", x);
    return (x);
}

int TrafficSplitAck::getWiFiTxOffset() //D1
{
    u_char x = mData[mOffset + 17];
    if (x < 128)
      return ((int)x);
    else
      return ((int)x - 256);
    
}

int TrafficSplitAck::getLteTxOffset() //D2    -128 ~ 127
{
    u_char x = mData[mOffset + 18];
    if (x < 128)
      return ((int)x);
    else
      return ((int)x - 256);
    
}

unsigned char TrafficSplitAck::getFlowID2()
{
    return mData[mOffset + 17];
}

unsigned char TrafficSplitAck::getStartLsn2()
{
    return mData[mOffset + 18];
}

int TrafficSplitAck::getStartSn2()
{
    return (int)(mData[mOffset + 19] << 16 | mData[mOffset + 20] << 8 | mData[mOffset + 21]);
}