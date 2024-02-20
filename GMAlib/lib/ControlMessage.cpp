//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : ControlMessage.cpp


#if defined(_WIN32) || defined(_WIN64) 
#define NOMINMAX
#endif

#include <iostream>
#include <cstring>
#include <climits>
#include <cmath>
#include <sstream>
#include <vector>

#include <thread>
#include <chrono>
#include <vector>
#include <iterator>
#include <functional>
#include <fcntl.h>
#include <csignal>
#include <stdio.h>
#include <openssl/rand.h>

#include "../include/ControlMessage.h"
#include "../include/Common.h"
#include "../include/Header.h"
#include "../include/EncryptorAesGcm.h"
#include "../include/SystemStateSettings.h"


ControlManager::ControlManager()
{
    wifiProbeID = 0;
    lteProbeID = 0;
    mrpID = 0;
    lrpID = 0;
    tsuID = 0;

}

void ControlManager::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
	this->p_systemStateSettings = p_systemStateSettings;
	sendWifiProbeMsg.initUnitSystemStateSettings(p_systemStateSettings);
	sendLteProbeMsg.initUnitSystemStateSettings(p_systemStateSettings);
	sendMRPMsg.initUnitSystemStateSettings(p_systemStateSettings);
	sendLRPMsg.initUnitSystemStateSettings(p_systemStateSettings);
	obj_sendTSUMsg.initUnitSystemStateSettings(p_systemStateSettings);
}

void ControlManager::updateSystemSettings()
{
	sendWifiProbeMsg.updateSettings();
	sendWifiProbeMsg.BuildPacketHeader();
	sendLteProbeMsg.updateSettings();
	sendLteProbeMsg.BuildPacketHeader();
	sendMRPMsg.updateSettings();
	sendMRPMsg.BuildPacketHeader();
	sendLRPMsg.updateSettings();
	sendLRPMsg.BuildPacketHeader();
	obj_sendTSUMsg.updateSettings();
	obj_sendTSUMsg.BuildPacketHeader();
}

void ControlManager::startThread()
{
	try
    {
        wifiProbeThread = std::thread(&SendWifiProbeMsg::Execute, &sendWifiProbeMsg);
        wifiProbeID = (std::thread::native_handle_type)1; 
    }
    catch (const std::system_error &e)
    {
        std::cout << "Caught system_error with code " << e.code()
                  << " meaning " << e.what() << '\n';
        wifiProbeID = 0;
    }
    
    try
    {
        lteProbeThread = std::thread(&SendLteProbeMsg::Execute, &sendLteProbeMsg);
        lteProbeID = (std::thread::native_handle_type)1; 
    }
    catch (const std::system_error &e)
    {
        std::cout << "Caught system_error with code " << e.code()
                  << " meaning " << e.what() << '\n';
        lteProbeID = 0;
    }
    
    try
    {
        mrpThread = std::thread(&SendMRPMsg::Execute, &sendMRPMsg);
        mrpID = (std::thread::native_handle_type)1; 
    }
    catch (const std::system_error &e)
    {
        std::cout << "Caught system_error with code " << e.code()
                  << " meaning " << e.what() << '\n';
        mrpID = 0;
    }
    

    try
    {
        lrpThread = std::thread(&SendLRPMsg::Execute, &sendLRPMsg);
        lrpID = (std::thread::native_handle_type)1; 
    }
    catch (const std::system_error &e)
    {
        std::cout << "Caught system_error with code " << e.code()
                  << " meaning " << e.what() << '\n';
        lrpID = 0;
    }

    try
    {
        tsuThread = std::thread(&SendTSUMsg::Execute, &obj_sendTSUMsg);
        tsuID = (std::thread::native_handle_type)1;
    }
    catch (const std::system_error &e)
    {
        std::cout << "Caught system_error with code " << e.code()
                  << " meaning " << e.what() << '\n';
        tsuID = 0;
    }
}

void ControlManager::cancelThread()
{
	if (wifiProbeID != 0)
    {
        while (sendWifiProbeMsg.ThreadBusy)
        {
            
            sendWifiProbeMsg.wifiprobe_begin_cv.notify_all();
            sendWifiProbeMsg.wifiprobe_ack_cv.notify_all();
            sendWifiProbeMsg.wifiprobe_next_cv.notify_all();
            p_systemStateSettings->msleep(1);
         }

        wifiProbeThread.join();
        wifiProbeID = 0;
    }
    
    if (lteProbeID != 0)
    {
        while (sendLteProbeMsg.ThreadBusy)
        {
            
            sendLteProbeMsg.lteprobe_begin_cv.notify_all();
            sendLteProbeMsg.lteprobe_ack_cv.notify_all();
            sendLteProbeMsg.lteprobe_next_cv.notify_all();
            p_systemStateSettings->msleep(1);
         }
        lteProbeThread.join();
        lteProbeID = 0;
    }
    
	if (lrpID != 0)
    {
        while (sendLRPMsg.ThreadBusy)
        {
            sendLRPMsg.notifyLRPCycle(0,0);
            p_systemStateSettings->msleep(1);
        }
        lrpThread.join();
        lrpID = 0;
    }
    
    if (mrpID != 0)
    {
        while (sendMRPMsg.ThreadBusy)
        {
            sendMRPMsg.mrp_begin_cv.notify_all(); 
            sendMRPMsg.mrp_exit_cv.notify_all();  
            p_systemStateSettings->msleep(1000);
        }
        mrpThread.join();
        mrpID = 0;
    }
    if (tsuID != 0)
    {
        while (obj_sendTSUMsg.ThreadBusy)
        {
            
            obj_sendTSUMsg.tsu_send_cv.notify_all();
            obj_sendTSUMsg.tsu_recv_cv.notify_all();
            p_systemStateSettings->msleep(1);
            
        }
        tsuThread.join();

        tsuID = 0;
    }
    std::stringstream ss;
	ss << "ControlMessageManager threads canceled...ok!\n";
	p_systemStateSettings->PrintLogs(ss);
}

void ControlManager::UpdateWifiParams(GMASocket wifiFd, struct sockaddr_in wifiServerAddr)
{
	sendWifiProbeMsg.UpdateWifiFd(wifiFd, wifiServerAddr);
	obj_sendTSUMsg.UpdateWifiFd(wifiFd, wifiServerAddr);
	sendMRPMsg.UpdateWifiFd(wifiFd, wifiServerAddr);
	sendLRPMsg.UpdateWifiFd(wifiFd, wifiServerAddr);
	sendWifiProbeMsg.notifyWifiProbeCycle();
}

void ControlManager::UpdateLteParams(GMASocket lteFd, struct sockaddr_in lteServerAddr)
{
	sendLteProbeMsg.UpdateLteFd(lteFd, lteServerAddr);
	obj_sendTSUMsg.UpdateLteFd(lteFd, lteServerAddr);
	sendMRPMsg.UpdateLteFd(lteFd, lteServerAddr);
	sendLRPMsg.UpdateLteFd(lteFd, lteServerAddr);
	sendLteProbeMsg.notifyLteProbeCycle();
}

void ControlManager::notifyMRPCycle()
{
	sendMRPMsg.notifyMRPCycle();
}

void ControlManager::notifyLRPCycle(bool isConnect, unsigned char code) 
{
    sendLRPMsg.notifyLRPCycle(isConnect, code);
}

void ControlManager::sendTSUMsg() 
{
	obj_sendTSUMsg.sendTSUMsg();
}

void ControlManager::sendWifiProbe() 
{
    sendWifiProbeMsg.sendWifiProbe();
}

void ControlManager::sendLteProbe() 
{
    sendLteProbeMsg.sendLteProbe();
}

void ControlManager::receiveWifiTSA(int seqNumber, int currentTimeMillis)
{
	obj_sendTSUMsg.receiveWifiTSA(seqNumber, currentTimeMillis);
}

void ControlManager::receiveLteTSA(int seqNumber, int systemTimeMs)
{
	obj_sendTSUMsg.receiveLteTSA(seqNumber, systemTimeMs);
}

void ControlManager::receiveWifiProbeAck(int seqNumebr)
{
	sendWifiProbeMsg.receiveProbeAck(seqNumebr);
}

void ControlManager::receiveLteProbeAck(int seqNumber)
{
	sendLteProbeMsg.receiveProbeAck(seqNumber);
}

void ControlManager::SendACK(unsigned char reqtype)
{
	sendWifiProbeMsg.SendACK(reqtype);
}


SendWifiProbeMsg::SendWifiProbeMsg()
{
	wifiServer.sin_family = {};
	wifiServer.sin_port = 0;
	wifiServer.sin_addr = {};
}

void SendWifiProbeMsg::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}

void SendWifiProbeMsg::updateSettings()
{
	memset(buf, 0, sizeof(buf));
	memset(plainText, 0, sizeof(plainText));

	lastSendWifiProbeTime = 0;
	intervalTime = 0;
	seqNum = 0;
	size = 0;
	recvAckSN = 1;
	sendWifiProbeThreadBusy = false;
	ThreadBusy = false;
	snAndTimeArray.clear();
	probingStart = false;
}

void SendWifiProbeMsg::Execute()
{
	ThreadBusy = true;
	std::unique_lock<std::mutex> next_lck(wifiprobe_next_mtx);
	std::unique_lock<std::mutex> ack_lck(wifiprobe_ack_mtx);
	std::unique_lock<std::mutex> lck(wifiprobe_begin_mtx);
	int sendProbeTime = 0;
 	try
	{
		while (p_systemStateSettings->isControlManager)
		{
			probingStart = false;
			wifiprobe_begin_cv.wait(lck); // sychronized lock
			probingStart = true;
			int sendFailCounter = 0;
			bool sendFlag = false;
			while (p_systemStateSettings->gWifiFlag)
			{
				sendWifiProbeThreadBusy = true;
				if (p_systemStateSettings->gDLAllOverLte)
				{
					intervalTime = p_systemStateSettings->wifiProbeIntervalScreenOff;
				}
				else
					intervalTime = p_systemStateSettings->wifiProbeIntervalScreenOn;

				seqNum = p_systemStateSettings->controlMsgSn;
				p_systemStateSettings->controlMsgSn = (p_systemStateSettings->controlMsgSn + 1) & 0x0000FFFF; // 2bytes
				lastSendWifiProbeTime = (int)(p_systemStateSettings->update_current_time_params() & 0x7FFFFFFF);
				p_systemStateSettings->lastSendWifiProbe = lastSendWifiProbeTime;
				p_systemStateSettings->lastReceiveWifiProbe = -1;

				plainText[28] = (unsigned char)1; //type
				plainText[29] = (unsigned char)0; //CID
				plainText[30] = (unsigned char)((p_systemStateSettings->key & 0xFF000000) >> 24);
				plainText[31] = (unsigned char)((p_systemStateSettings->key & 0x00FF0000) >> 16);
				plainText[32] = (unsigned char)((p_systemStateSettings->key & 0x0000FF00) >> 8);
				plainText[33] = (unsigned char)(p_systemStateSettings->key & 0x000000FF); //key
				plainText[34] = (unsigned char)((seqNum & 0xff00) >> 8);
				plainText[35] = (unsigned char)(seqNum & 0x00ff);

				int linkBitmap = p_systemStateSettings->GetLinkBitmap();
				plainText[36] = (unsigned char)linkBitmap; //first bit is wifi, second bit for lte
				plainText[37] = (unsigned char)0;		   //flag
				plainText[38] = (unsigned char)0;		   //r-cid
				plainText[39] = (unsigned char)((lastSendWifiProbeTime & 0xFF000000) >> 24);
				plainText[40] = (unsigned char)((lastSendWifiProbeTime & 0x00FF0000) >> 16);
				plainText[41] = (unsigned char)((lastSendWifiProbeTime & 0x0000FF00) >> 8);
				plainText[42] = (unsigned char)(lastSendWifiProbeTime & 0x000000FF); //time stamp

				if (wifiudpFd != GMA_INVALID_SOCKET)
				{
					sendFlag = false;
					size++;
					try
					{
						if (p_systemStateSettings->enable_encryption)
						{
							int aad_len = 4;
							unsigned char aad[4];
							int tag_len = 16;
							unsigned char tags[16];
							int iv_len = 12;
							unsigned char iv[12];

							memset(aad, 0, aad_len);
							memset(tags, 0, tag_len);
							memset(iv, 0, iv_len);

							memcpy(aad, buf, 4);

							unsigned char cipher[256];
							memset(cipher, 0, sizeof(cipher));

							if (RAND_bytes(iv, iv_len))
							{
								EncryptorAesGcm encryptorAesGcm;

								int ret = encryptorAesGcm.Encrypt((unsigned char*)plainText, sizeof(plainText),
									(unsigned char*)aad, aad_len,
									(unsigned char*)(p_systemStateSettings->aesKey.c_str()),
									(unsigned char*)iv, iv_len, (unsigned char*)cipher, tags);
								if (!ret)
								{
								}
								else
								{
									memcpy(buf + 4, cipher, plaintext_size);
									memcpy(buf + 4 + plaintext_size, tags, tag_len);
									memcpy(buf + 4 + plaintext_size + tag_len, iv, iv_len);

									std::stringstream ss;
									if (sendto(wifiudpFd, (char*)buf, 75, 0, (struct sockaddr*)&wifiServer, sizeof(wifiServer)) < 0)
									{
										ss << "Error: Send Wifi Probe Failed\n";
										p_systemStateSettings->PrintLogs(ss);
									}
									else
									{
										ss.str("");
										ss << "success to send for the wifi probe!" << seqNum << std::endl;
										p_systemStateSettings->PrintLogs(ss);
										p_systemStateSettings->wifiSendBytes += 75;
										sendFlag = true;
									}
								}
							}
					
						}
						else
						{
							std::stringstream ss;
							memcpy(buf + 2, plainText, plaintext_size);
							if (sendto(wifiudpFd, (char*)buf, 45, 0, (struct sockaddr *)&wifiServer, sizeof(wifiServer)) < 0)
							{
								ss << "Error: Send Wifi Probe Failed\n";
								p_systemStateSettings->PrintLogs(ss);
							}
							else
							{
								ss.str("");
								ss << "success to send for the wifi probe!" << seqNum << std::endl;
								p_systemStateSettings->PrintLogs(ss);
								p_systemStateSettings->wifiSendBytes += 45;
								sendFlag = true;
							}
						}
					}
					catch (const std::exception &e)
					{
						std::stringstream ss;
						ss << e.what() << std::endl;
						p_systemStateSettings->PrintLogs(ss);
					}
					if (sendFlag)
					{
						snAndTimeArray.insert(std::pair<int, int>(seqNum, lastSendWifiProbeTime));

						if (p_systemStateSettings->gIsLteConnect && !p_systemStateSettings->gDLAllOverLte)
							wifiprobe_ack_cv.wait_for(ack_lck, std::chrono::milliseconds(p_systemStateSettings->wifiProbeTimeout));
						else
							wifiprobe_ack_cv.wait_for(ack_lck, std::chrono::milliseconds(1000));
						
						//sendProbeTime = p_systemStateSettings->lastReceiveWifiProbe;
						if (snAndTimeArray.count(recvAckSN) > 0)
						{
							sendProbeTime = snAndTimeArray[recvAckSN];
						}
					}
					else
					{
						wifiprobe_ack_cv.wait_for(ack_lck, std::chrono::milliseconds(3));
					}
					if (p_systemStateSettings->lastReceiveWifiProbe >= 0 && sendFlag)
					{ //ack received
						p_systemStateSettings->wifiLinkRtt = p_systemStateSettings->lastReceiveWifiProbe - sendProbeTime;
						std::stringstream ss;
						ss.str("");
						ss << "\n WiFi probe rtt(ms): " << p_systemStateSettings->wifiLinkRtt << "\n";
						p_systemStateSettings->PrintLogs(ss);
						p_systemStateSettings->wifiLinkMaxRtt = std::max(p_systemStateSettings->wifiLinkRtt, p_systemStateSettings->wifiLinkMaxRtt);
						size = 0; //reset the counter to 0;
						snAndTimeArray.clear();
						if (p_systemStateSettings->gIsWifiConnect == false && p_systemStateSettings->wifiLinkRtt - p_systemStateSettings->lteLinkRtt < p_systemStateSettings->rttThLow) //add a Rtt_Th1 to config.txt (Rtt_Th1 = 0)
						{
							p_systemStateSettings->gIsWifiConnect = true;
							p_systemStateSettings->wifiIndexChangeAlpha = 0;
							p_systemStateSettings->wifiSplitFactor = p_systemStateSettings->paramL;
							p_systemStateSettings->lteSplitFactor = 0;
							p_systemStateSettings->gDLAllOverLte = false;
							p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg()(); //sendTsu.sendtsu
						}
					}
					else
					{
						if (size > 3)
						{ // more than 3 transmissions, link failure
							std::stringstream ss;
							ss << "more than 3 times, wifi link failure\n";
							size = 0;
							p_systemStateSettings->PrintLogs(ss);
							p_systemStateSettings->wifiLinkRtt = 1000;
							p_systemStateSettings->wifiProbeTimeout = 1000;
							p_systemStateSettings->numOfWifiLinkFailure++;
							p_systemStateSettings->lastReceiveWifiProbe = 0;
							p_systemStateSettings->gIsWifiConnect = false;
							if (p_systemStateSettings->gTunAvailable)
							{
								if (p_systemStateSettings->gLteFlag)
								{
									p_systemStateSettings->gIsLteConnect = true;
									if (p_systemStateSettings->gDLAllOverLte == false)
									{
										p_systemStateSettings->wifiSplitFactor = 0;
										p_systemStateSettings->lteSplitFactor = p_systemStateSettings->paramL;
										p_systemStateSettings->gDLAllOverLte = true;
										p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg();
										p_systemStateSettings->GMAIPCMessage(3,0,0,false,0); //controlManager.sendLteProbe();
										p_systemStateSettings->GMAIPCMessage(9, 0, 0, true, 2);
									}
								}
								else
								{
									ThreadBusy = false;
									p_systemStateSettings->mHandler(3);
									ss.str("");
									ss << "mHandler fail, line 374\n";
									p_systemStateSettings->PrintLogs(ss);
									return;
								}
							}
							snAndTimeArray.clear();
							p_systemStateSettings->GMAIPCMessage(10, 0, 0, false, 0);
						}
						else
						{
							intervalTime = 0; // retransmit immediately
						}
					}
				}
				else
				{
					std::stringstream ss;
					ss << "wifi channel is NULL !\n";
					p_systemStateSettings->PrintLogs(ss);

					p_systemStateSettings->wifiLinkRtt = 1000;
					p_systemStateSettings->wifiProbeTimeout = 1000;
					p_systemStateSettings->numOfWifiLinkFailure++;
					p_systemStateSettings->lastReceiveWifiProbe = 0;
					p_systemStateSettings->gIsWifiConnect = false;
					if (!p_systemStateSettings->gIsLteConnect)
					{
						ThreadBusy = false;
						p_systemStateSettings->mHandler(3);
						ss.str("");
						ss << "mHandler fail, line 382\n";
						p_systemStateSettings->PrintLogs(ss);
						return;
					}

				}
				sendWifiProbeThreadBusy = false;
				if (intervalTime > 0)
				{
					wifiprobe_next_cv.wait_for(next_lck, std::chrono::milliseconds(intervalTime * 1000)); // sychronized lock
				}
			}
		}
	}
	catch (const std::exception &e)
	{
		std::stringstream ss;
		ss << e.what() << std::endl;
		ss << "control message manager send wifi probe thread exit";
		p_systemStateSettings->PrintLogs(ss);
	}
	ThreadBusy = false;
	p_systemStateSettings->mHandler(3);
	std::stringstream ss;
	ss << "mHandler fail, line 408....[Wifi probe thread]: exit\n";
	p_systemStateSettings->PrintLogs(ss);
	return;
}



void SendWifiProbeMsg::SendACK(unsigned char reqtype)
{

	if (wifiudpFd != GMA_INVALID_SOCKET)
	{
		seqNum = p_systemStateSettings->controlMsgSn;
		p_systemStateSettings->controlMsgSn = (p_systemStateSettings->controlMsgSn + 1) & 0x0000FFFF; // 2bytes

		plainText2[28] = (unsigned char)6; //type
		plainText2[29] = (unsigned char)0; //CID
		plainText2[30] = (unsigned char)((p_systemStateSettings->key & 0xFF000000) >> 24);
		plainText2[31] = (unsigned char)((p_systemStateSettings->key & 0x00FF0000) >> 16);
		plainText2[32] = (unsigned char)((p_systemStateSettings->key & 0x0000FF00) >> 8);
		plainText2[33] = (unsigned char)(p_systemStateSettings->key & 0x000000FF); //key
		plainText2[34] = (unsigned char)((seqNum & 0xff00) >> 8);
		plainText2[35] = (unsigned char)(seqNum & 0x00ff);
		plainText2[40] = reqtype;

		try
		{
			if (p_systemStateSettings->enable_encryption)
			{
				int aad_len = 4;
				unsigned char aad[4];
				int tag_len = 16;
				unsigned char tags[16];
				int iv_len = 12;
				unsigned char iv[12];

				memset(aad, 0, aad_len);
				memset(tags, 0, tag_len);
				memset(iv, 0, iv_len);

				memcpy(aad, buf2, 4);

				unsigned char cipher[256];
				memset(cipher, 0, sizeof(cipher));

				if (RAND_bytes(iv, iv_len))
				{
					EncryptorAesGcm encryptorAesGcm;

					int ret = encryptorAesGcm.Encrypt((unsigned char*)plainText2, sizeof(plainText2),
						(unsigned char*)aad, aad_len,
						(unsigned char*)(p_systemStateSettings->aesKey.c_str()),
						(unsigned char*)iv, iv_len, (unsigned char*)cipher, tags);
					if (!ret)
					{
						printf("\n AesGCM encryption failed \n");
					}
					else
					{
				
						memcpy(buf2 + 4, cipher, plaintext2_size);
						memcpy(buf2 + 4 + plaintext2_size, tags, tag_len);
						memcpy(buf2 + 4 + plaintext2_size + tag_len, iv, iv_len);

						std::stringstream ss;

						if (sendto(wifiudpFd, (char*)buf2, 73, 0, (struct sockaddr*)&wifiServer, sizeof(wifiServer)) < 0)
						{
							ss << "Error: Send Wifi ACK Failed\n";
							p_systemStateSettings->PrintLogs(ss);
						}
						else
						{
							ss.str("");
							ss << "success to send for the wifi ACK!" << std::endl;
							p_systemStateSettings->PrintLogs(ss);
							p_systemStateSettings->wifiSendBytes += 73;
						}
					}
				}
				else
					printf("\n RAND bytes failed \n");
			}
			else
			{
				std::stringstream ss;
				memcpy(buf2 + 2, plainText2, plaintext2_size);
				if (sendto(wifiudpFd, (char*)buf2, 43, 0, (struct sockaddr*)&wifiServer, sizeof(wifiServer)) < 0)
				{
					ss << "Error: Send Wifi Probe Failed\n";
					p_systemStateSettings->PrintLogs(ss);
				}
				else
				{
					ss.str("");
					ss << "success to send for the wifi  ACK!" << std::endl;
					p_systemStateSettings->PrintLogs(ss);
					p_systemStateSettings->wifiSendBytes += 43;
				}
			}
		}
		catch (const std::exception& e)
		{
			std::stringstream ss;
			ss << e.what() << std::endl;
			p_systemStateSettings->PrintLogs(ss);
		}
	}
}

void SendWifiProbeMsg::UpdateWifiFd(GMASocket fd, struct sockaddr_in wifiServerAddr)
{
	wifiudpFd = fd;
	wifiServer = wifiServerAddr;
}

void SendWifiProbeMsg::BuildPacketHeader()
{
	gmaMessageHeader.init(buf, 0);
	ipHeader.init(plainText, 0);
	udpHeader.init(plainText, 20);

	if (p_systemStateSettings->enable_encryption)
	{
		gmaMessageHeader.setGMAMessageHeader((short)0x800F); //encrypted control
		gmaMessageHeader.setGmaClientId((short)p_systemStateSettings->clientId);
	}
	else
	{
		gmaMessageHeader.setGMAMessageHeader((short)0x00); //plain text
	}

	plainText[0] = 0x45;

	ipHeader.setTos((unsigned char)0);
	ipHeader.setTotalLength(plaintext_size);
	ipHeader.setIdentification(0);
	ipHeader.setFlagsAndOffset((short)0x4000);
	ipHeader.setTTL((unsigned char)64);
	ipHeader.setDestinationIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicGw));
	ipHeader.setProtocol((unsigned char)0x11);
	ipHeader.setSourceIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicIp));
	ipHeader.setSum((short)0);
	ipHeader.setSum((short)ipHeader.checksum(0, plainText, 0, 20));

	udpHeader.setDestinationPort((short)p_systemStateSettings->serverUdpPort);
	udpHeader.setSourcePort((short)p_systemStateSettings->clientProbePort);
	udpHeader.setTotalLength(plaintext_size - 20);
	udpHeader.setSum((short)0);


	gmaMessageHeader.init(buf2, 0);
	ipHeader.init(plainText2, 0);
	udpHeader.init(plainText2, 20);

	if (p_systemStateSettings->enable_encryption)
	{
		gmaMessageHeader.setGMAMessageHeader((short)0x800F); //encrypted control
		gmaMessageHeader.setGmaClientId((short)p_systemStateSettings->clientId);
	}
	else
	{
		gmaMessageHeader.setGMAMessageHeader((short)0x00); //plain text
	}

	plainText2[0] = 0x45;

	ipHeader.setTos((unsigned char)0);
	ipHeader.setTotalLength(plaintext2_size);
	ipHeader.setIdentification(0);
	ipHeader.setFlagsAndOffset((short)0x4000);
	ipHeader.setTTL((unsigned char)64);
	ipHeader.setDestinationIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicGw));
	ipHeader.setProtocol((unsigned char)0x11);
	ipHeader.setSourceIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicIp));
	ipHeader.setSum((short)0);
	ipHeader.setSum((short)ipHeader.checksum(0, plainText2, 0, 20));

	udpHeader.setDestinationPort((short)p_systemStateSettings->serverUdpPort);
	udpHeader.setSourcePort((short)p_systemStateSettings->clientProbePort);
	udpHeader.setTotalLength(plaintext2_size - 20);
	udpHeader.setSum((short)0);


}

void SendWifiProbeMsg::notifyWifiProbeCycle()
{
	wifiprobe_next_cv.notify_one();
	wifiprobe_begin_cv.notify_one();
	int x = 0;

	if(!p_systemStateSettings->gWifiFlag)
		return;

	while (!probingStart && x < 10)
	{
		p_systemStateSettings->msleep(1000);
		wifiprobe_begin_cv.notify_one();
		x++;
	}

	if (!probingStart)
	{
		p_systemStateSettings->mHandler(3);

		std::stringstream ss;
		ss << "mHandler fail, line 461...[notifyWifiProbeCycle]: exit\n";
		p_systemStateSettings->PrintLogs(ss);
	}

}

void SendWifiProbeMsg::sendWifiProbe()
{
	if (!sendWifiProbeThreadBusy)
	{
		wifiprobe_next_cv.notify_one();
	}
}

void SendWifiProbeMsg::receiveProbeAck(int recvProbeAckSeqNum)
{
	recvAckSN = recvProbeAckSeqNum;
	wifiprobe_ack_cv.notify_one();
}

SendLteProbeMsg::SendLteProbeMsg()
{
	lteServer.sin_family = {};
	lteServer.sin_port = 0;
	lteServer.sin_addr = {};
}

void SendLteProbeMsg::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}

void SendLteProbeMsg::updateSettings()
{
	memset(buf, 0, sizeof(buf));
	memset(plainText, 0, sizeof(plainText));

	lastSendLteProbeTime = 0;
	intervalTime = 0;
	seqNum = 0;
	size = 0;
	recvAckSN = 0;
	sendLteProbeThreadBusy = false;
	ThreadBusy = false;
	probingStart = false;
	snAndTimeArray.clear();
}

void SendLteProbeMsg::Execute()
{
	ThreadBusy = true;
	bool sendFlag = false;
	int sendProbeTime = 0;
	std::unique_lock<std::mutex> ack_lck(lteprobe_ack_mtx);
	std::unique_lock<std::mutex> lck(lteprobe_begin_mtx);
	std::unique_lock<std::mutex> next_lck(lteprobe_next_mtx);
	
	try
	{
		while (p_systemStateSettings->isControlManager)
		{
			probingStart = false;
			lteprobe_begin_cv.wait(lck); // sychronized lock
			probingStart = true;

			p_systemStateSettings->msleep(1000);
			while (p_systemStateSettings->gLteFlag)
			{
				sendLteProbeThreadBusy = true;
				if (p_systemStateSettings->gDLAllOverLte)
				{
					intervalTime = p_systemStateSettings->lteProbeIntervalScreenOn;
				}
				else
				{
					intervalTime = p_systemStateSettings->lteProbeIntervalScreenOff;
				}
				seqNum = p_systemStateSettings->controlMsgSn;
				p_systemStateSettings->controlMsgSn = (p_systemStateSettings->controlMsgSn + 1) & 0x0000FFFF; // 2bytes

				lastSendLteProbeTime = (int)(p_systemStateSettings->update_current_time_params() & 0x7FFFFFFF);
				p_systemStateSettings->lastSendLteProbe = lastSendLteProbeTime;
				p_systemStateSettings->lastReceiveLteProbe = -1;
				plainText[28] = (unsigned char)1; //type
				plainText[29] = (unsigned char)3; //CID
				plainText[30] = (unsigned char)((p_systemStateSettings->key & 0xFF000000) >> 24);
				plainText[31] = (unsigned char)((p_systemStateSettings->key & 0x00FF0000) >> 16);
				plainText[32] = (unsigned char)((p_systemStateSettings->key & 0x0000FF00) >> 8);
				plainText[33] = (unsigned char)(p_systemStateSettings->key & 0x000000FF); //key

				plainText[34] = (unsigned char)((seqNum & 0xff00) >> 8);
				plainText[35] = (unsigned char)(seqNum & 0x00ff); //sn

				int linkBitmap = p_systemStateSettings->GetLinkBitmap();
				plainText[36] = (unsigned char)linkBitmap;
				plainText[37] = (unsigned char)0; //flag
				plainText[38] = (unsigned char)3; //r-cid
				plainText[39] = (unsigned char)((lastSendLteProbeTime & 0xFF000000) >> 24);
				plainText[40] = (unsigned char)((lastSendLteProbeTime & 0x00FF0000) >> 16);
				plainText[41] = (unsigned char)((lastSendLteProbeTime & 0x0000FF00) >> 8);
				plainText[42] = (unsigned char)(lastSendLteProbeTime & 0x000000FF); //time stamp

				if (lteudpFd != GMA_INVALID_SOCKET)
				{
					size++; //num of transmission/retx for the same probe msg
					sendFlag = false;
					if (p_systemStateSettings->enable_encryption)
					{
						int aad_len = 4;
						unsigned char aad[4];
						int tag_len = 16;
						unsigned char tags[16];
						int iv_len = 12;
						unsigned char iv[12];

						memset(aad, 0, aad_len);
						memset(tags, 0, tag_len);
						memset(iv, 0, iv_len);

						memcpy(aad, buf, 4);

						unsigned char cipher[256];
						memset(cipher, 0, sizeof(cipher));


						if (RAND_bytes(iv, iv_len))
						{

							EncryptorAesGcm encryptorAesGcm;

							int ret = encryptorAesGcm.Encrypt((unsigned char*)plainText, sizeof(plainText),
								(unsigned char*)aad, aad_len,
								(unsigned char*)(p_systemStateSettings->aesKey.c_str()),
								(unsigned char*)iv, iv_len, (unsigned char*)cipher, tags);
							if (!ret)
							{
							}
							else {
								memcpy(buf + 4, cipher, plaintext_size);
								memcpy(buf + 4 + plaintext_size, tags, tag_len);
								memcpy(buf + 4 + plaintext_size + tag_len, iv, iv_len);
								std::stringstream ss;
								if (sendto(lteudpFd, (char *)buf, buf_size, 0, (struct sockaddr*)&lteServer, sizeof(lteServer)) < 0)
								{
									ss << "Error: Send lte Probe Failed\n";
									p_systemStateSettings->PrintLogs(ss);

								}
								else
								{
									ss.str("");
									ss << "success to send for the lte probe!" << seqNum << std::endl;
									p_systemStateSettings->PrintLogs(ss);
									p_systemStateSettings->lteSendBytes += 75;
									sendFlag = true;
								}
							}
						}
					}
					else
					{
						memcpy(buf + 2, plainText, 43);
						std::stringstream ss;
						if (sendto(lteudpFd, (char *)buf, 45, 0, (struct sockaddr *)&lteServer, sizeof(lteServer)) < 0)
						{
							ss << "Send Lte probe Failed !!! \n";
							p_systemStateSettings->PrintLogs(ss);
							
						}
						else
						{
							ss.str("");
							ss << "success for the LTE probe!" << seqNum;
							p_systemStateSettings->PrintLogs(ss);
							p_systemStateSettings->lteSendBytes += 45;
							sendFlag = true;
						}
					}

					if (sendFlag)
					{

						snAndTimeArray.insert(std::pair<int, int>(seqNum, lastSendLteProbeTime));
						lteprobe_ack_cv.wait_for(ack_lck, std::chrono::milliseconds(2000));
						//sendProbeTime = p_systemStateSettings->lastReceiveLteProbe;
						if (snAndTimeArray.count(recvAckSN) > 0)
						{
							sendProbeTime = snAndTimeArray[recvAckSN];
						}
					}
					else
					{
						lteprobe_ack_cv.wait_for(ack_lck, std::chrono::milliseconds(3));
					}
					if (p_systemStateSettings->lastReceiveLteProbe >= 0 && sendFlag)
					{ //received ack
						p_systemStateSettings->lteLinkRtt = p_systemStateSettings->lastReceiveLteProbe - sendProbeTime;
						std::stringstream ss;
						ss.str("");
						ss << "\n LTE probe rtt(ms): " << p_systemStateSettings->lteLinkRtt << "\n";
						p_systemStateSettings->PrintLogs(ss);
						size = 0;
						snAndTimeArray.clear();
						if (!p_systemStateSettings->gIsLteConnect)
						{
							p_systemStateSettings->gIsLteConnect = true;
							p_systemStateSettings->GMAIPCMessage(1, 0, 0, false, 0); //controlManager.sendTSUMsg();
						}

				
						if (!p_systemStateSettings->gTunAvailable)
						{

							if (!p_systemStateSettings->gIsWifiConnect)
							{
								p_systemStateSettings->wifiSplitFactor = 0;
								p_systemStateSettings->lteSplitFactor = p_systemStateSettings->paramL;
								p_systemStateSettings->gDLAllOverLte = true;
								p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg();

							} //move traffic to LTE (while WiFi is not connected)

							std::stringstream ss;
							ss << "Probes ok, start to build tun now..\n";
							p_systemStateSettings->PrintLogs(ss);
							p_systemStateSettings->mHandler(0);
						}
						else
						{
							if (p_systemStateSettings->wifiLinkRtt - p_systemStateSettings->lteLinkRtt > p_systemStateSettings->rttThHigh && p_systemStateSettings->gIsWifiConnect) ////add a Rtt_Th2 to config.txt
							{
								p_systemStateSettings->gIsWifiConnect = false; //wifi delay is too big and therefore treated as "disconnect"
								p_systemStateSettings->wifiSplitFactor = 0;
								p_systemStateSettings->lteSplitFactor = p_systemStateSettings->paramL;
								p_systemStateSettings->gDLAllOverLte = true;
								p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg();
							}
						}
						//move traffic to LTE (while WiFi is not connected)
					}
					else
					{
						if (size > 4)
						{ //more than 3 transmissions, link failure
							size = 0;
							p_systemStateSettings->lastReceiveLteProbe = 0;
							std::stringstream ss;
							ss << "more than 3 times, lte link failure\n";
							p_systemStateSettings->PrintLogs(ss);

							p_systemStateSettings->numOfLteLinkFailure++;
							p_systemStateSettings->gIsLteConnect = false;
							if (p_systemStateSettings->gIsWifiConnect && p_systemStateSettings->gTunAvailable)
							{
								p_systemStateSettings->wifiIndexChangeAlpha = 0;
								p_systemStateSettings->wifiSplitFactor = p_systemStateSettings->paramL;
								p_systemStateSettings->lteSplitFactor = 0;
								p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg();
							}
							else
							{

								p_systemStateSettings->mHandler(3);
								ss.str("");
								ss << "mHandler fail, line 658\n";
								p_systemStateSettings->PrintLogs(ss);
								ThreadBusy = false;
								return;
							}
							snAndTimeArray.clear();
						}
						else
						{
							intervalTime = 0; // retransmit immediately
							if (size == 3)
								p_systemStateSettings->GMAIPCMessage(11, 0, 0, false, 0);
						}
					}
				}
				sendLteProbeThreadBusy = false;
				if (intervalTime > 0)
				{
					lteprobe_next_cv.wait_for(next_lck, std::chrono::milliseconds(intervalTime * 1000));
				}
			}

			
		}
	}
	catch (const char *e)
	{
		std::cout << e << std::endl;
	}
	p_systemStateSettings->mHandler(3);

	std::stringstream ss;
	ss << "mHandler fail, line 692...[Lte probe thread]: exit\n";
	p_systemStateSettings->PrintLogs(ss);
	ThreadBusy = false;
	return;
}

void SendLteProbeMsg::UpdateLteFd(GMASocket fd, struct sockaddr_in lteServerAddr)
{
	lteudpFd = fd;
	lteServer = lteServerAddr;
}

void SendLteProbeMsg::BuildPacketHeader()
{
	gmaMessageHeader.init(buf, 0);
	ipHeader.init(plainText, 0);

	if (p_systemStateSettings->enable_encryption)
	{
		gmaMessageHeader.setGMAMessageHeader((short)0x800F); //encrypted control
		gmaMessageHeader.setGmaClientId((short)p_systemStateSettings->clientId);
	}
	else
	{
		gmaMessageHeader.setGMAMessageHeader((short)0x00); //plain text
	}

	plainText[0] = 0x45;

	ipHeader.setTos((unsigned char)0);
	
	ipHeader.setTotalLength(plaintext_size);
	ipHeader.setIdentification(0);
	ipHeader.setFlagsAndOffset((short)0x4000);
	ipHeader.setTTL((unsigned char)64);
	ipHeader.setDestinationIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicGw));
	ipHeader.setProtocol((unsigned char)0x11);
	ipHeader.setSourceIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicIp));
	ipHeader.setSum((short)0);
	ipHeader.setSum((short)ipHeader.checksum(0, plainText, 0, 20));

	udpHeader.init(plainText, 20);
	udpHeader.setDestinationPort((short)p_systemStateSettings->serverUdpPort);
	udpHeader.setSourcePort((short)p_systemStateSettings->clientProbePort);
	udpHeader.setTotalLength(plaintext_size - 20);
	udpHeader.setSum((short)0);
}

void SendLteProbeMsg::notifyLteProbeCycle()
{
	lteprobe_next_cv.notify_one();
	lteprobe_begin_cv.notify_one();
	int x = 0;

	if(!p_systemStateSettings->gLteFlag)
	 return;

	while (!probingStart && x < 10)
	{
		p_systemStateSettings->msleep(1000);
		lteprobe_begin_cv.notify_one();
		x++;
	}
	if (!probingStart)
	{
		p_systemStateSettings->mHandler(3);

		std::stringstream ss;
		ss << "mHandler fail, line 848...[notifyLteProbeCycle]: exit\n";
		p_systemStateSettings->PrintLogs(ss);
	}

}

void SendLteProbeMsg::sendLteProbe()
{
	std::thread run(std::bind(&SendLteProbeMsg::thread_sendLteProbe, this));
	run.join();
}

void SendLteProbeMsg::receiveProbeAck(int recvProbeAckSeqNum)
{
	recvAckSN = recvProbeAckSeqNum;
	lteprobe_ack_cv.notify_one();
}

void SendLteProbeMsg::thread_sendLteProbe()
{
	for (int i = 0; i < 10; ++i)
	{
		if (sendLteProbeThreadBusy)
		{
			try
			{
				p_systemStateSettings->msleep(1000); 
			}
			catch (const char *e)
			{
				std::cout << e << std::endl;
				i = 3;
			}
		}
		else
		{
			lteprobe_next_cv.notify_one();
			break;
		}
	}
}

//Class send MRP message
SendMRPMsg::SendMRPMsg()
{
	speed = 1000;
	dl_speed = 1000;
	time = 10;
	wifiServer.sin_family = {};
	wifiServer.sin_port = 0;
	lteServer.sin_family = {};
	lteServer.sin_port = 0;
	lteServer.sin_addr = {};
	wifiServer.sin_addr = {};
}

void SendMRPMsg::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}

void SendMRPMsg::updateSettings()
{
	memset(buf, 0, sizeof(buf));
	long lteNrtDownlinkData = 0;
	long lteRtDownlinkData = 0;
	long lteTotalUplinkData = 0;
	long wifiNrtDownlinkData = 0;
	long wifiRtDownlinkData = 0;

	long wifiTotalUplinkData = 0;
	int lteDownlinkNrtThroughput = 0;
	int wifiDownlinkNrtThroughput = 0;
	int lteDownlinkRtThroughput = 0;
	int wifiDownlinkRtThroughput = 0;
	int lteUplinkThroughput = 0;
	int wifiUplinkThroughput = 0;
	ThreadBusy = false; 
	time = p_systemStateSettings->MRPinterval;
}

void SendMRPMsg::Execute()
{
	ThreadBusy = true;
	std::unique_lock<std::mutex> lck(mrp_exit_mtx);
	std::unique_lock<std::mutex> beginlck(mrp_begin_mtx);
	while (p_systemStateSettings->isControlManager && !p_systemStateSettings->gTunAvailable)
	{
		mrp_begin_cv.wait_for(beginlck, std::chrono::seconds(60));
	}

	std::stringstream ss_startmrp;
	ss_startmrp << "starting measurement (MRP)!!!\n";
	p_systemStateSettings->PrintLogs(ss_startmrp);

	std::stringstream ss;
	int wifi_avg_owd = 0;

	while (p_systemStateSettings->isControlManager) //isControlManager == true
	{
		ss.str("");
		buf[30] = (unsigned char)255;
		buf[32] = (unsigned char)((p_systemStateSettings->key & 0xFF000000) >> 24);
		buf[33] = (unsigned char)((p_systemStateSettings->key & 0x00FF0000) >> 16);
		buf[34] = (unsigned char)((p_systemStateSettings->key & 0x0000FF00) >> 8);
		buf[35] = (unsigned char)(p_systemStateSettings->key & 0x000000FF); //key
		buf[36] = (unsigned char)0;
		buf[37] = (unsigned char)0; //sn = 0
		buf[38] = (unsigned char)0;
		buf[39] = (unsigned char)0; // vendor id
		buf[40] = (unsigned char)4; // sub-type: MRPv2 : 4    MRP: 1
		int offset = 49;
		int addLength = 0;
		short count = 0;

		std::istringstream f(p_systemStateSettings->lteIpv4Address);
		std::vector<std::string> lteStrings;
		std::string tmp;
		while (std::getline(f, tmp, '.'))
		{
			lteStrings.push_back(tmp);
		}

		buf[41] = (unsigned char)(std::atoi(lteStrings[0].c_str()) & 0x00FF);
		buf[42] = (unsigned char)(std::atoi(lteStrings[1].c_str()) & 0x00FF);
		buf[43] = (unsigned char)(std::atoi(lteStrings[2].c_str()) & 0x00FF);
		buf[44] = (unsigned char)(std::atoi(lteStrings[3].c_str()) & 0x00FF); //virtual IP

		//add WIFI IP.
		std::istringstream fWifi(p_systemStateSettings->wifiIpv4Address);
		std::vector<std::string> wifiStrings;
		while (std::getline(fWifi, tmp, '.'))
		{
			wifiStrings.push_back(tmp);
		}
		buf[45] = (unsigned char)(std::atoi(wifiStrings[0].c_str()) & 0x00FF);
		buf[46] = (unsigned char)(std::atoi(wifiStrings[1].c_str()) & 0x00FF);
		buf[47] = (unsigned char)(std::atoi(wifiStrings[2].c_str()) & 0x00FF);
		buf[48] = (unsigned char)(std::atoi(wifiStrings[3].c_str()) & 0x00FF); //virtual IP

		for (int i = 0; i < p_systemStateSettings->MRPsize; ++i)
		{
			//aggregate MRPsize measurement reports into one control message
			if ((offset + 40) > p_systemStateSettings->gVnicMTU) //the message is too big
			{
				ss << "[MRP]: current MRP message count/MRPsize:"
				   << count << "/"
				   << p_systemStateSettings->MRPsize << "... msg size too big, break!!!\n";
				p_systemStateSettings->PrintLogs(ss);
				break;
			}
			time = p_systemStateSettings->MRPinterval;
			if (time <= 0 || time >=10000)
   			  time = 30;
			ss.str("");
			ss << "[MRP]: sleep (s): " << time << " i:" << i << std::endl;
			p_systemStateSettings->PrintLogs(ss);
			try
			{
				mrp_exit_cv.wait_for(lck, std::chrono::seconds(time));
			}
			catch (const std::exception &e)
			{
				ss.str("");
				ss << e.what() << '\n';
				p_systemStateSettings->PrintLogs(ss);
			}
			
			if(!p_systemStateSettings->isControlManager)
			{
				break;
			}
			
			PrepareMeasureReport();

			if (!p_systemStateSettings->isControlManager)
			{
				break;
			}

			ss.str("");
			ss << "[MRP]: current MRP message count/MRPsize:"
			   << count << "/" << p_systemStateSettings->MRPsize << std::endl;
			p_systemStateSettings->PrintLogs(ss);

			if (dl_speed > 0)
			{
				buf[offset] = (unsigned char)count;
				addLength = BuildMeasureReportElement(buf, offset);
				offset += addLength;
				count++;
			}

			
			p_systemStateSettings->numOfTsuMessages = 0;		 // the number of transmitted TSU messages
			p_systemStateSettings->numOfReorderingTimeout = 0;	 // the number of reordering timeouts
			p_systemStateSettings->numOfReorderingOverflow = 0; // the number of reordering buffer overflows
			if (p_systemStateSettings->wifiMissingPacketNum + p_systemStateSettings->wifiInorderPacketNum > 0 && p_systemStateSettings->wifiPacketNum > 0)
			{
				ss.str("");
				ss << "GMA measurements: WiFi OWD Min: " << p_systemStateSettings->wifiOwdMin
				   << ",Max: " << p_systemStateSettings->wifiOwdMax << ",Avg: "
				   << (long)(p_systemStateSettings->wifiOwdSum / p_systemStateSettings->wifiPacketNum)
				   << ",Loss Rate: " << 1.0 * (p_systemStateSettings->wifiMissingPacketNum - p_systemStateSettings->wifiAbnormalPacketNum) / (p_systemStateSettings->wifiMissingPacketNum + p_systemStateSettings->wifiInorderPacketNum)
				   << ",inorder Pkts: " << p_systemStateSettings->wifiInorderPacketNum << ",missing Pkts: " << p_systemStateSettings->wifiMissingPacketNum
				   << ",Out-of-order Pkts: " << p_systemStateSettings->wifiAbnormalPacketNum << ",Max Rate(mbps): " << (long)(p_systemStateSettings->wifiRate * 8 / 1000) << std::endl;
				p_systemStateSettings->PrintLogs(ss);
				wifi_avg_owd = (int)(p_systemStateSettings->wifiOwdSum / p_systemStateSettings->wifiPacketNum);
			}

			if (p_systemStateSettings->currentTimeMs > 0x0FFFFFFF || wifi_avg_owd < -1000 || wifi_avg_owd > 1000)
			{ //sync again every 74 hours
				p_systemStateSettings->mHandler(2);
				ss << "wifi_avg_owd:" << wifi_avg_owd << " Sync Again!\n"; //mhandler.sendEmptyMessage(2);
				p_systemStateSettings->PrintLogs(ss);
			}


			//realtime traffic
			if (p_systemStateSettings->wifiRtMissingPacketNum + p_systemStateSettings->wifiRtInorderPacketNum > 0 && p_systemStateSettings->wifiRtPacketNum > 0)
			{
				ss.str("");
				ss << "GMA [RT]: WiFi OWD Min: " << p_systemStateSettings->wifiRtOwdMin << ",Max: " << p_systemStateSettings->wifiRtOwdMax
				   << ",Avg: " << (long)(p_systemStateSettings->wifiRtOwdSum / p_systemStateSettings->wifiRtPacketNum) << ",Loss Rate: "
				   << (double)(1.0 * (p_systemStateSettings->wifiRtMissingPacketNum - p_systemStateSettings->wifiRtAbnormalPacketNum) / (p_systemStateSettings->wifiRtMissingPacketNum + p_systemStateSettings->wifiRtInorderPacketNum))
				   << ",inorder Pkts: " << p_systemStateSettings->wifiRtInorderPacketNum << ",missing Pkts: " << p_systemStateSettings->wifiRtMissingPacketNum
				   << ",Out-of-order Pkts: " << p_systemStateSettings->wifiRtAbnormalPacketNum << std::endl;
				p_systemStateSettings->PrintLogs(ss);
			}
			if (p_systemStateSettings->lteMissingPacketNum + p_systemStateSettings->lteInorderPacketNum > 0 && p_systemStateSettings->ltePacketNum > 0)
			{
				ss.str("");
				ss << "GMA measurements: LTE OWD Min: " << p_systemStateSettings->lteOwdMin << ",Max: " << p_systemStateSettings->lteOwdMax
				   << ",Avg: " << (long)(p_systemStateSettings->lteOwdSum / p_systemStateSettings->ltePacketNum) << ",Loss Rate: "
				   << (double)(1.0 * (p_systemStateSettings->lteMissingPacketNum - p_systemStateSettings->lteAbnormalPacketNum) / (p_systemStateSettings->lteMissingPacketNum + p_systemStateSettings->lteInorderPacketNum))
				   << ",inorder Pkts: " << p_systemStateSettings->lteInorderPacketNum << ",missing Pkts: " << p_systemStateSettings->lteMissingPacketNum
				   << ",Out-of-order Pkts: " << p_systemStateSettings->lteAbnormalPacketNum << ",Max Rate(mbps): " << (long)(p_systemStateSettings->lteRate * 8 / 1000) << std::endl;
				p_systemStateSettings->PrintLogs(ss);
			}

			//realtime traffic
			if (p_systemStateSettings->lteRtMissingPacketNum + p_systemStateSettings->lteRtInorderPacketNum > 0 && p_systemStateSettings->lteRtPacketNum > 0)
			{
				ss.str("");
				ss << "GMA [RT]: LTE OWD Min: " << p_systemStateSettings->lteRtOwdMin << ",Max: " << p_systemStateSettings->lteRtOwdMax
				   << ",Avg: " << (long)(p_systemStateSettings->lteRtOwdSum / p_systemStateSettings->lteRtPacketNum) << ",Loss Rate: "
				   << (double)(1.0 * (p_systemStateSettings->lteRtMissingPacketNum - p_systemStateSettings->lteRtAbnormalPacketNum) / (p_systemStateSettings->lteRtMissingPacketNum + p_systemStateSettings->lteRtInorderPacketNum))
				   << ",inorder Pkts: " << p_systemStateSettings->lteRtInorderPacketNum << ",missing Pkts: " << p_systemStateSettings->lteRtMissingPacketNum
				   << ",Out-of-order Pkts: " << p_systemStateSettings->lteRtAbnormalPacketNum << std::endl;
				;
				p_systemStateSettings->PrintLogs(ss);
			}
			if (p_systemStateSettings->ENABLE_FLOW_MEASUREMENT)
			{
				if (p_systemStateSettings->flowOwdPacketNum > 0)
				{
					//the abnormal packets for flow measurement maybe big due to duplicate mode, e.g.,g 32-1, 32-2...
					ss.str("");
					ss << "GMA flow measurements"
					   << " OWD Min: " << p_systemStateSettings->flowOwdMin << ",Max: " << p_systemStateSettings->flowOwdMax
					   << ",Avg: " << (long)(p_systemStateSettings->flowOwdSum / p_systemStateSettings->flowOwdPacketNum)
					   << " Loss: " << (double)(1.0 * (p_systemStateSettings->flowMissingPacketNum - p_systemStateSettings->flowAbnormalPacketNum) / (p_systemStateSettings->flowMissingPacketNum + p_systemStateSettings->flowInorderPacketNum))
					   << " inorder: " << p_systemStateSettings->flowInorderPacketNum
					   << " missing: " << p_systemStateSettings->flowMissingPacketNum
					   << " abnormal: " << p_systemStateSettings->flowAbnormalPacketNum << std::endl;
					p_systemStateSettings->PrintLogs(ss);
					//bug 
					/*
					if (p_systemStateSettings->lteInorderPacketNum + p_systemStateSettings->wifiInorderPacketNum == 0)
  						p_systemStateSettings->GMAIPCMessage(1, 0, 0, false, 0); //controlManager.sendTSUMsg();
					*/
				}
				p_systemStateSettings->flowInorderPacketNum = 0;
				p_systemStateSettings->flowMissingPacketNum = 0;
				p_systemStateSettings->flowAbnormalPacketNum = 0;
				p_systemStateSettings->flowOwdMax = INT_MIN;
				;
				p_systemStateSettings->flowOwdMin = INT_MAX;
				p_systemStateSettings->flowOwdSum = 0;
				p_systemStateSettings->flowOwdPacketNum = 0;
			}
			ss.str("");
			ss << "test parameter " << int(p_systemStateSettings->nonRealtimelModeFlowId) << ":" << std::endl;
			p_systemStateSettings->PrintLogs(ss);
			
			//update maxReorderingDelay
			/*
			int avg_lteOwd = 0; 
			if (p_systemStateSettings->ltePacketNum > 0)
				avg_lteOwd = p_systemStateSettings->lteOwdSum / p_systemStateSettings->ltePacketNum;
			int avg_wifiOwd = 0;
			if (p_systemStateSettings->wifiPacketNum > 0)
				avg_wifiOwd = p_systemStateSettings->wifiOwdSum / p_systemStateSettings->wifiPacketNum;
			
			int avg_RtlteOwd = 0;
			if (p_systemStateSettings->lteRtPacketNum > 0)
				avg_RtlteOwd = p_systemStateSettings->lteRtOwdSum / p_systemStateSettings->lteRtPacketNum;
			int avg_RtwifiOwd = 0;
			if (p_systemStateSettings->wifiRtPacketNum > 0)
				avg_RtwifiOwd = p_systemStateSettings->wifiRtOwdSum / p_systemStateSettings->wifiRtPacketNum;

			if (avg_lteOwd < avg_wifiOwd)
				p_systemStateSettings->maxReorderingDelay = avg_wifiOwd + p_systemStateSettings->MIN_MAXREORDERINGDELAY;
			else
				p_systemStateSettings->maxReorderingDelay = avg_lteOwd + p_systemStateSettings->MIN_MAXREORDERINGDELAY;
			
			if (avg_RtlteOwd < avg_RtwifiOwd)
				p_systemStateSettings->HRreorderingTimeout = avg_RtwifiOwd + p_systemStateSettings->MIN_MAXREORDERINGDELAY;
			else
				p_systemStateSettings->HRreorderingTimeout = avg_RtlteOwd + p_systemStateSettings->MIN_MAXREORDERINGDELAY;
			*/
			
			
			if (p_systemStateSettings->wifiRtPacketNum == 0)
				p_systemStateSettings->wifiRtOwdMax = 0;
			if (p_systemStateSettings->lteRtPacketNum == 0)
				p_systemStateSettings->lteRtOwdMax = 0;

			int owd_diff_lte_to_wifi = p_systemStateSettings->lteRtOwdMax - p_systemStateSettings->wifiRtOwdMin;
			int owd_diff_wifi_to_lte = p_systemStateSettings->wifiRtOwdMax - p_systemStateSettings->lteRtOwdMin;

			if (owd_diff_lte_to_wifi > owd_diff_wifi_to_lte)
					p_systemStateSettings->HRreorderingTimeout = owd_diff_lte_to_wifi  + 20 ;
			else
					p_systemStateSettings->HRreorderingTimeout = owd_diff_wifi_to_lte  + 20;

			if (p_systemStateSettings->HRreorderingTimeout < p_systemStateSettings->MIN_MAXREORDERINGDELAY)
				p_systemStateSettings->HRreorderingTimeout = p_systemStateSettings->MIN_MAXREORDERINGDELAY;
			else if (p_systemStateSettings->HRreorderingTimeout > p_systemStateSettings->MAX_MAXREORDERINGDELAY)
				p_systemStateSettings->HRreorderingTimeout = p_systemStateSettings->MAX_MAXREORDERINGDELAY;
				
			p_systemStateSettings->GMAIPCMessage(16, p_systemStateSettings->HRreorderingTimeout, p_systemStateSettings->maxReorderingDelay, false, 0); //update reordering timer


			ss.str("");
			ss << "GMA measurements: Reordering Timer nrt" << p_systemStateSettings->maxReorderingDelay << " hr: " << p_systemStateSettings->HRreorderingTimeout << std::endl;
			p_systemStateSettings->PrintLogs(ss);
			p_systemStateSettings->wifiInorderPacketNum = 0;
			p_systemStateSettings->wifiMissingPacketNum = 0;
			p_systemStateSettings->wifiAbnormalPacketNum = 0;

			p_systemStateSettings->wifiRtOwdSum = 0;
			p_systemStateSettings->wifiRtPacketNum = 0;
			p_systemStateSettings->wifiRtOwdMax = INT_MIN;
			p_systemStateSettings->wifiRtOwdMin = INT_MAX;
			p_systemStateSettings->wifiRtInorderPacketNum = 0;
			p_systemStateSettings->wifiRtMissingPacketNum = 0;
			p_systemStateSettings->wifiRtAbnormalPacketNum = 0;

			p_systemStateSettings->lteInorderPacketNum = 0;
			p_systemStateSettings->lteMissingPacketNum = 0;
			p_systemStateSettings->lteAbnormalPacketNum = 0;

			p_systemStateSettings->lteRtOwdSum = 0;
			p_systemStateSettings->lteRtPacketNum = 0;
			p_systemStateSettings->lteRtOwdMax = INT_MIN;
			p_systemStateSettings->lteRtOwdMin = INT_MAX;
			p_systemStateSettings->lteRtInorderPacketNum = 0;
			p_systemStateSettings->lteRtMissingPacketNum = 0;
			p_systemStateSettings->lteRtAbnormalPacketNum = 0;

			p_systemStateSettings->numOfLteLinkFailure = 0;
			p_systemStateSettings->numOfWifiLinkFailure = 0;
			p_systemStateSettings->numOfTsuLinkFailure = 0;
		}

		if (count > 0)
		{

			ipHeader.init(buf, p_systemStateSettings->sizeofGMAMessageHeader); //conflict with packetheader
			udpHeader.init(buf, p_systemStateSettings->sizeofGMAMessageHeader + 20);
			//duplicate initialization for ip/udp header......

			ipHeader.setTotalLength(offset - p_systemStateSettings->sizeofGMAMessageHeader);
			ipHeader.setSum((short)0);
			ipHeader.setSum((short)ipHeader.checksum(0, buf, p_systemStateSettings->sizeofGMAMessageHeader, 20));
			udpHeader.setTotalLength(offset - p_systemStateSettings->sizeofGMAMessageHeader - 20);
			udpHeader.setSum((short)0);
			if (p_systemStateSettings->gIsWifiConnect)
			{
				buf[31] = (unsigned char)0; //CID wifi
				try
				{
					//send(wifiudpFd, buf, offset, 0); //JZ: the buf length should be variable depending on "count"
					if (sendto(wifiudpFd, (char *)buf, offset, 0, (struct sockaddr *)&wifiServer, sizeof(wifiServer)) <= 0)
					 printf("\n sendto error");

					ss.str("");
					ss << "[MRP END] send over wifi!!!! size: " << (count + 1) << std::endl;
					p_systemStateSettings->PrintLogs(ss);
				}
				catch (const std::exception &e)
				{
					ss.str("");
					ss << e.what() << '\n';
					p_systemStateSettings->PrintLogs(ss);
				}
			}
			else if (p_systemStateSettings->gIsLteConnect)
			{
				buf[31] = (unsigned char)3; //CID lte
			    if (sendto(lteudpFd, (char *)buf, offset, 0, (struct sockaddr *)&lteServer, sizeof(lteServer)) <= 0)
					  printf("\n setsocketopt error\n");
					ss.str("");
					ss << "[MRP END] send over lte!!!! size: " << (count + 1) << std::endl;
					p_systemStateSettings->PrintLogs(ss);
			
			}
		}
	}
	ss.str("");
	ss << "[MRP message thread]: exit\n";
	p_systemStateSettings->PrintLogs(ss);
	ThreadBusy = false;
	return;
}

void SendMRPMsg::BuildPacketHeader()
{
	gmaMessageHeader.init(buf, 0);
	ipHeader.init(buf, p_systemStateSettings->sizeofGMAMessageHeader);
	udpHeader.init(buf, p_systemStateSettings->sizeofGMAMessageHeader + 20);
	gmaMessageHeader.setGMAMessageHeader((short)0x0);

	buf[p_systemStateSettings->sizeofGMAMessageHeader] = 0x45;

	ipHeader.setTos((unsigned char)0);
	ipHeader.setTotalLength(buf_size - p_systemStateSettings->sizeofGMAMessageHeader);
	ipHeader.setIdentification(0);
	ipHeader.setFlagsAndOffset((short)0x4000);
	ipHeader.setTTL((unsigned char)64);
	ipHeader.setDestinationIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicGw));
	ipHeader.setProtocol((unsigned char)0x11);
	ipHeader.setSourceIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicIp));
	ipHeader.setSum((short)0);
	ipHeader.setSum((short)ipHeader.checksum(0, buf, p_systemStateSettings->sizeofGMAMessageHeader, 20));

	udpHeader.setDestinationPort((short)p_systemStateSettings->serverUdpPort);
	udpHeader.setSourcePort((short)p_systemStateSettings->clientProbePort);
	udpHeader.setTotalLength(buf_size - p_systemStateSettings->sizeofGMAMessageHeader - 20);
	udpHeader.setSum((short)0);
}

int SendMRPMsg::BuildMeasureReportElement(unsigned char *buf, int offset)
{
	int currentTime = (int)(p_systemStateSettings->update_current_time_params() & 0x7FFFFFFF); //(int)(System.currentTimeMillis() + SystemStateSettings.gStartTime)&0x7FFFFFFF;
	//(1)timestamp: second
	buf[offset + 1] = (unsigned char)(((currentTime / 1000) & 0x0000FF00) >> 8);
	buf[offset + 2] = (unsigned char)((currentTime / 1000) & 0x000000FF);

	//(2) total down link throughput(kBps)
	buf[offset + 3] = (unsigned char)((dl_speed & 0x0000FF00) >> 8);
	buf[offset + 4] = (unsigned char)(dl_speed & 0x000000FF);

	//(3) wifi/lte down link Tx rate(kBps)
	buf[offset + 5] = (unsigned char)((p_systemStateSettings->wifiRate & 0x0000FF00) >> 8);
	buf[offset + 6] = (unsigned char)(p_systemStateSettings->wifiRate & 0x000000FF); //wifi down link Tx rate(kBps)
	buf[offset + 7] = (unsigned char)((p_systemStateSettings->lteRate & 0x0000FF00) >> 8);
	buf[offset + 8] = (unsigned char)(p_systemStateSettings->lteRate & 0x000000FF); //lte down link Tx rate(kBps)

	//(4) RSSI
	buf[offset + 9] = (unsigned char)(p_systemStateSettings->wifiRssi & 0x000000FF); //wifi rssi(-dBm)
	buf[offset + 10] = (unsigned char)(p_systemStateSettings->lteRssi & 0x000000FF); //lte rssi(-dBm)

	//(5) last RTT
	buf[offset + 11] = (unsigned char)(p_systemStateSettings->wifiLinkRtt & 0x000000FF); //last wifi RTT(ms)
	buf[offset + 12] = (unsigned char)(p_systemStateSettings->lteLinkRtt & 0x000000FF);  //last lte RTT(ms)

	//(6)num of tsu message exchanges(per second)
	buf[offset + 13] = (unsigned char)((int)(std::round(p_systemStateSettings->numOfTsuMessages / time)) & 0x000000FF);
	//(7)num of reordering timeout
	buf[offset + 14] = (unsigned char)(p_systemStateSettings->numOfReorderingTimeout & 0x000000FF);
	//(8)num of reordering buffer over flows
	buf[offset + 15] = (unsigned char)(p_systemStateSettings->numOfReorderingOverflow & 0x000000FF);

	//(9)num of link failures
	buf[offset + 16] = (unsigned char)(p_systemStateSettings->numOfWifiLinkFailure & 0x000000FF); //num of wifi link failures
	buf[offset + 17] = (unsigned char)(p_systemStateSettings->numOfLteLinkFailure & 0x000000FF);  //num of lte link failures

	//(10)min OWD diff(ms); is this one correct??????
	buf[offset + 18] = (unsigned char)(p_systemStateSettings->wifiOwdOffset);

	int rtOffset = 0;
	short rtBit = 0;
	int downlinkRtThroughput = wifiDownlinkRtThroughput + lteDownlinkRtThroughput;
	if (downlinkRtThroughput > 0)
	{
		rtOffset = 10;
		rtBit = 128;
		//(RT1) total throughput
		buf[offset + 20] = (unsigned char)((downlinkRtThroughput & 0x0000FF00) >> 8);
		buf[offset + 21] = (unsigned char)(downlinkRtThroughput & 0x000000FF);

		//(RT2) wifi throughput ratio
		buf[offset + 22] = (unsigned char)(wifiDownlinkRtThroughput == 0 ? 0 : ((wifiDownlinkRtThroughput * 100 / downlinkRtThroughput)) & 0x000000FF); //wifi down link throughput ratio

		//(RT3) OWD range wifi/lte
		if (p_systemStateSettings->wifiRtPacketNum < p_systemStateSettings->minPktsample)
		{
			buf[offset + 23] = -1;
		}
		else
		{
			buf[offset + 23] = (unsigned char)((p_systemStateSettings->wifiRtOwdMax - p_systemStateSettings->wifiRtOwdMin) & 0x0000007F); //wifi OWD range(ms)
		}
		if (p_systemStateSettings->lteRtPacketNum < p_systemStateSettings->minPktsample)
		{
			buf[offset + 24] = -1;
		}
		else
		{
			buf[offset + 24] = (unsigned char)((p_systemStateSettings->lteRtOwdMax - p_systemStateSettings->lteRtOwdMin) & 0x0000007F); //lte OWD range(ms)
		}
		//(RT4) ave owd diff wifi- lte
		if (p_systemStateSettings->wifiRtPacketNum < p_systemStateSettings->minPktsample || p_systemStateSettings->lteRtPacketNum < p_systemStateSettings->minPktsample)
		{
			buf[offset + 25] = (unsigned char)0; //average OWD difference
		}
		else
		{
			buf[offset + 25] = (unsigned char)(p_systemStateSettings->wifiRtOwdSum / p_systemStateSettings->wifiRtPacketNum - p_systemStateSettings->lteRtOwdSum / p_systemStateSettings->lteRtPacketNum); //average OWD difference
		}

		//(RT5) LOSS wifi/lte
		int numOfWifiPackets = p_systemStateSettings->wifiRtMissingPacketNum + p_systemStateSettings->wifiRtInorderPacketNum;
		int numoflostPackets = p_systemStateSettings->wifiRtMissingPacketNum - p_systemStateSettings->wifiRtAbnormalPacketNum;
		if (numOfWifiPackets == 0 || numoflostPackets <= 0)
		{
			buf[offset + 26] = (unsigned char)127; //packet loss = 0
		}
		else
		{
			buf[offset + 26] = (unsigned char)((int)(std::round(std::abs(std::log10(numOfWifiPackets / numoflostPackets)))) & 0x000000FF); //wifi down link log(1/packet_loss_rate)
		}

		//int numOfLtePackets = p_systemStateSettings->lteMissingPacketNum - p_systemStateSettings->lteAbnormalPacketNum + p_systemStateSettings->lteInorderPacketNum;
		int numOfLtePackets = p_systemStateSettings->lteRtMissingPacketNum + p_systemStateSettings->lteRtInorderPacketNum;
		numoflostPackets = p_systemStateSettings->lteRtMissingPacketNum - p_systemStateSettings->lteRtAbnormalPacketNum;
		if (numOfLtePackets == 0 || numoflostPackets <= 0)
		{
			buf[offset + 27] = (unsigned char)127; //packet loss = 0
		}
		else
		{
			buf[offset + 27] = (unsigned char)((int)(std::round(std::abs(std::log10(numOfLtePackets / numoflostPackets)))) & 0x000000FF); //lte down link log(1/packet_loss_rate)
		}

		//(RT6) out of order packet per wifi/lte
		buf[offset + 28] = (unsigned char)((p_systemStateSettings->wifiRtAbnormalPacketNum / time) & 0x000000FF); //wifi down link out of packet count
		buf[offset + 29] = (unsigned char)((p_systemStateSettings->lteRtAbnormalPacketNum / time) & 0x000000FF);  //lte up link out of packet count
	}

	int nrtOffset = 0;
	short nrtBit = 0;
	int downlinkNrtThroughput = wifiDownlinkNrtThroughput + lteDownlinkNrtThroughput;
	if (downlinkNrtThroughput > 0)
	{
		//nrtOffset = 10;   MRP
		nrtOffset = 13; //MRP2
		nrtBit = 64;
		//(NRT1) total throughput
		buf[offset + rtOffset + 20] = (unsigned char)((downlinkNrtThroughput & 0x0000FF00) >> 8);
		buf[offset + rtOffset + 21] = (unsigned char)(downlinkNrtThroughput & 0x000000FF);

		//(NRT2) wifi throughput ratio
		buf[offset + rtOffset + 22] = (unsigned char)(wifiDownlinkNrtThroughput == 0 ? 0 : ((wifiDownlinkNrtThroughput * 100 / downlinkNrtThroughput)) & 0x000000FF); //wifi down link throughput ratio

		//(NRT3) OWD range wifi/lte
		if (p_systemStateSettings->wifiPacketNum < p_systemStateSettings->minPktsample)
		{
			buf[offset + rtOffset + 23] = -1;
		}
		else
		{
			buf[offset + rtOffset + 23] = (unsigned char)((p_systemStateSettings->wifiOwdMax - p_systemStateSettings->wifiOwdMin) & 0x0000007F); //wifi OWD range(ms)
		}
		if (p_systemStateSettings->ltePacketNum < p_systemStateSettings->minPktsample)
		{
			buf[offset + rtOffset + 24] = -1;
		}
		else
		{
			buf[offset + rtOffset + 24] = (unsigned char)((p_systemStateSettings->lteOwdMax - p_systemStateSettings->lteOwdMin) & 0x0000007F); //lte OWD range(ms)
		}

/*
		if (p_systemStateSettings->wifiOwdMin != INT_MAX && p_systemStateSettings->lteOwdMin != INT_MAX)
		    p_systemStateSettings->wifiOwdOffset = p_systemStateSettings->wifiOwdMin - p_systemStateSettings->lteOwdMin;
		else
		    p_systemStateSettings->wifiOwdOffset = 0;
*/	

	    //(NRT4) ave owd diff wifi- lte
		if (p_systemStateSettings->wifiPacketNum < p_systemStateSettings->minPktsample || p_systemStateSettings->ltePacketNum < p_systemStateSettings->minPktsample)
		{
			buf[offset + rtOffset + 25] = (unsigned char)0; //average OWD difference
		//	p_systemStateSettings->wifiOwdOffset = 0;
			buf[offset + rtOffset + 32] = 0;
		}
		else
		{
			buf[offset + rtOffset + 25] = (unsigned char)(p_systemStateSettings->wifiOwdSum / p_systemStateSettings->wifiPacketNum - p_systemStateSettings->lteOwdSum / p_systemStateSettings->ltePacketNum); //average OWD difference
			//we only use NRT traffic to set the wifi offset!
			if (p_systemStateSettings->flowOwdPacketNum < p_systemStateSettings->minPktsample)
				buf[offset + rtOffset + 32] = 0;
			else
				buf[offset + rtOffset + 32] = (unsigned char)(p_systemStateSettings->wifiOwdSum / p_systemStateSettings->wifiPacketNum -
															  p_systemStateSettings->flowOwdSum / p_systemStateSettings->flowOwdPacketNum);
		}

		//(NRT5) LOSS wifi/lte
		//int numOfWifiPackets = p_systemStateSettings->wifiMissingPacketNum - p_systemStateSettings->wifiAbnormalPacketNum + p_systemStateSettings->wifiInorderPacketNum;
		int numOfWifiPackets = p_systemStateSettings->wifiMissingPacketNum + p_systemStateSettings->wifiInorderPacketNum;
		int numoflostPackets = p_systemStateSettings->wifiMissingPacketNum - p_systemStateSettings->wifiAbnormalPacketNum;
		if (numOfWifiPackets == 0 || numoflostPackets <= 0)
		{
			buf[offset + rtOffset + 26] = (unsigned char)127; //packet loss = 0
		}
		else
		{
			buf[offset + rtOffset + 26] = (unsigned char)((int)(std::round(std::abs(std::log10(numOfWifiPackets / numoflostPackets)))) & 0x000000FF); //wifi down link log(1/packet_loss_rate)
		}

		//int numOfLtePackets = p_systemStateSettings->lteMissingPacketNum - p_systemStateSettings->lteAbnormalPacketNum + p_systemStateSettings->lteInorderPacketNum;
		int numOfLtePackets = p_systemStateSettings->lteMissingPacketNum + p_systemStateSettings->lteInorderPacketNum;
		numoflostPackets = p_systemStateSettings->lteMissingPacketNum - p_systemStateSettings->lteAbnormalPacketNum;
		if (numOfLtePackets == 0 || numoflostPackets <= 0)
		{
			buf[offset + rtOffset + 27] = (unsigned char)127; //packet loss = 0
		}
		else
		{
			buf[offset + rtOffset + 27] = (unsigned char)((int)(std::round(std::abs(std::log10(numOfLtePackets / numoflostPackets)))) & 0x000000FF); //lte down link log(1/packet_loss_rate)
		}
		//(NRT6) out of order packet per wifi/lte
		buf[offset + rtOffset + 28] = (unsigned char)((p_systemStateSettings->wifiAbnormalPacketNum / time) & 0x000000FF); //wifi down link out of packet count
		buf[offset + rtOffset + 29] = (unsigned char)((p_systemStateSettings->lteAbnormalPacketNum / time) & 0x000000FF);	//lte up link out of packet count

		//Flow Measurement (MRPv2)
		int numOfflowPackets = p_systemStateSettings->flowMissingPacketNum + p_systemStateSettings->flowInorderPacketNum;
		int numofflowlostPackets = p_systemStateSettings->flowMissingPacketNum - p_systemStateSettings->flowAbnormalPacketNum;

		if (p_systemStateSettings->flowOwdPacketNum >= p_systemStateSettings->minPktsample)
		{
			buf[offset + rtOffset + 30] = (unsigned char)((p_systemStateSettings->flowOwdMax - p_systemStateSettings->flowOwdMin) & 0x0000007F);
		}
		else
			buf[offset + rtOffset + 30] = -1;

		if (numOfflowPackets == 0 || numofflowlostPackets <= 0)
		{
			buf[offset + rtOffset + 31] = (unsigned char)127; //packet loss = 0
		}
		else
		{
			buf[offset + rtOffset + 31] = (unsigned char)((int)(std::round(std::abs(std::log10(numOfflowPackets / numofflowlostPackets)))) & 0x000000FF); //wifi down link log(1/packet_loss_rate)
		}
		//buf[offset + rtOffset + 32]
		//next: 33
		//Log.v("MRP[NRT6]", "wifi out order:" + buf[offset + rtOffset + 28] + ", lte out order:" + buf[offset + rtOffset + 29]);
	}
	buf[offset + 19] = (unsigned char)(nrtBit + rtBit);
	//Log.v("MRP[11]", "flag:" + buf[offset + 19]);
	//max payload = 1 byte (count) + 19 bytes (fixed header), 10 optional bytes (realtime) + 10 optional bytes (non-realtime);
	return 20 + rtOffset + nrtOffset;
}

void SendMRPMsg::PrepareMeasureReport()
{

	int currentTime = (int)(p_systemStateSettings->update_current_time_params() & 0x7FFFFFFF); //(int)(System.currentTimeMillis() + SystemStateSettings.gStartTime)&0x7FFFFFFF;

	if (p_systemStateSettings->serverTcpPort != 0)
	{ //do not open TCP socket if the port is set to 0.
		std::stringstream ss;
		if (p_systemStateSettings->gDLAllOverLte)
		{
			ss << "Measured service MRP, openTCPsocket lte\n";
			p_systemStateSettings->PrintLogs(ss);
			p_systemStateSettings->GMAIPCMessage(12, 0, 0, false, 0);
			//serviceManager.OpenLteTcpSocketChannel(); //open a lte tcp socket channel if not open yet
		}
		else
		{
			if (p_systemStateSettings->gIsWifiConnect)
			{
				ss.str("");
				ss << "Measured service MRP, openTCPsocket wifi\n";
				p_systemStateSettings->PrintLogs(ss);
				p_systemStateSettings->GMAIPCMessage(13, 0, 0, false, 0);
				//serviceManager.OpenWifiTcpSocketChannel(); //open a wifi tcp socket channel if not open yet
			}
		}

		if (!p_systemStateSettings->gIsWifiConnect || currentTime - p_systemStateSettings->lastReceiveWifiWakeUpReq > 3600000)
		{
			//close the wakeup socket if the link is disconnected or no activity in an hours
			ss.str("");
			ss << "Measured service MRP, closeTCPsocket wifi\n";
			p_systemStateSettings->PrintLogs(ss);
			//serviceManager.CloseWifiTcpSocketChannel();
			p_systemStateSettings->GMAIPCMessage(14, 0, 0, false, 0);
			p_systemStateSettings->lastReceiveWifiWakeUpReq = currentTime;
		}

		if (!p_systemStateSettings->gIsLteConnect || currentTime - p_systemStateSettings->lastReceiveLteWakeUpReq > 3600000)
		{
			ss.str("");
			ss << "Measured service MRP, closeTCPsocket lte\n";
			p_systemStateSettings->PrintLogs(ss);
			//serviceManager.CloseLteTcpSocketChannel();
			p_systemStateSettings->GMAIPCMessage(15, 0, 0, false, 0);
			p_systemStateSettings->lastReceiveLteWakeUpReq = currentTime;
		}
	}
	lteDownlinkNrtThroughput = (int)((p_systemStateSettings->lteReceiveNrtBytes - lteNrtDownlinkData) / (time)) / 1000; //kBps
	lteDownlinkRtThroughput = (int)((p_systemStateSettings->lteReceiveRtBytes - lteRtDownlinkData) / (time)) / 1000;	 //kBps

	lteUplinkThroughput = (int)((p_systemStateSettings->lteSendBytes - lteTotalUplinkData) / (time)) / 1000;
	wifiDownlinkNrtThroughput = (int)((p_systemStateSettings->wifiReceiveNrtBytes - wifiNrtDownlinkData) / (time)) / 1000;
	wifiDownlinkRtThroughput = (int)((p_systemStateSettings->wifiReceiveRtBytes - wifiRtDownlinkData) / (time)) / 1000;

	wifiUplinkThroughput = (int)((p_systemStateSettings->wifiSendBytes - wifiTotalUplinkData) / (time)) / 1000;

	lteNrtDownlinkData = p_systemStateSettings->lteReceiveNrtBytes;
	lteRtDownlinkData = p_systemStateSettings->lteReceiveRtBytes;
	lteTotalUplinkData = p_systemStateSettings->lteSendBytes;
	wifiNrtDownlinkData = p_systemStateSettings->wifiReceiveNrtBytes;
	wifiRtDownlinkData = p_systemStateSettings->wifiReceiveRtBytes;
	wifiTotalUplinkData = p_systemStateSettings->wifiSendBytes;

	speed = lteDownlinkNrtThroughput + lteDownlinkRtThroughput + lteUplinkThroughput + wifiDownlinkNrtThroughput + wifiDownlinkRtThroughput + wifiUplinkThroughput;
	dl_speed = lteDownlinkNrtThroughput + lteDownlinkRtThroughput + wifiDownlinkNrtThroughput + wifiDownlinkRtThroughput;

	p_systemStateSettings->wifiRssi = 0;
	p_systemStateSettings->lteRssi = 0;

	if (p_systemStateSettings->gWifiFlag)
	{
			p_systemStateSettings->wifiRssi = p_systemStateSettings->GetWifiRssiStrength();
			std::stringstream ss;
			ss << "Measured service MRP wifi rssi:" << p_systemStateSettings->wifiRssi << std::endl;
			p_systemStateSettings->PrintLogs(ss);

			if (p_systemStateSettings->wifiRssi < p_systemStateSettings->wifiHighRssi && !p_systemStateSettings->gLteFlag)
			{
			}

			if (p_systemStateSettings->wifiRssi < p_systemStateSettings->wifiLowRssi)
			{
				if (p_systemStateSettings->gIsLteConnect && !p_systemStateSettings->gDLAllOverLte)
				{
					p_systemStateSettings->wifiSplitFactor = 0;
					p_systemStateSettings->lteSplitFactor = p_systemStateSettings->paramL;
					p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg();
					p_systemStateSettings->wifiIndexChangeAlpha = 0;
					p_systemStateSettings->gDLAllOverLte = true;
					p_systemStateSettings->GMAIPCMessage(3,0,0,false,0); //controlManager.sendLteProbe(); //reset WiFi probe interval
				}
			}
			else if (p_systemStateSettings->wifiRssi > p_systemStateSettings->wifiHighRssi)
			{
				if (p_systemStateSettings->gIsWifiConnect && p_systemStateSettings->gDLAllOverLte)
				{
					p_systemStateSettings->gDLAllOverLte = false;
					p_systemStateSettings->GMAIPCMessage(2,0,0,false,0); //controlManager.sendWifiProbe();  //reset WiFi probe interval
					p_systemStateSettings->wifiSplitFactor = p_systemStateSettings->paramL;
					p_systemStateSettings->lteSplitFactor = 0;
					p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg(); //sendTSUMsg.sendTSUMsg();
					p_systemStateSettings->wifiIndexChangeAlpha = 0;
				}
			}
	}

	p_systemStateSettings->MRPinterval = p_systemStateSettings->MRPintervalActive;

	if (p_systemStateSettings->wifiPacketNum < time * 3 || !p_systemStateSettings->gIsLteConnect) // low traffic activity or LTE not connected
	{
		p_systemStateSettings->wifiProbeTh = INT_MAX;
		p_systemStateSettings->wifiProbeTimeout = 1000;
	}
	else
	{
		p_systemStateSettings->wifiProbeTh = (int)(time * 1000 * 5 / p_systemStateSettings->wifiPacketNum);
		if (p_systemStateSettings->wifiProbeTh < 50) //min = 50ms
			p_systemStateSettings->wifiProbeTh = 50;

		if (p_systemStateSettings->wifiLinkMaxRtt > 0)
		{
			p_systemStateSettings->wifiProbeTimeout = p_systemStateSettings->wifiLinkMaxRtt * 2;
			if (p_systemStateSettings->wifiProbeTimeout < 100) //min timeout = 100ms
				p_systemStateSettings->wifiProbeTimeout = 100;
		}
		else
			p_systemStateSettings->wifiProbeTimeout = 1000;
	}

	p_systemStateSettings->wifiLinkMaxRtt = 0;

	if (speed < p_systemStateSettings->minTpt)
	{
		p_systemStateSettings->MRPinterval = p_systemStateSettings->MRPintervalIdle;
		if (!p_systemStateSettings->gWifiFlag)
		{
			if (currentTime - p_systemStateSettings->gDisconnectWifiTime > p_systemStateSettings->idleTimer * 1000 * 60)
			{
				p_systemStateSettings->mHandler(3);
				std::stringstream ss;
				ss << "mHandler fail, line 2064...[MRP idle]: exit\n";
				p_systemStateSettings->PrintLogs(ss);
				return;
			}
		}
		else if (!p_systemStateSettings->gScreenOnFlag && p_systemStateSettings->wifiRssi > p_systemStateSettings->wifiHighRssi && !p_systemStateSettings->gDLAllOverLte && p_systemStateSettings->gUlRToverLteFlag == 0 && p_systemStateSettings->gDlRToverLteFlag == 0 && p_systemStateSettings->gLteAlwaysOnFlag == 0 && p_systemStateSettings->gLteFlag && p_systemStateSettings->stopLterequest && p_systemStateSettings->gIsWifiConnect && currentTime - p_systemStateSettings->gLastScreenOffTime > 30 * 60 * 1000)
		{
		}
	}
	else
	{
		if (!p_systemStateSettings->gLteFlag)
		{
		}
		else if (!p_systemStateSettings->gIsWifiConnect && p_systemStateSettings->gWifiFlag)
		{
			p_systemStateSettings->GMAIPCMessage(2,0,0,false,0); //controlManager.sendWifiProbe(); //sendWifiProbeMsg.sendWifiProbe();
			//sendWifiProbe(); //probing to check if Wi-Fi is connected
		}

		if (p_systemStateSettings->wifiSplitFactor == 0 || p_systemStateSettings->lteSplitFactor == 0) //send TSU to reset TX OWD offset
		{
			p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg();
		}

	}

	if (p_systemStateSettings->gLteFlag && p_systemStateSettings->lteRssiMeasurement == 1)
	{
		//Lte rssi strength
	}
}

void SendMRPMsg::UpdateWifiFd(GMASocket wifiFd, struct sockaddr_in wifiServerAddr)
{
	wifiudpFd = wifiFd;
	wifiServer = wifiServerAddr;
}

void SendMRPMsg::UpdateLteFd(GMASocket lteFd, struct sockaddr_in lteServerAddr)
{
	lteudpFd = lteFd;
	lteServer = lteServerAddr;
}

void SendMRPMsg::notifyMRPCycle()
{
	mrp_begin_cv.notify_one();
}

//Class Send LRP Message
SendLRPMsg::SendLRPMsg()
{
	isConnect = false;
	code = '\0';
	wifiServer.sin_family = {};
	wifiServer.sin_port = 0;
	lteServer.sin_family = {};
	lteServer.sin_port = 0;
	lteServer.sin_addr = {};
	wifiServer.sin_addr = {};
}

void SendLRPMsg::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}

void SendLRPMsg::updateSettings()
{
	memset(buf, 0, sizeof(buf));
	ThreadBusy = false;
}

void SendLRPMsg::Execute()
{
	ThreadBusy = true;
	while (p_systemStateSettings->isControlManager) //add clock
	{
		std::unique_lock<std::mutex> lck(lrp_begin_mtx);
		lrp_begin_cv.wait(lck); // sychronized lock

		buf[30] = (unsigned char)0xFF; //type
		buf[32] = (unsigned char)((p_systemStateSettings->key & 0xFF000000) >> 24);
		buf[33] = (unsigned char)((p_systemStateSettings->key & 0x00FF0000) >> 16);
		buf[34] = (unsigned char)((p_systemStateSettings->key & 0x0000FF00) >> 8);
		buf[35] = (unsigned char)(p_systemStateSettings->key & 0x000000FF); //key
		buf[36] = (unsigned char)0;
		buf[37] = (unsigned char)0; //sn num
		buf[38] = (unsigned char)0;
		buf[39] = (unsigned char)0; //vender id
		buf[40] = (unsigned char)2; //sub type

		int currentTime = (int)(p_systemStateSettings->update_current_time_params() & 0x7FFFFFFF);	 //(int)(System.currentTimeMillis() + SystemStateSettings.gStartTime)&0x7FFFFFFF;
		buf[41] = (unsigned char)(((currentTime / 1000) & 0x0000FF00) >> 8); //timestamp: seconds
		buf[42] = (unsigned char)((currentTime / 1000) & 0x000000FF);

		buf[43] = (unsigned char)0;
		buf[44] = (unsigned char)0;
		buf[45] = (unsigned char)0;
		buf[46] = (unsigned char)0;
		buf[47] = (unsigned char)0;
		buf[48] = (unsigned char)0; //bssid
		if (isConnect)
		{
			p_systemStateSettings->GetWifiBssid(buf+43);
		}
		
		buf[49] = code; //event code

		if (p_systemStateSettings->gIsWifiConnect)
		{
			buf[31] = (unsigned char)0; //CID wifi
			if(sendto(wifiudpFd, (char *)buf, buf_size, 0, (struct sockaddr *)&wifiServer, sizeof(wifiServer)) <=0 )
				std::cout << "sendto error" << std::endl;
			
		}
		else if (p_systemStateSettings->gIsLteConnect)
		{
			buf[31] = (unsigned char)3; //CID lte
			if (sendto(lteudpFd, (char *)buf, buf_size, 0, (struct sockaddr *)&lteServer, sizeof(lteServer)) <=0 )
				std::cout << "sendto error" << std::endl;
			
		}
	}
	std::stringstream ss;
	ss << "[LRP message thread]: exit\n";
	p_systemStateSettings->PrintLogs(ss);
	ThreadBusy = false;
	return;
}

void SendLRPMsg::BuildPacketHeader()
{
	gmaMessageHeader.init(buf, 0);
	gmaMessageHeader.setGMAMessageHeader((short)0x0);

	ipHeader.init(buf, p_systemStateSettings->sizeofGMAMessageHeader);
	buf[p_systemStateSettings->sizeofGMAMessageHeader] = 0x45;

	ipHeader.setTos((unsigned char)0);
	ipHeader.setTotalLength(buf_size - p_systemStateSettings->sizeofGMAMessageHeader);
	ipHeader.setIdentification(0);
	ipHeader.setFlagsAndOffset((short)0x4000);
	ipHeader.setTTL((unsigned char)64);
	ipHeader.setDestinationIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicGw));
	ipHeader.setProtocol((unsigned char)0x11);
	ipHeader.setSourceIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicIp));
	ipHeader.setSum((short)0);
	ipHeader.setSum((short)ipHeader.checksum(0, buf, p_systemStateSettings->sizeofGMAMessageHeader, 20));

	udpHeader.init(buf, p_systemStateSettings->sizeofGMAMessageHeader + 20);
	udpHeader.setDestinationPort((short)p_systemStateSettings->serverUdpPort);
	udpHeader.setSourcePort((short)p_systemStateSettings->clientProbePort);
	udpHeader.setTotalLength(buf_size - p_systemStateSettings->sizeofGMAMessageHeader - 20);
	udpHeader.setSum((short)0);
}

void SendLRPMsg::UpdateWifiFd(GMASocket wifiFd, struct sockaddr_in wifiServerAddr)
{
	wifiudpFd = wifiFd;
	wifiServer = wifiServerAddr;
}

void SendLRPMsg::UpdateLteFd(GMASocket lteFd, struct sockaddr_in lteServerAddr)
{
	lteudpFd = lteFd;
	lteServer = lteServerAddr;
}

void SendLRPMsg::notifyLRPCycle(bool isConnect, unsigned char code)
{
	this->isConnect = isConnect;
	this->code = code;
	lrp_begin_cv.notify_one();
}

//Send TSU Message Class
SendTSUMsg::SendTSUMsg()
{
	wifiServer.sin_family = {};
	wifiServer.sin_port = 0;
	lteServer.sin_family = {};
	lteServer.sin_port = 0;
	lteServer.sin_addr = {};
	wifiServer.sin_addr = {};
}

void SendTSUMsg::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}

void SendTSUMsg::updateSettings()
{
	memset(buf, 0, buf_size);
	memset(plainText, 0, plaintext_size);

	seqNum = 0;
	nextRecvTSASeqNum = 0;
	tsu_success_flag = 0;
	tsu_busy_flag = false;
	ThreadBusy = false;
	wifiSplitFactor = 32;
	lteSplitFactor = 0;
	lvalue = 0;
	wifiSnAndTimeArray.clear();
	lteSnAndTimeArray.clear();
}

void SendTSUMsg::Execute()
{
	ThreadBusy = true;
	while (p_systemStateSettings->isControlManager)
	{
		std::unique_lock<std::mutex> send_lck(tsu_send_mtx);
		tsu_busy_flag = false;
		tsu_send_cv.wait(send_lck); // sychronized lock

		tsu_busy_flag = true;
		if (p_systemStateSettings->gLteFlag || p_systemStateSettings->gWifiFlag)
		{
			if (lteSplitFactor < 3)
			{
				wifiSplitFactor = p_systemStateSettings->paramL; //if lte split factor is smaller than 3, send all packets to wifi, and duplicate lteSplitFactor/paramL over LTE
			}
			else if (wifiSplitFactor < 3)
			{
				lteSplitFactor = p_systemStateSettings->paramL; //if wifi split factor is smaller than 3, send all packets to lte, and duplicate wifiSplitFactor/paramL over wifi
			}

			if (wifiSplitFactor < 0 || lteSplitFactor < 0)
			{
				std::stringstream ss;
				ss << "TSU wrong split parameters\n";
				p_systemStateSettings->PrintLogs(ss);
				continue;
			}
			else
			{
				tsu_success_flag = 0;
				if (wifiSplitFactor == 0 || lteSplitFactor == 0)
				{
					if (p_systemStateSettings->splitEnable == 1)
					{
						long systemTimeMsLong = (long)(p_systemStateSettings->update_current_time_params());
						int systemTimeMs = (int)(systemTimeMsLong & 0x7FFFFFFF);
						p_systemStateSettings->currentTimeMs = (systemTimeMs + p_systemStateSettings->gStartTime) & 0x7FFFFFFF;
						p_systemStateSettings->reorderStopTime = p_systemStateSettings->currentTimeMs + 1000; //stop reordering after 1 second
					}
					p_systemStateSettings->splitEnable = 0;
					trafficSplitingUpdate();
				}
				else
				{
					if (p_systemStateSettings->gStartTime >= 0)
					{
						p_systemStateSettings->splitEnable = 1;
						trafficSplitingUpdate();
					}
				}
			}
		}
	}
	std::stringstream ss;
	ss << "[TSU message thread]: exit\n";
	p_systemStateSettings->PrintLogs(ss);
	ThreadBusy = false;
	tsu_busy_flag = false;
}

void SendTSUMsg::trafficSplitingUpdate()
{
	int size = 0;
	int linkFlag = 0; //2: wifi; 1: lte;
		
	plainText[28] = (unsigned char)5;														//type
	if (p_systemStateSettings->gIsWifiConnect && wifiSplitFactor > 0 && lteSplitFactor == 0)
		{
			plainText[29] = (unsigned char)0;
		}
		else if (p_systemStateSettings->gIsLteConnect)
		{
			plainText[29] = (unsigned char)3;
		}
		else
		{
			p_systemStateSettings->mHandler(3);
			std::stringstream ss;
			ss << "control message manager connection status has changed, stop the ongoing TSU process\n";
			ss << "mHandler fail, line 1617\n";
			p_systemStateSettings->PrintLogs(ss);
			return; //something is wrong, abort the operation;
		}
		plainText[30] = (unsigned char)((p_systemStateSettings->key & 0xFF000000) >> 24);
		plainText[31] = (unsigned char)((p_systemStateSettings->key & 0x00FF0000) >> 16);
		plainText[32] = (unsigned char)((p_systemStateSettings->key & 0x0000FF00) >> 8);
		plainText[33] = (unsigned char)(p_systemStateSettings->key & 0x000000FF); //key
		
		int linkBitmap = p_systemStateSettings->GetLinkBitmap();
		plainText[36] = (unsigned char)linkBitmap;								   //first bit is wifi, second bit for lte
		plainText[37] = (unsigned char)p_systemStateSettings->nonRealtimelModeFlowId; //flow id
		plainText[38] = (unsigned char)wifiSplitFactor;							   //K1										 //K1
		plainText[39] = (unsigned char)lteSplitFactor;																			 //K2										 //K2
		plainText[40] = (unsigned char)lvalue;																					 //L1
		plainText[41] = (unsigned char)p_systemStateSettings->realtimeModeFlowId;													 //FLOW ID2											 //flow id
		plainText[42] = (unsigned char)(p_systemStateSettings->gDLAllOverLte || p_systemStateSettings->gDlRToverLteFlag == 1 ? 0 : 1); //K1
		plainText[43] = (unsigned char)(p_systemStateSettings->gDLAllOverLte || p_systemStateSettings->gDlRToverLteFlag == 1 ? 1 : 0); //K2
		plainText[44] = (unsigned char)1;		
		if (lteSplitFactor == 0 || wifiSplitFactor == 0) //reset OWD offset
		{
			plainText[45]  = 255;
			plainText[46]  = 255;
		}
		else
		{

			if (p_systemStateSettings->wifiOwdTxOffset > 0 || p_systemStateSettings->lteOwdTxOffset > 0)	
			{
				plainText[45] = (unsigned char)p_systemStateSettings->wifiOwdTxOffset; //max = 250ms (1 Byte)
				plainText[46] = (unsigned char)p_systemStateSettings->lteOwdTxOffset;
				printf("\n OWD offset wifi:%u LTE: %u", plainText[45], plainText[46]);
				p_systemStateSettings->wifiOwdTxOffset = 0;
				p_systemStateSettings->lteOwdTxOffset = 0;
			}
			else
			{
				plainText[45]  = 0;
				plainText[46]  = 0;
			}
		}
		
	
	while (size < 8 && tsu_success_flag == 0)
	{ //transmit up to 3 times
		seqNum = p_systemStateSettings->controlMsgSn;
		plainText[34] = (unsigned char)((seqNum & 0xff00) >> 8);
		plainText[35] = (unsigned char)(seqNum & 0x00ff); //seq num
		p_systemStateSettings->controlMsgSn = (p_systemStateSettings->controlMsgSn + 1) & 0x0000FFFF; //2bytes
		try
		{
			if (p_systemStateSettings->enable_encryption)
			{
				int aad_len = 4;
				unsigned char aad[4];
				int tag_len = 16;
				unsigned char tags[16];
				int iv_len = 12;
				unsigned char iv[12];

				memset(aad, 0, aad_len);
				memset(tags, 0, tag_len);
				memset(iv, 0, iv_len);

				memcpy(aad, buf, 4);

				unsigned char cipher[256];

			
				if (RAND_bytes(iv, iv_len))
				{
					EncryptorAesGcm encryptorAesGcm;

					int ret = encryptorAesGcm.Encrypt((unsigned char*)plainText, sizeof(plainText),
						(unsigned char*)aad, aad_len,
						(unsigned char*)(p_systemStateSettings->aesKey.c_str()),
						(unsigned char*)iv, iv_len, cipher, tags);
					if (!ret)
					{
						std::stringstream ss;
						ss << "[TSU ERROR]: AesGCM encryption failed\n";
						p_systemStateSettings->PrintLogs(ss);
						continue;
					}
					else
					{
						memcpy(buf + 4, cipher, plaintext_size);
						memcpy(buf + 4 + plaintext_size, tags, tag_len);
						memcpy(buf + 4 + plaintext_size + tag_len, iv, iv_len);
					}
				}
				else
				{
					std::stringstream ss;
					ss << "[TSU ERROR]: RAND bytes failed\n";
					p_systemStateSettings->PrintLogs(ss);
					continue;
				}
			}
			else
			{
				memcpy(buf + 2, plainText, plaintext_size);
			}
		}
		catch (const char *e)
		{
		}
		if (p_systemStateSettings->gIsWifiConnect && wifiSplitFactor > 0 && lteSplitFactor == 0)
		{
			p_systemStateSettings->lastSendWifiTsu = (int)(p_systemStateSettings->update_current_time_params() & 0x7FFFFFFF);
			if (wifiudpFd != GMA_INVALID_SOCKET)
			{
				if (sendto(wifiudpFd, (char *)buf, buf_size, 0, (struct sockaddr *)&wifiServer, sizeof(wifiServer)) <= 0)
				{
					std::stringstream ss;
					ss << "[TSU ERROR]: Send over wifi\n";
					p_systemStateSettings->PrintLogs(ss);
				}
			}
			p_systemStateSettings->wifiSendBytes += buf_size;
			wifiSnAndTimeArray.insert(std::pair<int, int>(seqNum, p_systemStateSettings->lastSendWifiTsu));
			linkFlag = 2;
		}
		else 
		{
			p_systemStateSettings->lastSendLteTsu = (int)(p_systemStateSettings->update_current_time_params() & 0x7FFFFFFF);
			if (lteudpFd != GMA_INVALID_SOCKET)
			{
				if (sendto(lteudpFd, (char *)buf, buf_size, 0, (struct sockaddr *)&lteServer, sizeof(lteServer)) <= 0)				
				{
					std::stringstream ss;
					ss << "[TSU ERROR]: Send over lte\n";
					p_systemStateSettings->PrintLogs(ss);				}
			}
			p_systemStateSettings->lteSendBytes += buf_size;
			lteSnAndTimeArray.insert(std::pair<int, int>(seqNum, p_systemStateSettings->lastSendLteTsu));
			linkFlag = 1;
		}

		nextRecvTSASeqNum = seqNum;
		std::unique_lock<std::mutex> tsu_lck(tsu_recv_mtx);
		tsu_recv_cv.wait_for(tsu_lck, std::chrono::milliseconds(200 + size * 200)); // sychronized lock

		size++;
	}
	if (tsu_success_flag == 0)
	{
		//TSU failure
		p_systemStateSettings->numOfTsuLinkFailure++;
		std::stringstream ss;
		switch (linkFlag)
		{
		case 1: //TSU-over-LTE fails
			ss << "control message manager TSU-over-LTE failure\n";
			p_systemStateSettings->PrintLogs(ss);
			p_systemStateSettings->numOfLteLinkFailure++;
			p_systemStateSettings->lastReceiveLteProbe = 0;
			p_systemStateSettings->gIsLteConnect = false;
			if (p_systemStateSettings->gIsWifiConnect)
			{
				p_systemStateSettings->wifiIndexChangeAlpha = 0;
				p_systemStateSettings->wifiSplitFactor = p_systemStateSettings->paramL;
				p_systemStateSettings->lteSplitFactor = 0;
				wifiSplitFactor = p_systemStateSettings->paramL;
				lteSplitFactor = 0;
				p_systemStateSettings->gDLAllOverLte = false;
				trafficSplitingUpdate();
				p_systemStateSettings->GMAIPCMessage(2,0,0,false,0); //controlManager.sendWifiProbe(); //sendWifiProbeMsg.sendWifiProbe();
			}
			else
			{
				ss.str("");
				ss << "line 1807-1813 commented, check segmentation fault\n";
				p_systemStateSettings->mHandler(3);
				ss << "mHandler fail, line 1779\n";
				p_systemStateSettings->PrintLogs(ss);
				return;
			}
			lteSnAndTimeArray.clear();
			break;
		case 2: //TSU-over-WiFi fails
			ss << "control message manager TSU-over-Wi-Fi failure\n";
			p_systemStateSettings->PrintLogs(ss);
			p_systemStateSettings->numOfWifiLinkFailure++;
			p_systemStateSettings->lastReceiveWifiProbe = 0;
			p_systemStateSettings->gIsWifiConnect = false;
			if (p_systemStateSettings->gIsLteConnect)
			{
				wifiSplitFactor = 0;
				lteSplitFactor = p_systemStateSettings->paramL;
				p_systemStateSettings->wifiSplitFactor = 0;
				p_systemStateSettings->lteSplitFactor = p_systemStateSettings->paramL;
				p_systemStateSettings->gDLAllOverLte = true;
				trafficSplitingUpdate();
				p_systemStateSettings->GMAIPCMessage(3,0,0,false,0); //controlManager.sendLteProbe(); //sendLteProbeMsg.sendLteProbe();
				p_systemStateSettings->GMAIPCMessage(9, 0, 0, true, 3);
			}
			else
			{
				ss.str("");
				ss << "line 1833-1839 commented, check segmentation fault\n";
				p_systemStateSettings->mHandler(3);
				ss << "mHandler fail, line 1805\n";
				p_systemStateSettings->PrintLogs(ss);
				return;
			}
			wifiSnAndTimeArray.clear();
			break;
		default:
			break;
		}
	}
}

void SendTSUMsg::receiveWifiTSA(int recvProbeAckSeqNum, int recvWifiTSATime)
{
	//2^16 = 65536
	if (rollOverDiff2(recvProbeAckSeqNum, nextRecvTSASeqNum, 65536) >= 0)
	{
		tsu_success_flag = 1;
		nextRecvTSASeqNum = recvProbeAckSeqNum + 1;
		tsu_recv_cv.notify_one();
	}
	int sendTSUTime = recvWifiTSATime;
	if (wifiSnAndTimeArray.count(recvProbeAckSeqNum) > 0)
	{
		sendTSUTime = wifiSnAndTimeArray[recvProbeAckSeqNum];
	}
	if (recvWifiTSATime - sendTSUTime > 0)
	{
		p_systemStateSettings->wifiLinkRtt = recvWifiTSATime - sendTSUTime;
		p_systemStateSettings->wifiLinkMaxRtt = std::max(p_systemStateSettings->wifiLinkRtt, p_systemStateSettings->wifiLinkMaxRtt);

		wifiSnAndTimeArray.clear();
	}
}

void SendTSUMsg::receiveLteTSA(int recvProbeAckSeqNum, int recvLteTSATime)
{
	//2^16 = 65536;
	if (rollOverDiff2(recvProbeAckSeqNum, nextRecvTSASeqNum, 65536) >= 0)
	{
		tsu_success_flag = 1;
		nextRecvTSASeqNum = recvProbeAckSeqNum + 1;
		tsu_recv_cv.notify_one();
	}
	int sendTSUTime = recvLteTSATime;
	if (lteSnAndTimeArray.count(recvProbeAckSeqNum) > 0)
	{
		sendTSUTime = lteSnAndTimeArray[recvProbeAckSeqNum];
	}
	if (recvLteTSATime - sendTSUTime > 0)
	{
		p_systemStateSettings->lteLinkRtt = recvLteTSATime - sendTSUTime;
		lteSnAndTimeArray.clear();
		tsu_success_flag = 1;
	}
}

void SendTSUMsg::BuildPacketHeader()
{
	gmaMessageHeader.init(buf, 0);
	if (p_systemStateSettings->enable_encryption)
	{
		gmaMessageHeader.setGMAMessageHeader((short)0x800F);
		gmaMessageHeader.setGmaClientId((short)p_systemStateSettings->clientId);
	}
	else
	{
		gmaMessageHeader.setGMAMessageHeader((short)0x00);
	}

	ipHeader.init(plainText, 0);
	plainText[0] = 0x45;
	ipHeader.setTos((unsigned char)0);
	ipHeader.setTotalLength(plaintext_size);
	ipHeader.setIdentification(0);
	ipHeader.setFlagsAndOffset((short)0x4000);
	ipHeader.setTTL((unsigned char)64);
	ipHeader.setDestinationIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicGw));
	ipHeader.setProtocol((unsigned char)0x11);
	ipHeader.setSourceIP(ipHeader.ipStringToInt(p_systemStateSettings->serverVnicIp));
	ipHeader.setSum((short)0);
	ipHeader.setSum((short)ipHeader.checksum(0, plainText, 0, 20));

	udpHeader.init(plainText, 20);
	udpHeader.setDestinationPort((short)p_systemStateSettings->serverUdpPort);
	udpHeader.setSourcePort((short)p_systemStateSettings->clientProbePort);
	udpHeader.setTotalLength(plaintext_size - 20);
	udpHeader.setSum((short)0);
}

int SendTSUMsg::rollOverDiff2(int x, int y, int max)
{
	int diff = x - y;
	if (diff > (max / 2))
	{
		diff = diff - max;
	}
	else if (diff < 0 - max / 2)
	{
		diff = diff + max;
	}
	return diff;
}

void SendTSUMsg::UpdateWifiFd(GMASocket wifiFd, struct sockaddr_in wifiServerAddr)
{
	wifiudpFd = wifiFd;
	wifiServer = wifiServerAddr;
}

void SendTSUMsg::UpdateLteFd(GMASocket lteFd, struct sockaddr_in lteServerAddr)
{
	lteudpFd = lteFd;
	lteServer = lteServerAddr;
}

void SendTSUMsg::sendTSUMsg()
{
	if (!tsu_busy2_flag)
	{
		tsu_busy2_flag = true;
		std::thread run(std::bind(&SendTSUMsg::thread_sendTSUMsg, this));
		run.detach();
	}

}

void SendTSUMsg::thread_sendTSUMsg()
{
	for (int i = 0; i < 3; ++i)
	{
		if (tsu_busy_flag)
		{
			try
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(2000));  		//sleep(2); //sleep 2 seconds
			} 
			catch (const char* e)
			{
				//std::cout << e << std::endl;
				break;
			}
		}
		else
			break;
	}
	wifiSplitFactor = p_systemStateSettings->wifiSplitFactor;
	lteSplitFactor = p_systemStateSettings->lteSplitFactor;
	lvalue = p_systemStateSettings->paramL;
	tsu_send_cv.notify_one();
	tsu_busy2_flag = false;
}
