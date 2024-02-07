//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : ReorderingManager.cpp

#include "../include/ReorderingManager.h"
#include "../include/SystemStateSettings.h"
#include "../include/Common.h"
#include <iostream>
#include <sstream>
#include <string>
#include <cstring>
#include <functional>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>

#elif defined(_WIN32) || defined(_WIN64) 
#include <WinSock2.h>
#endif


using namespace std;

ReorderingManager::ReorderingManager()
{
	ringBufferSlotLimitSize = 200;
	eachSlotLimitSize = 2000;
	ringBuffer = NULL;
	slotOccupied = NULL;
	rcv_timestamp = NULL;
	tx_timestamp = NULL;
	rcv_PktSn = NULL;
	rcv_PktLSn = NULL;
	rcv_PktLen = NULL;
	rcv_PktType = NULL;
	ringBufferInfo = new RingBufferInfo;
}

ReorderingWorker::ReorderingWorker()
{
	ringBufferInfo = NULL;
	ringBufferSlotLimitSize = 0;
	dataOffset = 0;
	reorderIDHR = 0;
	reorderIDHR2 = 0;
}

ReorderingManager::~ReorderingManager()
{
	if (ringBuffer)
	{
		for (int i = 0; i < ringBufferSlotLimitSize; i++)
		{
			delete[] ringBuffer[i];
		}
		delete[] ringBuffer;
	}

	delete[] slotOccupied;
	delete[] rcv_timestamp;
	delete[] tx_timestamp;
	delete[] rcv_PktSn;
	delete[] rcv_PktLSn;
	delete[] rcv_PktLen;
	delete[] rcv_PktType;
	delete ringBufferInfo; 
}

ReorderingWorker::~ReorderingWorker()
{
	delete[] m_shared_rx_index_list;
}

void ReorderingManager::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}

void ReorderingManager::updateSystemSettings()
{
	ringBufferInfo->ringBufferEnd = 0;
	
	if (ringBuffer)
	{
		for (int i = 0; i < ringBufferSlotLimitSize; i++)
		{
			delete[] ringBuffer[i];
		}
		delete[] ringBuffer;
	}

	ringBufferSlotLimitSize = p_systemStateSettings->reorderBufferSize;
	eachSlotLimitSize = p_systemStateSettings->gmaMTUsize;
	
	ringBuffer = new char* [ringBufferSlotLimitSize];
	for (int i = 0; i < ringBufferSlotLimitSize; i++)
	{
			ringBuffer[i] = new char[eachSlotLimitSize];
	}
	
	if (slotOccupied)
		delete[] slotOccupied;
	
	slotOccupied = new char[ringBufferSlotLimitSize];

	
	if (rcv_timestamp)
		delete[] rcv_timestamp;
	rcv_timestamp = new int[ringBufferSlotLimitSize];
	
	if (tx_timestamp)
		delete[] tx_timestamp;
	tx_timestamp = new int[ringBufferSlotLimitSize];
	
	if (rcv_PktSn)
		delete[] rcv_PktSn;
	rcv_PktSn = new int[ringBufferSlotLimitSize];
	
	if (rcv_PktLSn)
		delete[] rcv_PktLSn;
	rcv_PktLSn = new int[ringBufferSlotLimitSize];


	if (rcv_PktLen)
		delete[] rcv_PktLen;
	rcv_PktLen = new int[ringBufferSlotLimitSize];
	
	if (rcv_PktType)
		delete[] rcv_PktType;
	rcv_PktType = new char[ringBufferSlotLimitSize];


	memset(slotOccupied, 0, ringBufferSlotLimitSize);

	memset(rcv_timestamp, 0, ringBufferSlotLimitSize);

	memset(tx_timestamp, 0, ringBufferSlotLimitSize);

	memset(rcv_PktSn, 0, ringBufferSlotLimitSize);

	memset(rcv_PktLSn, 0, ringBufferSlotLimitSize);

	memset(rcv_PktType, 0, ringBufferSlotLimitSize);

	memset(rcv_PktLen, 0, ringBufferSlotLimitSize);

    int lHRBufferSize = p_systemStateSettings->HRBufferSize;
	if (lHRBufferSize < 10)
		lHRBufferSize = 10;
	if (lHRBufferSize > ringBufferSlotLimitSize / 2)
		lHRBufferSize = ringBufferSlotLimitSize / 2;
	
	int lHRreorderingTimeout = p_systemStateSettings->HRreorderingTimeout;
	if (lHRreorderingTimeout < 1)
		lHRreorderingTimeout = 1;   //min = 1 ms
	if (lHRreorderingTimeout > 2000)
		lHRreorderingTimeout = 2000; //max = 2 seconds

	hrReorderingWorker.updateSystemSettings(p_systemStateSettings, ringBuffer, slotOccupied, 
		rcv_timestamp, tx_timestamp, rcv_PktSn, rcv_PktLen, ringBufferInfo,
		lHRreorderingTimeout, lHRBufferSize, true, rcv_PktType, rcv_PktLSn);


	int lNRTBufferSize = ringBufferSlotLimitSize - lHRBufferSize - 1; 
	int lNRTreorderingTimeout = p_systemStateSettings->MIN_MAXREORDERINGDELAY;
	if (lNRTreorderingTimeout < 10)
		lHRreorderingTimeout = 10;   //min = 10 ms
	if (lNRTreorderingTimeout > 2000)
		lNRTreorderingTimeout = 2000; //max = 2 seconds

	nrtReorderingWorker.updateSystemSettings(p_systemStateSettings, ringBuffer, slotOccupied,
		rcv_timestamp, tx_timestamp, rcv_PktSn, rcv_PktLen, ringBufferInfo,
		lNRTreorderingTimeout, lNRTBufferSize, true, rcv_PktType, rcv_PktLSn);

}

void ReorderingWorker::updateReorderingTimer(int x)
{
	HRreorderingTimeout = x;
}

void ReorderingWorker::updateSystemSettings(SystemStateSettings* p_systemStateSettings, char** x1, char* x2, int* x3, int* x4, int* x5, int* x6, RingBufferInfo* x7, int x8, int x9, bool flag, char* x10, int* x11)
{
	this->p_systemStateSettings = p_systemStateSettings;

	dataOffset = p_systemStateSettings->sizeofDlGmaDataHeader; //GMA header size = 11 Bytes
	ringBuffer = x1;
	slotOccupied = x2;//a list stores the occupied slots.
	rcv_timestamp = x3; //a list stores the receive time of the queued packets
	tx_timestamp = x4; //a list stores the tx time of the queued packets
	rcv_PktSn = x5; //a list stores the packet sn of queued packets
	rcv_PktLSn = x11; //a list stores the packet Lsn of queued packets
	rcv_PktLen = x6; // a list stores the packet length of queued packets
	ringBufferInfo = x7;
	dropOutOrderPkt = flag;
	rcv_PktType = x10;

	stopReorderingManager = false;
	nextHrSn = 0;
	maxWifiSn = 0;
	maxLteSn = 0;

	ul_packet_sn = 0;
	ul_packet_Lsn = 0;
	ul_packet_type = -1;
	m_rx_index_start = 0;
	m_rx_index_end = 0;
	m_rx_index_reorder = 0;
   m_output_running_flag2 = false;

	if (m_shared_rx_index_list)
		delete[] m_shared_rx_index_list;

	HRreorderingTimeout = x8; // p_systemStateSettings->HRreorderingTimeout;
	HRBufferSize = x9; // p_systemStateSettings->HRBufferSize;
	ringBufferSlotLimitSize = p_systemStateSettings->reorderBufferSize;

	m_shared_rx_index_list = new unsigned short[HRBufferSize];
	
	memset(m_shared_rx_index_list, 0, HRBufferSize);

}


char *ReorderingManager::requestBuffer()
{
	/*
	int lringBufferEnd = ringBufferInfo->ringBufferEnd;
	while (slotOccupied[lringBufferEnd] == 1)
	{ //find the next available slot in ring buffer
		lringBufferEnd = (lringBufferEnd + 1) % ringBufferSlotLimitSize;
	}
	ringBufferInfo->ringBufferEnd = lringBufferEnd;
	return ringBuffer[lringBufferEnd];
	*/
	return ringBuffer[ringBufferInfo->ringBufferEnd];
}

void ReorderingManager::startReordering()
{
	hrReorderingWorker.startReordering();
	nrtReorderingWorker.startReordering();
}

void ReorderingWorker::startReordering()
{
	try
	{
		reorderingThreadHR2 = std::thread(std::bind(&ReorderingWorker::hr_reordering_thread, this));
		reorderIDHR2 = (std::thread::native_handle_type)1;
	}
	catch (const std::system_error& e)
	{
		std::cout << "Caught system_error with code " << e.code()
			<< " meaning " << e.what() << '\n';
		reorderIDHR2 = 0;
	}

}

void ReorderingManager::closeReorderingManager()
{
	hrReorderingWorker.closeReorderingWorker();
	nrtReorderingWorker.closeReorderingWorker();
}

void ReorderingWorker::closeReorderingWorker()
{
	stopReorderingManager = true;
	
	while (HRreorderThreadBusy2)
	{
		m_output_cond2.notify_one();
		p_systemStateSettings->msleep(1);
	}

	if (reorderIDHR2 != 0)
	{
		reorderingThreadHR2.join();
		reorderIDHR2 = 0;
	}

}

void ReorderingWorker::updateNextSn(int receiveDataSn, int lsn, char type)
{
	ul_packet_sn = receiveDataSn;
	ul_packet_Lsn = lsn;
	ul_packet_type = type;
}

int ReorderingWorker::GetNextSn()
{
	return ul_packet_sn;
}

bool ReorderingWorker::push_last_packet_into_rx_queue()
{
	if ((m_rx_index_end + 1) % HRBufferSize == m_rx_index_start)//reordering index queue full
	{
		p_systemStateSettings->numOfReorderingOverflow++;
		stringstream ss;
		ss << "[Error] index queue full" << endl;
		p_systemStateSettings->PrintLogs(ss);
		return false;  
	}
	else
	{

		int lringBufferEnd = ringBufferInfo->ringBufferEnd;

		//ring (reordering) buffer full
		int next = (lringBufferEnd + 1) % ringBufferSlotLimitSize;
		int i = 0;
		for (i = 0; i <= ringBufferSlotLimitSize; i++)
		{ //find the next available slot in ring buffer
			if (slotOccupied[next] == 1)
				next = (next + 1) % ringBufferSlotLimitSize;
			else
				break;
		}
		if (i == ringBufferSlotLimitSize) //ring (reordering) buffer full
		{
			p_systemStateSettings->numOfReorderingOverflow++;
			stringstream ss;
			ss << "[Error] ring buffer full" << endl;
			p_systemStateSettings->PrintLogs(ss);
			return false;
		}
		//////

		slotOccupied[ringBufferInfo->ringBufferEnd] = 1;
		m_shared_rx_index_list[m_rx_index_end] = lringBufferEnd; // m_rx_buffer_index_end;
		m_rx_index_end = (m_rx_index_end + 1) % HRBufferSize;
		ringBufferInfo->ringBufferEnd = next;
	}
	return true;
}

int ReorderingWorker::rollover_diff(int x1, int x2)
{
	int diff = x1 - x2;
	if (diff > 128)
		diff = diff - 256;
	else if (diff < -128)
		diff = diff + 256;

	return diff;
}

int ReorderingWorker::rollover_diff2(int x1, int x2)
{
	int diff = x1 - x2;
	if (diff > (FHDR_FSN_NUM_MASK >> 1))
		diff = diff - FHDR_FSN_NUM_MASK - 1;
	else if (diff < -(FHDR_FSN_NUM_MASK >> 1))
		diff = diff + FHDR_FSN_NUM_MASK + 1;

	return diff;
}

void ReorderingWorker::receiveHRPacket(char* packet, int lSeqNum, int mSeqNum, int len, char type, int tx_time)
{
	int diff_sn = 0;
	unsigned short b_index;
	int lringBufferEnd = ringBufferInfo->ringBufferEnd;
	
	if (p_systemStateSettings->GetLinkBitmap() == 3)
	{
		diff_sn = rollover_diff2(mSeqNum, ul_packet_sn);
		/*if (diff_sn == 1)
		{
			ul_packet_sn = mSeqNum;
			outputHRPacket(packet, len, mSeqNum, tx_time);
		}
		else 
		*/	
		if (diff_sn >= 1)
		{
			rcv_timestamp[lringBufferEnd] = p_systemStateSettings->currentTimeMs;
			tx_timestamp[lringBufferEnd] = tx_time;
			rcv_PktSn[lringBufferEnd] = mSeqNum;
			rcv_PktLSn[lringBufferEnd] = lSeqNum;
			rcv_PktLen[lringBufferEnd] = len;
			rcv_PktType[lringBufferEnd] = type;
			if (!push_last_packet_into_rx_queue()) //reorder buffer full, release the packet
			{
				m_output_cond2.notify_one();
				p_systemStateSettings->msleep(1);
				//ul_packet_sn = mSeqNum;
				//outputHRPacket(packet, len, mSeqNum, tx_time);
			}
		}
		else
		{   //out of order
			if(!dropOutOrderPkt)
			  outputHRPacket(packet, len, mSeqNum, tx_time);
		}
	}
	else
	{ // no reordering if only one link is available
		ul_packet_sn = mSeqNum;
		ul_packet_Lsn = lSeqNum;
		ul_packet_type = type;
		outputHRPacket(packet, len, mSeqNum, tx_time);
	}
	/*release_in_order_packets();
	
	if (output_list_packet_available() && !m_output_running_flag)//buffer not empty
	{
		m_output_cond.notify_one();
	}*/
	if (!m_output_running_flag2 && m_rx_index_start != m_rx_index_end)
		m_output_cond2.notify_one();
	
	return;
}

void ReorderingWorker::hr_reordering_thread()
{
	int slotNext;
	int slotPre;
	unsigned short b_index;
	u_short b_index_pre;
	u_short b_index_next;
	int timeout = 0;
	int pkt_sn = 0;
	HRreorderThreadBusy2 = true;
	while (!stopReorderingManager)
	{
		m_output_running_flag2 = false;
		std::unique_lock<std::mutex> lck(m_output_mtx2);
		if (timeout > 0)
		{
			m_output_cond2.wait_for(lck, std::chrono::milliseconds(timeout));
			long systemTimeMsLong = (long)(p_systemStateSettings->update_current_time_params());
			int systemTimeMs = (int)(systemTimeMsLong & 0x7FFFFFFF);
			p_systemStateSettings->currentSysTimeMs = systemTimeMs;
			p_systemStateSettings->currentTimeMs = (systemTimeMs + p_systemStateSettings->gStartTime) & 0x7FFFFFFF;
		}
		else
			m_output_cond2.wait(lck);

		m_output_running_flag2 = true;//the output thread is in running state.
		if (stopReorderingManager)
			break;
				
		while (m_rx_index_reorder != m_rx_index_end)
		{
			   //multi-link reordering step1: find the per-link max SN for in-order packets
			   if(rollover_diff2(maxWifiSn, ul_packet_sn) < 0)
					maxWifiSn = ul_packet_sn;
			   if(rollover_diff2(maxLteSn, ul_packet_sn) < 0)
					maxLteSn = ul_packet_sn;
			   
			   b_index = m_shared_rx_index_list[m_rx_index_reorder];
			   pkt_sn = rcv_PktSn[b_index]; 
			   if (rcv_PktType[b_index] == 3)
			   {
				   if (rollover_diff2(maxLteSn, pkt_sn) < 0)
				      maxLteSn = pkt_sn;
			   }
			   else
			   {
				   if (rollover_diff2(maxWifiSn, pkt_sn) < 0)
	 			     maxWifiSn = pkt_sn;
			   }

			  
			   //////////////////////////
			    
			   
				//////////////////////// reordering start 
				slotPre = m_rx_index_reorder;
				while (slotPre != m_rx_index_start) {//more than 2 packets in the queue
					//we check if the last received packet is inorder or not
					slotNext = slotPre;
					slotPre = ((slotPre + HRBufferSize) - 1) % HRBufferSize;//find the previous slot
					b_index_pre = m_shared_rx_index_list[slotPre];
					
					if (rollover_diff2(rcv_PktSn[b_index_pre], pkt_sn) <= 0)
					{	//packet in order
						break;
					}
					else {
						//packet out of order, we swap it with the previous one until it is moved to the correct position
						m_shared_rx_index_list[slotPre] = b_index;
						m_shared_rx_index_list[slotNext] = b_index_pre;
					}
				}
				////////////////////////// reordering end
				m_rx_index_reorder = (m_rx_index_reorder + 1) % HRBufferSize;
				timeout = release_in_order_packets();
				
		}
	}

	HRreorderThreadBusy2 = false;
	return;
}

int ReorderingWorker::release_in_order_packets()
{
	int timeout = 0; //ms
	unsigned short b_index;
	int buff_th = HRBufferSize*4/5; //congestion detection threshold = 0.8 * buffer size
	int buff_end = m_rx_index_end + HRBufferSize;
	while (m_rx_index_start != m_rx_index_reorder)
		  {
				b_index = m_shared_rx_index_list[m_rx_index_start];
				int diff = rollover_diff2(rcv_PktSn[b_index], ul_packet_sn);
				if (diff == 1)
				{
					outputHRPacket(ringBuffer[b_index], rcv_PktLen[b_index], rcv_PktSn[b_index], tx_timestamp[b_index]);
					slotOccupied[b_index] = 0;
					m_rx_index_start = (m_rx_index_start + 1) % HRBufferSize;
					ul_packet_sn = rcv_PktSn[b_index];
					ul_packet_Lsn = rcv_PktLSn[b_index];
					ul_packet_type = rcv_PktType[b_index];
				}
				else if (diff <= 0)
				{
					//drop redundent packet
					slotOccupied[b_index] = 0;
					m_rx_index_start = (m_rx_index_start + 1) % HRBufferSize;
				}
				else if ((buff_end - m_rx_index_start) % HRBufferSize > buff_th)
				{   //reordering index is full, and release the first packet 
					//printf("\n index queue is full, release the first packet");
					p_systemStateSettings->numOfReorderingOverflow++;
					outputHRPacket(ringBuffer[b_index], rcv_PktLen[b_index], rcv_PktSn[b_index], tx_timestamp[b_index]);
					slotOccupied[b_index] = 0;
					m_rx_index_start = (m_rx_index_start + 1) % HRBufferSize;
					ul_packet_sn = rcv_PktSn[b_index];
					ul_packet_Lsn = rcv_PktLSn[b_index];
					ul_packet_type = rcv_PktType[b_index];
				}
				else
				{   //timeout 
					
					int queue_time = p_systemStateSettings->currentTimeMs - rcv_timestamp[b_index];
					timeout = HRreorderingTimeout - queue_time;
					//timeout = 1000 - (p_systemStateSettings->currentTimeMs - rcv_timestamp[b_index]);

					if (timeout <= 0) 
					{

						if(HRreorderingTimeout < 1000) //increase timer up to 1 second 
							HRreorderingTimeout = queue_time + 20;

						stringstream ss;
						ss << "\n[reordering timeout]" << timeout << " queue time: " << queue_time << endl;
						p_systemStateSettings->PrintLogs(ss);
						p_systemStateSettings->numOfReorderingTimeout++; 
						outputHRPacket(ringBuffer[b_index], rcv_PktLen[b_index], rcv_PktSn[b_index], tx_timestamp[b_index]);
						slotOccupied[b_index] = 0;
						m_rx_index_start = (m_rx_index_start + 1) % HRBufferSize;
						ul_packet_sn = rcv_PktSn[b_index];
						ul_packet_Lsn = rcv_PktLSn[b_index];
						ul_packet_type = rcv_PktType[b_index];
					}
					else
					{ 
						//multi-link reordering step2: release in-order packets
						int next = maxLteSn;
						if (rollover_diff2(next, maxWifiSn) > 0)
							next = maxWifiSn;
						if (rollover_diff2(rcv_PktSn[b_index], next) <= 0)
						{
							//printf("\n multi-link reorderining last %d maxLte %d maxWiFi %d pkt %d,", (int)ul_packet_sn, maxLteSn, maxWifiSn, rcv_PktSn[b_index]);
							outputHRPacket(ringBuffer[b_index], rcv_PktLen[b_index], rcv_PktSn[b_index], tx_timestamp[b_index]);
							slotOccupied[b_index] = 0;
							m_rx_index_start = (m_rx_index_start + 1) % HRBufferSize;
							ul_packet_sn = rcv_PktSn[b_index];
							ul_packet_Lsn = rcv_PktLSn[b_index];
							ul_packet_type = rcv_PktType[b_index];
						} //////////////////////////////////////
						else if(p_systemStateSettings->reorderLsnEnhanceFlag == 1 && !dropOutOrderPkt)
						{
							if (rcv_PktType[b_index] == ul_packet_type)
							{
								if (diff == rollover_diff(rcv_PktLSn[b_index], ul_packet_Lsn))
								{
									//per-link packet loss is detected, and release the packet
									//printf("\n LSN-based eorderining link %d last SN %d last LSN %d SN %d LSN %d,", (int) ul_packet_type, ul_packet_sn, ul_packet_Lsn, rcv_PktSn[b_index], rcv_PktLSn[b_index]);
									outputHRPacket(ringBuffer[b_index], rcv_PktLen[b_index], rcv_PktSn[b_index], tx_timestamp[b_index]);
									slotOccupied[b_index] = 0;
									m_rx_index_start = (m_rx_index_start + 1) % HRBufferSize;
									ul_packet_sn = rcv_PktSn[b_index];
									ul_packet_Lsn = rcv_PktLSn[b_index];
									ul_packet_type = rcv_PktType[b_index];
								}
								else
									break;
							}
							else
								break;
						}
						else 
							break;
					}
				}
		   } 
	
	if (m_rx_index_start == m_rx_index_end) //empty buffer
		timeout = 0;
	
    return (timeout);
}

void ReorderingWorker::outputHRPacket(char* packet, int len, int sn, int tx_time)
{

	int ret = p_systemStateSettings->tunwrite(packet + dataOffset, len);
	if (ret == -1)
	{
		stringstream ss;
		ss << "[Error]reordering manager tun write" << endl;
		p_systemStateSettings->PrintLogs(ss);
	}
	
    if (p_systemStateSettings->ENABLE_FLOW_MEASUREMENT)
	{
		if (sn == nextHrSn)
		{
			p_systemStateSettings->flowInorderPacketNum++;
			nextHrSn = (sn + 1) & FHDR_FSN_NUM_MASK;
		}
		else
		{
			int lflowMissingPacketNum = rollover_diff2(sn, nextHrSn);
			if (lflowMissingPacketNum > 0)
			{
				p_systemStateSettings->flowInorderPacketNum++;
				p_systemStateSettings->flowMissingPacketNum += lflowMissingPacketNum;
				nextHrSn = (sn + 1) & FHDR_FSN_NUM_MASK;
			}
			else
			{
				p_systemStateSettings->flowAbnormalPacketNum++;
			}
		}
		
	}

	int owdMs = p_systemStateSettings->currentTimeMs - tx_time;
	if (owdMs < 10000)
	{ //only update OWD smaller than 10 s
		p_systemStateSettings->flowOwdSum += owdMs;
		//Log.v("WiFi", "currentTimeMs():"+Long.toString(currentTimeMs) + " timeStampMs:"+Long.toString(timestampMs) + " OWD:"+Long.toString(currentTimeMs-timestampMs));
		p_systemStateSettings->flowOwdPacketNum++;

		if (p_systemStateSettings->flowOwdMin > owdMs)
		{
			p_systemStateSettings->flowOwdMin = owdMs;
		}
		if (p_systemStateSettings->flowOwdMax < owdMs)
		{
			p_systemStateSettings->flowOwdMax = owdMs;
		}
	}
	
}
//////////HR (duplication) flow reordering end///////////

