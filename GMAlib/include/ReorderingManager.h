//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : ReorderingManager.h

#ifndef _REORDERING_H
#define _REORDERING_H

#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <condition_variable>
#include "SystemStateSettings.h"

#define FHDR_FSN_NUM_MASK	0x00FFFFFF //3 bytes for data SN

struct RingBufferInfo {
	int ringBufferEnd = 0; //ring buffer index pointing the available slot
};

class ReorderingWorker {

private:
	ReorderingWorker(const ReorderingWorker& src) { /* do not create copies */ }
	ReorderingWorker& operator=(const ReorderingWorker&) { return *this; }

	int ringBufferSlotLimitSize;
	
	char** ringBuffer = NULL;
	char* slotOccupied = NULL;//a list stores the occupied slots.
	int* rcv_timestamp = NULL; //a list stores the receive time of the queued packets
	int* tx_timestamp = NULL; //a list stores the receive time of the queued packets
	int* rcv_PktSn = NULL; //a list stores the packet sn of queued packets
	int* rcv_PktLSn = NULL; //a list stores the packet sn of queued packets
	int* rcv_PktLen = NULL; // a list stores the packet length of queued packets
	char* rcv_PktType = NULL; // a list stores the link type of queued packets
	RingBufferInfo* ringBufferInfo;

	int dataOffset; //GMA header size = 11 Bytes
	bool stopReorderingManager = false;
	int nextHrSn = 0;
	int maxWifiSn = 0;
	int maxLteSn = 0;
	bool dropOutOrderPkt = true;

	std::thread reorderingThreadHR;
	std::thread reorderingThreadHR2;

	std::thread::native_handle_type reorderIDHR;
	std::thread::native_handle_type reorderIDHR2;


	bool HRreorderThreadBusy = false;
	bool HRreorderThreadBusy2 = false;
	int HRBufferSize = 500;  //pkts
	int HRreorderingTimeout = 50; //ms
	int ul_packet_sn = 0;
	int ul_packet_Lsn = 0;
	char ul_packet_type = -1;
	
	unsigned short* m_shared_rx_index_list = NULL; //virtual wifi index queue
	unsigned short m_rx_index_start = 0;
	unsigned short m_rx_index_end = 0;
	unsigned short m_rx_index_reorder = 0;
	
    std::mutex m_output_mtx2;
	std::condition_variable m_output_cond2;
    bool m_output_running_flag2 = false;

	int release_in_order_packets();
	bool push_last_packet_into_rx_queue();
	int rollover_diff2(int x1, int x2);
	int rollover_diff(int x1, int x2);

public:

	ReorderingWorker();
	~ReorderingWorker();
	SystemStateSettings* p_systemStateSettings = NULL;
	void updateSystemSettings(SystemStateSettings* p_systemStateSettings, char** x1, char* x2, int* x3, int* x4, int* x5, int* x6, RingBufferInfo* x7, int x8, int x9, bool flag, char* x10, int* x11);
	void hr_reordering_thread();
	void receiveHRPacket(char* packet, int lSeqNum, int mSeqNum, int len, char type, int tx_time);
	void closeReorderingWorker();
	void startReordering();
	void updateNextSn(int receiveDataSn, int lSeqNum, char type);
	void outputHRPacket(char* packet, int len, int sn, int tx_time);
	void updateReorderingTimer(int x);
	int GetNextSn();

};

class ReorderingManager {
private:
	ReorderingManager(const ReorderingManager& src) { /* do not create copies */ }
	ReorderingManager& operator=(const ReorderingManager&) { return *this; }

	int ringBufferSlotLimitSize;
	int eachSlotLimitSize;//limit of packet size
	char** ringBuffer;
	char* slotOccupied;//a list stores the occupied slots.
	int* rcv_timestamp; //a list stores the receive time of the queued packets
	int* tx_timestamp; //a list stores the receive time of the queued packets
	int* rcv_PktSn; //a list stores the packet sn of queued packets
	int* rcv_PktLSn; //a list stores the packet sn of queued packets
	int* rcv_PktLen; // a list stores the packet length of queued packets
	char* rcv_PktType; // a list stores the link type of queued packets

	RingBufferInfo* ringBufferInfo = NULL;
	
public:

	ReorderingWorker hrReorderingWorker;  //reordering worker for high-reliability flow
	ReorderingWorker nrtReorderingWorker;  //reordering worker for non-real-time flow
	SystemStateSettings* p_systemStateSettings = NULL;

	ReorderingManager();
	~ReorderingManager();
	void initUnitSystemStateSettings(SystemStateSettings* p_systemStateSettings);
	void updateSystemSettings();
	void closeReorderingManager();
	void startReordering();
	char* requestBuffer();

};

#endif


