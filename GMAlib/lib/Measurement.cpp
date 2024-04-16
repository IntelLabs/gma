//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : Measurement.cpp

#if defined(_WIN32) || defined(_WIN64) 
#define NOMINMAX
#endif
#include <algorithm>
#include <iostream>
#include "../include/Measurement.h"
#include "../include/SystemStateSettings.h"

int QUEUEING_DELAY_TARGET_MS = 10; //we would like to set value as 10 + dt, where dt is the estimated time drift from TX to RX.

int rollOverDiff2(int x, int y, int max)
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

MeasureDevice::MeasureDevice(char cid)
{
	rateEstimationLastCycle = 0;
	packetsBeforeLastLoss = 0;
	this->cid = cid;
}

void MeasureDevice::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
	//move structure here
	rateEstimationLastCycle = p_systemStateSettings->MAX_RATE_ESTIMATE; // kBps
	packetsBeforeLastLoss = p_systemStateSettings->INITIAL_PACKETS_BEFORE_LOSS;
}

void MeasureDevice::resetBurstRateEstimate()
{
	minOwdPerBurst = 0;
	maxOwdPerBurst = INT_MAX;
	packetCountPerBurst = 0;
	burstRatePerInterval = 0;
}

void MeasureDevice::AddDataToBurstRateEstimate(int owdMs)
{
	if (owdMs > (1.0 - p_systemStateSettings->BURST_INCREASING_ALPHA) * minOwdPerBurst + p_systemStateSettings->BURST_INCREASING_ALPHA * maxOwdPerBurst)
	{ //owd keep increasing
		packetCountPerBurst++;
		if (maxOwdPerBurst < owdMs)
		{
			maxOwdPerBurst = owdMs;
		}
		burstStopTime = p_systemStateSettings->currentTimeMs;
		if (p_systemStateSettings->wifiCid == cid)
		{
			burstStopBytes = p_systemStateSettings->wifiReceiveNrtBytes;
		}
		else if (p_systemStateSettings->lteCid == cid)
		{
			burstStopBytes = p_systemStateSettings->lteReceiveNrtBytes;
		}
	}
	else
	{ 
		if (packetCountPerBurst >= p_systemStateSettings->MIN_PACKET_COUNT_PER_BURST)
		{
			if (0 == burstRatePerInterval)
			{
				burstRatePerInterval = (burstStopBytes - burstStartBytes) / (burstStopTime - burstStartTime);
			}
			else
			{
				burstRatePerInterval = (burstRatePerInterval + (burstStopBytes - burstStartBytes) / (burstStopTime - burstStartTime)) / 2; //I am doing a simple moving average of all burst rate measurements in he same interval
			}
		}
		//reset to the first owd of a burst
		minOwdPerBurst = owdMs;
		maxOwdPerBurst = owdMs;
		packetCountPerBurst = 0;
		burstStartTime = p_systemStateSettings->currentTimeMs;
		if (p_systemStateSettings->wifiCid == cid)
		{
			burstStartBytes = p_systemStateSettings->wifiReceiveNrtBytes;
		}
		else if (p_systemStateSettings->lteCid == cid)
		{
			burstStartBytes = p_systemStateSettings->lteReceiveNrtBytes;
		}
	}
}

void MeasureDevice::updateLastPacketOwd(int owdMs, bool dataFlag)
{
	if (abs(owdMs) < 10000)
	{ //only update OWD smaller than 10 s
		if (0 == numOfPacketsPerInterval % p_systemStateSettings->BURST_SAMPLE_FREQUENCY)
		{
			AddDataToBurstRateEstimate(owdMs);
		}
		lastPacketOwd = owdMs;
		numOfPacketsPerInterval++;
		sumOwdPerInterval += lastPacketOwd;
		if (maxOwdPerInterval + 3 < owdMs ) //3ms margin
		{
			maxOwdPerInterval = owdMs;
		}

	    if (dataFlag)
		{
			numOfDataPacketsPerInterval++; //n(i)
			// add GMA2.0 specific per-packet measurement
			if (minOwdPerInterval > owdMs + 3) //3ms margin
			 {
				  lowerOwdNumPerInterval ++ ;
			      if (lowerOwdNumPerInterval > 3)  //update minOWd if > 3 data pkts with lower OWD
			      {
					minOwdPerInterval = owdMs; 
					lowerOwdNumPerInterval = 0;
				  }
			 }
			
			if (p_systemStateSettings->wifiCid == cid)
			{
				p_systemStateSettings->wifiOwdMinLongTerm = std::min(p_systemStateSettings->wifiOwdMinLongTerm, minOwdPerInterval);
				if (owdMs - QUEUEING_DELAY_TARGET_MS > p_systemStateSettings->wifiOwdMinLongTerm)
				  numOfDataDelayViolationPerInterval++; //k(i)
			} else if (p_systemStateSettings->lteCid == cid)
			{
		  		p_systemStateSettings->lteOwdMinLongTerm = std::min(p_systemStateSettings->lteOwdMinLongTerm, minOwdPerInterval); 
	  			if (owdMs - QUEUEING_DELAY_TARGET_MS > p_systemStateSettings->lteOwdMinLongTerm)
				  numOfDataDelayViolationPerInterval++; //k(i)
				//Make sure we already adjust the p_systemStateSettings->lteOwdMinLongTerm based on sender owd adjustment (notified in tsa)!
		     }
		   
		}
		else
		{
			if (minOwdPerInterval > owdMs + 3)
				minOwdPerInterval = owdMs; //update minOWd if any control pkt with lower OWD
		}
	}

}

void MeasureDevice::updateLsn(short lastLsn)
{
	/* the following code detects the following packets (take into account overflow)
		(1) in order (this LSN = last LSN + 1);
		(2) a gap (this LSN > last LSN + 1), which means there are packets missing;
		(3) abnormal (this LSN <= last SN).
	*/
	if (0 == numOfInOrderPacketsPerCycle + numOfAbnormalPacketsPerCycle)
	{ //first packet in this measurement,  mark as in order.
		numOfInOrderPacketsPerCycle++;
		packetsAfterLastLoss++;
		this->lastLsn = lastLsn;
	}
	else
	{
		if (1 == rollOverDiff2(lastLsn, this->lastLsn, 256))
		{ //in order packets
			numOfInOrderPacketsPerCycle++;
			packetsAfterLastLoss++;
			this->lastLsn = lastLsn;
		}
		else if (0 == rollOverDiff2(lastLsn, this->lastLsn, 256))
		{ // duplicate packets
			numOfAbnormalPacketsPerCycle++;
			numOfAbnormalPacketsPerInterval++;
			packetsAfterLastLoss++;
		}
		else if (1 < rollOverDiff2(lastLsn, this->lastLsn, 256))
		{ // detect a gap: received Lsn larger than expected value.
			numOfMissingPacketsPerCycle = numOfMissingPacketsPerCycle + rollOverDiff2(lastLsn, this->lastLsn, 256) - 1;
			numOfMissingPacketsPerInterval = numOfMissingPacketsPerInterval + rollOverDiff2(lastLsn, this->lastLsn, 256) - 1;
			numOfInOrderPacketsPerCycle++;
			packetsBeforeLastLoss = packetsAfterLastLoss;
			packetsAfterLastLoss = 0;
			this->lastLsn = lastLsn;
		}
		else
		{ // lastLsn < this.lastLsn
			numOfAbnormalPacketsPerCycle++;
			numOfAbnormalPacketsPerInterval++;
			packetsAfterLastLoss++;
		}
	}
}

LinkState::LinkState()
{

}

void
LinkState::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}

uint8_t
LinkState::GetDefaultLinkCid()
{
	return p_systemStateSettings->wifiCid;
}

bool
LinkState::IsLinkUp(uint8_t cid)
{
	return true;
}

void
LinkState::NoDataDown(uint8_t cid)
{
	//do nothing here.
}

TrafficSplitting::TrafficSplitting()
{
	m_linkState = new LinkState();
}

TrafficSplitting::~TrafficSplitting()
{
	delete m_linkState;
}

void TrafficSplitting::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
	m_linkState->initUnitSystemStateSettings(p_systemStateSettings);
}

bool TrafficSplitting::delayBasedAlgorithm(int wifiOwd, int lteOwd)
{
	int lastWifiIndex = p_systemStateSettings->wifiSplitFactor;
	bool update = false;
	if (p_systemStateSettings->TOLERANCE_DELAY_BOUND < wifiOwd - lteOwd)
	{
		if (p_systemStateSettings->wifiIndexChangeAlpha >= 0)
		{
			p_systemStateSettings->wifiIndexChangeAlpha = -1;
		}
		if ((wifiOwd - lteOwd >= lastDecisionWifiOwd - lastDecisionlteOwd) && (lastWifiIndex > 0))
		//if (lastWifiIndex > 0)
		{
			lastWifiIndex += std::min(-1, p_systemStateSettings->wifiIndexChangeAlpha + p_systemStateSettings->STEP_ALPHA_THRESHOLD);
			p_systemStateSettings->wifiIndexChangeAlpha -= 1;
			lastWifiIndex = std::max(0, lastWifiIndex);
			update = true;
		}
	}
	else if (p_systemStateSettings->TOLERANCE_DELAY_BOUND < lteOwd - wifiOwd)
	//else if (0  <= lteOwd - wifiOwd)
	{
		if (p_systemStateSettings->wifiIndexChangeAlpha <= 0)
		{
			p_systemStateSettings->wifiIndexChangeAlpha = 1;
		}
		//if (lteOwd >= lastDecisionlteOwd && lastWifiIndex < p_systemStateSettings->paramL)
		if ((lteOwd - wifiOwd  >= lastDecisionlteOwd - lastDecisionWifiOwd) && (lastWifiIndex < p_systemStateSettings->paramL))
		{
			lastWifiIndex += std::max(1, p_systemStateSettings->wifiIndexChangeAlpha - p_systemStateSettings->STEP_ALPHA_THRESHOLD);
			p_systemStateSettings->wifiIndexChangeAlpha += 1;
			lastWifiIndex = std::min(p_systemStateSettings->paramL, lastWifiIndex);
			update = true;
		}
	}
	else //wifi lte delay difference is less than the TOLERANCE_DELAY_L
	{
		p_systemStateSettings->wifiIndexChangeAlpha = 0;//reset the adaptive alpha
	}
	lastDecisionWifiOwd = wifiOwd;
	lastDecisionlteOwd = lteOwd;

	if (update)
	{
		p_systemStateSettings->wifiSplitFactor = lastWifiIndex;
		p_systemStateSettings->lteSplitFactor = p_systemStateSettings->paramL - lastWifiIndex;
		p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg();
		p_systemStateSettings->numOfTsuMessages++;
	}
	return update;
}

bool TrafficSplitting::delayLossBasedAlgorithm(int wifiOwd, int lteOwd, int wifiPackets, int ltePackets)
{
	int lastWifiIndex = p_systemStateSettings->wifiSplitFactor;
	bool update = false;
	bool same_delay = false;
	if (p_systemStateSettings->TOLERANCE_DELAY_BOUND < wifiOwd - lteOwd)
	{
		if (p_systemStateSettings->wifiIndexChangeAlpha >= 0)
		{
			p_systemStateSettings->wifiIndexChangeAlpha = -1;
		}
		if (wifiOwd >= lastDecisionWifiOwd && lastWifiIndex > 0)
		{
			lastWifiIndex += std::min(-1, p_systemStateSettings->wifiIndexChangeAlpha + p_systemStateSettings->STEP_ALPHA_THRESHOLD);
			p_systemStateSettings->wifiIndexChangeAlpha -= 1;
			lastWifiIndex = std::max(0, lastWifiIndex);
			update = true;
		}
	}
	//else if (p_systemStateSettings->TOLERANCE_DELAY_BOUND < lteOwd - wifiOwd)
	else if (0  <= lteOwd - wifiOwd)
	{
		if (p_systemStateSettings->wifiIndexChangeAlpha <= 0)
		{
			p_systemStateSettings->wifiIndexChangeAlpha = 1;
		}
		if (lteOwd >= lastDecisionlteOwd && lastWifiIndex < p_systemStateSettings->paramL)
		{
			lastWifiIndex += std::max(1, p_systemStateSettings->wifiIndexChangeAlpha - p_systemStateSettings->STEP_ALPHA_THRESHOLD);
			p_systemStateSettings->wifiIndexChangeAlpha += 1;
			lastWifiIndex = std::min(p_systemStateSettings->paramL, lastWifiIndex);
			update = true;
		}
	}
	else //wifi lte delay difference is less than the TOLERANCE_DELAY_L
	{
		same_delay = true;
	}
	lastDecisionWifiOwd = wifiOwd;
	lastDecisionlteOwd = lteOwd;

	bool loss = false;
	if (same_delay)
	{
		if (ltePackets > wifiPackets * p_systemStateSettings->TOLERANCE_LOSS_BOUND)
		{
			//decrease wifi, and increase lte
			if (p_systemStateSettings->wifiIndexChangeAlpha >= 0)
			{
				p_systemStateSettings->wifiIndexChangeAlpha = -1;
			}
			if (lastWifiIndex > 0)
			{
				lastWifiIndex += std::min(-1, p_systemStateSettings->wifiIndexChangeAlpha + p_systemStateSettings->STEP_ALPHA_THRESHOLD);
				p_systemStateSettings->wifiIndexChangeAlpha -= 1;
				lastWifiIndex = std::max(0, lastWifiIndex);
				loss = true;
				update = true;
			}
		}
		else if (wifiPackets > ltePackets * p_systemStateSettings->TOLERANCE_LOSS_BOUND)
		{
			//decrease LTE, and increase wifi
			if (p_systemStateSettings->wifiIndexChangeAlpha <= 0)
			{
				p_systemStateSettings->wifiIndexChangeAlpha = 1;
			}
			if (lastWifiIndex < p_systemStateSettings->paramL)
			{
				lastWifiIndex += std::max(1, p_systemStateSettings->wifiIndexChangeAlpha - p_systemStateSettings->STEP_ALPHA_THRESHOLD);
				p_systemStateSettings->wifiIndexChangeAlpha += 1;
				lastWifiIndex = std::min(p_systemStateSettings->paramL, lastWifiIndex);
				loss = true;
				update = true;
			}
		}
		else //wifi lte loss difference is less than the TOLERANCE_LOSS_BOUND
		{
			//same delay and same loss
			p_systemStateSettings->wifiIndexChangeAlpha = 0;//reset the adaptive alpha
		}
	}

	if (update)
	{
		p_systemStateSettings->wifiSplitFactor = lastWifiIndex;
		p_systemStateSettings->lteSplitFactor = p_systemStateSettings->paramL - lastWifiIndex;
		p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg();
		p_systemStateSettings->numOfTsuMessages++;
		this->wifi->packetsBeforeLastLoss = p_systemStateSettings->INITIAL_PACKETS_BEFORE_LOSS;
		this->lte->packetsBeforeLastLoss = p_systemStateSettings->INITIAL_PACKETS_BEFORE_LOSS;
		this->wifi->packetsAfterLastLoss = 0;
		this->lte->packetsAfterLastLoss = 0;
	}
	return update;
}

bool TrafficSplitting::congestionBasedAlgorithm(int wifiPackets, int ltePackets, double wifiUti, double lteUti, int wifiOwd, int lteOwd)
{
	bool update = false;
	if (p_systemStateSettings->wifiSplitFactor == p_systemStateSettings->paramL)
	{
		//all traffic goes to wifi
		if (wifiPackets * p_systemStateSettings->congestDetectLossThreshold < 1 || wifiUti > p_systemStateSettings->congestDetectUtilizationThreshold)
		{
			//utilization > threshold or  loss rate higher than limit, use delay based algorithm
			//trigger to send LTE probe for OWD measurements if the last probe is 10 seconds ago
			if (p_systemStateSettings->currentSysTimeMs - p_systemStateSettings->lastReceiveLteProbeAck > 5000)
			{
				p_systemStateSettings->GMAIPCMessage(3,0,0,false,0); //controlManager.sendLteProbe();
			}
			else
			{
				switch (p_systemStateSettings->SPLIT_ALGORITHM)
				{
				case 1:
					update = delayBasedAlgorithm(wifiOwd, lteOwd);
					break;
				case 2:
					update = delayLossBasedAlgorithm(wifiOwd, lteOwd, wifiPackets, ltePackets);
					break;
				default:
					update = delayBasedAlgorithm(wifiOwd, lteOwd);
					break;
				}
			}
		}
	}
	else
	{ //already started splitting, use delay based algorithm
		switch (p_systemStateSettings->SPLIT_ALGORITHM)
		{
		case 1:
			update = delayBasedAlgorithm(wifiOwd, lteOwd);
			break;
		case 2:
			update = delayLossBasedAlgorithm(wifiOwd, lteOwd, wifiPackets, ltePackets);
			break;
		default:
			update = delayBasedAlgorithm(wifiOwd, lteOwd);
			break;
		}
	}
	return update;
}

void
NS_FATAL_ERROR(std::string str)
{
	std::perror(str.c_str());
}

void
NS_ASSERT_MSG(bool flag, std::string str)
{
	if (flag == false)
	{
		std::perror(str.c_str());
	}
}

int
TrafficSplitting::GetMinSplittingBurst()
{
	return 8;
}

int
TrafficSplitting::GetMaxSplittingBurst()
{	
	return 128;
}

int
TrafficSplitting::GetMeasurementBurstRequirement()
{
	return std::max(p_systemStateSettings->MIN_PACKET_BURST_PER_INTERVAL * p_systemStateSettings->paramL, 128);
}


bool TrafficSplitting::DelayViolationBasedAlgorithm(int wifiViolation, int wifiTotalPkt, int lteViolation, int lteTotalPkt, int durationMs, int threshMs)
{
	//printf("\n ***** MZ measuremnt end | wifi k(i): %d n(i): %d | lte k(i): %d n(i): %d | durationMs: %d | threshMs: %d *****\n", wifiViolation, wifiTotalPkt, lteViolation, lteTotalPkt, durationMs, threshMs);
	//printf("\n ***** MZ | wifi wdMinLongTerm: %d minOwd: %d | lte wdMinLongTerm: %d minOwd: %d *****\n", p_systemStateSettings->wifiOwdMinLongTerm, p_systemStateSettings->wifiOwdMin, p_systemStateSettings->lteOwdMinLongTerm, p_systemStateSettings->lteOwdMin); 
	/**
	 * 
	 * Implement the GMA2.0 Traffic Splitting Algorithm from "AF9456 An Enhanced Dynamic Multi-Access Traffic Splitting Method for Next-Gen Edge Network"
	 * 
	 * Congestion Measurement Requirement:
	 * 1. measurement time should be within range [10ms, 1000ms]
	 * 2. larger than 2 RTT
	 * 3. larger than 2 packet splitting burst 32x2=64 (link failure has to meet this condition!)
	 * 
	 * First define the following parameters:
	 * k(i): num of delay violation data packets for link i.
	 * n(i): num of data packets for link i.
	 * s(i): splitting ratio for link i.
	 * b(i): bandwith estimation for link i, packets/second.
	 * 
	 * This algorithm includes Link failure detection and Enhanced Multi-Path Traffic Splitting Algorithm
	 * 
	 * 
	*/
	int m_splittingBurst = p_systemStateSettings->paramL;
	m_queueingDelayTargetMs = QUEUEING_DELAY_TARGET_MS;

	std::vector<uint8_t> m_lastSplittingIndexList;
	m_lastSplittingIndexList.push_back(p_systemStateSettings->wifiSplitFactor);
	m_lastSplittingIndexList.push_back(p_systemStateSettings->lteSplitFactor);


	//create the measurement object
	//we keep the first link as wifi, and second link as lte
	RxMeasurement *measurement = new RxMeasurement();
	measurement->m_links = 2;
	measurement->m_cidList.push_back(p_systemStateSettings->wifiCid);
	measurement->m_cidList.push_back(p_systemStateSettings->lteCid);

	measurement->m_delayViolationPktNumList.push_back(wifiViolation);
	measurement->m_delayViolationPktNumList.push_back(lteViolation);

	measurement->m_totalPktNumList.push_back(wifiTotalPkt);
	measurement->m_totalPktNumList.push_back(lteTotalPkt);

	measurement->m_measureIntervalThreshS= 0.001*threshMs;
	measurement->m_measureIntervalDurationS = 0.001*durationMs;


	// ---| The following code is from simulation |---
	bool update = false;

	/*//start from all traffic goes to the default link
	if(m_lastSplittingIndexList.size() == 0)
	{
		for (uint8_t ind = 0; ind < measurement->m_links; ind++)
		{
			if(measurement->m_cidList.at(ind) == m_linkState->GetDefaultLinkCid())
			{
				m_lastSplittingIndexList.push_back(m_splittingBurst);
			}
			else
			{
				m_lastSplittingIndexList.push_back(0);
			}
		}
	}*/

	if(m_lastRatio.size() == 0)//not initialized yet.
	{
		for (uint8_t ind = 0; ind < measurement->m_links; ind++)
		{
			m_lastRatio.push_back((double)m_lastSplittingIndexList.at(ind)/m_splittingBurst);
		}
	}

	uint64_t sumPkt = 0; //sum(n(i))

	/**Link Failure Detection**/
	/*
	//The following implements link failure detection
	uint8_t activeLink = 0; //the number of link with s(i) > 0
	for (uint8_t ind = 0; ind < measurement->m_links; ind++)
	{
		if (m_lastSplittingIndexList.at(ind) > 0)
		{
			//link is active for data.
			activeLink++;
		}
		if(m_linkState->IsLinkUp(measurement->m_cidList.at(ind)))//link is okey
		{
			sumPkt += measurement->m_totalPktNumList.at(ind);
		}
	}

	if (activeLink == 0)
	{
		NS_FATAL_ERROR("active link must be > 0");
	}
	else if (activeLink == 1)
	{
		//Single-Link Operation (steer traffic to a single link):
		//If no packet is received in the last interval, i.e. i.e. sum(n(i)) = 0 and Q = 1 (where Q indicates active traffic for this flow), the link failure is detected, 
		//and redirect the flow to another available link. Furthermore, probe or control messages are transmitted over the link to update its status.
		for (uint8_t ind = 0; ind < measurement->m_links; ind++)
		{
			if (m_lastSplittingIndexList.at(ind) > 0)
			{
				//find the only link is active for data.
				if(m_linkState->IsLinkUp(measurement->m_cidList.at(ind)))//link is okey
				{
					if (m_lastSplittingIndexList.at(ind) > 0 && measurement->m_totalPktNumList.at(ind) == 0 && m_splittingBurst == GetMaxSplittingBurst())
					{
						//s(i) > 0 AND n(i) = 0
						//we also make sure it is split mode (m_splittingBurst > 1)

						//for single link, we also need to flow to be active.
						if (m_flowActive)
						{
							//If all conditions are met, mark it as link down.... We will send a TSU to probe the link status. and mark it as up if acked.
							std::cout << "RX APP No Data Link Down | ______________";
							for (uint8_t ind = 0; ind < measurement->m_links; ind++)
							{
								std::cout << "[link:" << +ind << " splitting :"<< +m_lastSplittingIndexList.at (ind)
								<< " total:" << +measurement->m_totalPktNumList.at (ind)<<"] ";
							}
							
							std::cout << " sum: " << sumPkt << " splittingBurst: " << +m_splittingBurst << "\n";
							//let find a better way to compute no data link down... Maybe after the reordering.
							m_linkState->NoDataDown(measurement->m_cidList.at(ind));
							update = true; //send tsu
							m_flowActive = false;
						}
					}
				}
				//else already down, do nothing.
				break;//we only have one link is active
			}

		}
	}
	else
	{
		//Multi-Link Operation (split traffic over multiple links):
		//if the total number of received packets sum(n(i)) in the last interval exceeds T2:
		//		If any link has s(i) > 0 and n(i) = 0, a data channel link failure is identified, and s(i) is set to 0, effectively discontinuing the use of the link for data transmission.
		//		Additionally, probe or control messages are sent immediately over the link to check its connection status.
		//else:
		//		there is not enough data packet for link failure detection.
		for (uint8_t ind = 0; ind < measurement->m_links; ind++)
		{
			if(m_linkState->IsLinkUp(measurement->m_cidList.at(ind)))//link is okey
			{
				if (m_lastSplittingIndexList.at(ind) > 0 && measurement->m_totalPktNumList.at(ind) == 0 && m_splittingBurst == GetMaxSplittingBurst() && (int)sumPkt >= GetMeasurementBurstRequirement())
				{
					//s(i) > 0 AND n(i) = 0
					//we also make sure it is split mode (m_splittingBurst > 1), and the total received pkt numbner is greater than the min pkt requirement for measurement
					//If all conditions are met, mark it as link down.... We will send a TSU to probe the link status. and mark it as up if acked.
					std::cout << "RX APP No Data Link Down | ______________";
					for (uint8_t ind = 0; ind < measurement->m_links; ind++)
					{
						std::cout << "[link:" << +ind << " splitting :"<< +m_lastSplittingIndexList.at (ind)
						<< " total:" << +measurement->m_totalPktNumList.at (ind)<<"] ";
					}
					
					std::cout << " sum: " << sumPkt << " splittingBurst: " << +m_splittingBurst << "\n";
					//let find a better way to compute no data link down... Maybe after the reordering.
					m_linkState->NoDataDown(measurement->m_cidList.at(ind));
					update = true; //send tsu
				}
			}
		}
	}
	//link failure detection done.
	*/
	/*
	std::cout << "Measurement Interval: " << measurement->m_measureIntervalDurationS << " s \n";
	for (uint8_t ind = 0; ind < measurement->m_links; ind++)
	{
		std::cout << "[link: " << +ind 
		<< ", s(i):"<<+m_lastSplittingIndexList.at (ind) 
		<< ", k(i):"<<measurement->m_delayViolationPktNumList.at (ind)
		<< ", n(i):" << measurement->m_totalPktNumList.at (ind)
		<< ", status:" << m_linkState->IsLinkUp(measurement->m_cidList.at(ind))
		<< "]\n";
	}*/

	/**GMA2.0 Enhanced Traffic Splitting Algorithm**/
	//compute the congestion measurement values after updating the link status.
	uint32_t noneCongestedLink = 0; //check the number of links without congestion k(i) == 0.
	sumPkt = 0; //sum(n(i))
	uint64_t sumCongested = 0; //sum((k(i))
	uint64_t sumPktNoCongestion = 0; //sum(n(i)) under the condition k(i) == 0

	for (uint8_t ind = 0; ind < measurement->m_links; ind++)
	{
		double bw = 0;
		if(m_linkState->IsLinkUp(measurement->m_cidList.at(ind)))//link is okey
		{
			if (m_lastSplittingIndexList.at(ind) > 0 && measurement->m_totalPktNumList.at(ind) > 0)
			{
				//at least one link s(i) > 0 and n(i) > 0
				m_flowActive = true;
			}

			if (measurement->m_delayViolationPktNumList.at(ind) == 0)
			{
				//find one link without congestion
				noneCongestedLink++;
			}
			sumCongested += measurement->m_delayViolationPktNumList.at(ind);
			sumPkt += measurement->m_totalPktNumList.at(ind);
			if (measurement->m_delayViolationPktNumList.at(ind) == 0)
			{
				sumPktNoCongestion += measurement->m_totalPktNumList.at(ind);
			}
			bw = (double)measurement->m_totalPktNumList.at(ind)/measurement->m_measureIntervalDurationS;
		}

		//compute bw estimate b(i) here
		//if link is down, bw = 0
		auto iterBw = m_cidToBwHistMap.find(measurement->m_cidList.at(ind));
		auto iterKi = m_cidToKiHistMap.find(measurement->m_cidList.at(ind));
		if (iterBw == m_cidToBwHistMap.end())
		{
			m_cidToBwHistMap[measurement->m_cidList.at(ind)]=std::vector<double>{bw};
			m_cidToKiHistMap[measurement->m_cidList.at(ind)]=std::vector<uint32_t>{measurement->m_delayViolationPktNumList.at(ind)};

		}
		else
		{
			iterBw->second.push_back(bw);
			iterKi->second.push_back(measurement->m_delayViolationPktNumList.at(ind));
		}
	}

	// only keep the last m_bwHistSize bw estimate, e.g., only use the the last 10 measurements to find the max bandwidth.
	auto iterBw = m_cidToBwHistMap.begin();
	auto iterKi = m_cidToKiHistMap.begin();
	while (iterBw != m_cidToBwHistMap.end())
	{

		while(iterBw->second.size() > m_bwHistSize)
		{
			//remove old measurement-> only keep m_bwHistSize, e.g., 10 bw measurements.
			iterBw->second.erase(iterBw->second.begin());
			iterKi->second.erase(iterKi->second.begin());
		}
		//std::cout << "cid: " << +iterBw->first << " bw: [";
		//for (uint32_t i = 0; i < iterBw->second.size(); i++)
		//{
		//	std::cout << iterBw->second.at(i) << " ";
		//}
		//std::cout << "]" << std::endl;
		iterBw++;
		iterKi++;
	}

	//auto iterMaxBw = m_cidToMaxBwMap.begin();
	//std::cout << "allLinkBwAvailable: " << allLinkBwAvailable << " | sumMaxBwKequalZero: " << sumMaxBwKequalZero;
	//while (iterMaxBw != m_cidToMaxBwMap.end())
	//{
	//	std::cout << "[cid: " << +iterMaxBw->first << " max bw: " << iterMaxBw->second << "]" ;
	//	iterMaxBw++;
	//}
	//std::cout << std::endl;

	//start GMA2.0 splitting algorithm
	std::vector<double> newRatio;

	if (sumPkt == 0)
	{
		//Case #1 (No Traffic): If no links receive any packets, i.e., n(i) = 0 for all links, we will stop splitting and steer the flow to the default link.
		for (uint8_t ind = 0; ind < measurement->m_links; ind++)
		{
			newRatio.push_back(0.0);
			//If n(i) = 0 for all links //no traffic
			//set s(x) = 1.0 for the default link, and s(j) = 0 for all other links.
			if(measurement->m_cidList.at(ind) == m_linkState->GetDefaultLinkCid())
			{
				if(m_linkState->IsLinkUp(measurement->m_cidList.at(ind)))//link is okey
				{
					newRatio.at(ind) = 1.0;//should only be 1 link.
				}
				else
				{
					NS_FATAL_ERROR("default link should always be up!");
				}
			}
		}
	}
	else
	{
		//data measurement is active.
		if (sumCongested == 0) // no congestion for all links
		{

			//Case #2 (No Congestion): If no links experience congestion, i.e., k(i) = 0 for all links,

			//we will steer traffic from a none-default none-zero traffic link j to the default link.
			uint64_t nDefN = 0; //non-default link with none-zero traffic.
			uint8_t nDefIndex = 0;
			uint8_t defIndex = 0;
			uint8_t linkWithData = 0; //num of links n(i) > 0
			for (uint8_t ind = 0; ind < measurement->m_links; ind++)
			{
				if(m_linkState->IsLinkUp(measurement->m_cidList.at(ind)))//link is okey
				{
					if (measurement->m_totalPktNumList.at(ind) > 0)
					{
						linkWithData++;
					}

					if(measurement->m_cidList.at(ind) != m_linkState->GetDefaultLinkCid())
					{
						//none default link
						if (measurement->m_totalPktNumList.at(ind) > 0)
						{
							//none default and none zero traffic.
							nDefN = measurement->m_totalPktNumList.at(ind);
							nDefIndex = ind;
						} 
					}
					else
					{
						//default link
						defIndex =  ind;
					}
				}
			}

			if (linkWithData == 1)  //move all traffic to the default link if only one link is active without congestion
			{
				//If only one link has data, i.e., n(x) > 0, set s(x) = 1.0 and s(j) = 0 for other links.
				//x: to indicate the default link.
				//j: indicates non default links.
				for (uint8_t ind = 0; ind < measurement->m_links; ind++)
				{
					newRatio.push_back(0.0);
					if(m_linkState->IsLinkUp(measurement->m_cidList.at(ind)))//link is okey
					{
						if(measurement->m_cidList.at(ind) == m_linkState->GetDefaultLinkCid())
						{
							newRatio.at(ind) = 1.0;//should only be 1 link.
						}
					}
				}

			}
			else
			{
				//More than one link has data
				//	x: indicates the none-default none zero traffic link that need to reallocate.
				//	j: indicate the default link.
				//  k: other none-default link does not need to reallocate.
				//For link x:
				//	Set s(x) = (n(x) - R)/sum(n(i)), where R = min(n(x), p*sum(n(i))) and p = 0.1 //if n(x) is larger than R, it takes a few iterations to move all traffic from link x to link j.
				//For link j:
				//	s(j) = (n(j) + R)/sum(n(i))
				//For link k:
				// s(k) = (n(k))/sum(n(i))

				m_relocateScaler = ((double)p_systemStateSettings->minSplitAdjustmentStep)/((double)m_splittingBurst);				
				//move traffic to the default link
				uint64_t relocatePktNum = std::min(nDefN, (uint64_t)(m_relocateScaler*(double)sumPkt)); //compute R.  

				if (relocatePktNum  > 0)
				{
					//std::cout << " relocate data: " << relocatePktNum << " from nDefIndex: " << +nDefIndex << " to defIndex: " << +defIndex <<std::endl;
					for (uint8_t ind = 0; ind < measurement->m_links; ind++)
					{
						newRatio.push_back(0.0);
						if(m_linkState->IsLinkUp(measurement->m_cidList.at(ind)))//link is okey
						{
							if (measurement->m_totalPktNumList.at(ind) < measurement->m_delayViolationPktNumList.at(ind) || sumPkt == 0)
							{
								NS_FATAL_ERROR("traffic splitting algorithm condition not meet!");
							}


							if (ind == nDefIndex)//find none-default none-zero link that need reallocate
							{
								//s(x) = (n(x) - R)/sum(n(i))
								newRatio.at(ind) = (double)(nDefN-relocatePktNum)/sumPkt;
							}
							else if (ind == defIndex) //find the default link
							{
								// /s(j) = (n(j) + R)/sum(n(i))	
								newRatio.at(ind)= (double)(measurement->m_totalPktNumList.at(ind) + relocatePktNum)/sumPkt;
							}
							else //other none-default links keeps s(k) = n(k)/sum(n(i))
							{
								//s(k) = (n(k))/sum(n(i))
								newRatio.at(ind)= (double)(measurement->m_totalPktNumList.at(ind))/sumPkt;
							}
						}
					}
				}
			}
		}
		else //we detect links with congestion
		{
			//case #3 and case #4 is implemented here.

			if (noneCongestedLink > 0)//we also detect links without congestion.
			{
				//Case #3 (Medium Congestion): When only a subset of links experience congestion, k(i) > 0 for some links, 
				//we will reallocate a portion of data traffic from a congested link to non-congested links.

				//check if all operational link has bandwidth estimate.
				bool allLinkBwAvailable = true; //for simplicity, here we check all links, not only the non-congested links.
				std::map< uint8_t, double> m_cidToMaxBwMap; // the key is the cid of the link and the value is the bandwith estimate.
				double sumMaxBwKequalZero = 0.0;
				for (uint8_t ind = 0; ind < measurement->m_links; ind++)
				{
					if(m_linkState->IsLinkUp(measurement->m_cidList.at(ind)))//link is okey
					{
						auto iterBw = m_cidToBwHistMap.find(measurement->m_cidList.at(ind));
						auto iterKi = m_cidToKiHistMap.find(measurement->m_cidList.at(ind));
						if (iterBw != m_cidToBwHistMap.end())
						{
							auto histBwVector = iterBw->second;
							double maxBw = *max_element (histBwVector.begin(), histBwVector.end());

							auto histKiVector = iterKi->second;
							double maxKi = *max_element (histKiVector.begin(), histKiVector.end());

							NS_ASSERT_MSG(histBwVector.size() == histKiVector.size(), "The size of k(i) and b(i) hist must be the same!");

							m_cidToMaxBwMap[measurement->m_cidList.at(ind)] = maxBw;
							if (measurement->m_delayViolationPktNumList.at(ind) == 0)
							{
								sumMaxBwKequalZero += maxBw;
							}

							if (maxKi == 0 || maxBw < 1.0)
							{
								//never experienced congestion or bw smaller than 1 packet / second, consider no bandwidth measurement->
								allLinkBwAvailable = false;
							}
								
						}
						else
						{
							//find at least one link without bw history.
							allLinkBwAvailable = false;
						}
						//else no bw history for this link.
					}
				}

				for (uint8_t ind = 0; ind < measurement->m_links; ind++)
				{
					newRatio.push_back(0.0);
					if(m_linkState->IsLinkUp(measurement->m_cidList.at(ind)))//link is okey
					{
						if (measurement->m_totalPktNumList.at(ind) < measurement->m_delayViolationPktNumList.at(ind) || sumPkt == 0)
						{
							NS_FATAL_ERROR("traffic splitting algorithm condition not meet!");
						}

						double newScaler = m_congestionScaler; //initial to the default value, e.g., 0.3
						if (m_adaptiveCongestionScaler && allLinkBwAvailable)
						{
							//Enhancement #1:
							//In the case of medium congestion (case #3), the objective is to transfer congested packets from links with k(x) > 0 to links with k(j) = 0 without causing congestion to link j. 
							//This means that the total amount of reallocated traffic, given by sum(k(x))*a, must not exceed the available resources in non-congested links, given by sum(b(j))*D - sum(n(j))), 
							//where D is the interval duration for this congestion measurement-> Instead of using a constant a, e.g., 0.3, 
							//we can adaptively learn its value using the following two steps assuming b(j) > 0 for all links:

							//step 1: a = (sum(b(j))*D - sum(n(j)))/sum(k(x)). 
							newScaler = (sumMaxBwKequalZero*measurement->m_measureIntervalDurationS-sumPktNoCongestion)/sumCongested;
							if (newScaler < -1e-9)//ignore the the rounding error.
							{
								NS_FATAL_ERROR("newScaler cannot be smaller than zero!!!");
							}
							//step 2: a = max(a_min, min(a, a_max)), where a_min = 0.1 and a_max = 0.5. //this step limits the range of ‘a’ to be [0.1, 0.5].
							newScaler = std::max(CONGESTION_SCALER_MIN, newScaler);
							newScaler = std::min(CONGESTION_SCALER_MAX, newScaler);

						}

						if (measurement->m_delayViolationPktNumList.at(ind) > 0) // k(x) > 0
						{
							//For link x, where x indicates the link with k(x) > 0:
							//set s(x) = (n(x) - k(x) * a))/sum(n(i)), where a is configurable control parameter, e.g. 0.3.
							newRatio.at(ind) = (double)(measurement->m_totalPktNumList.at(ind) - measurement->m_delayViolationPktNumList.at(ind) * newScaler) / sumPkt;
						}
						else // k(j) == 0
						{
							//For link j, where j indicates the link with k(j) = 0:
							if (m_enableBwEstimate && allLinkBwAvailable)//check if bandwith estimate is enabled, and whether all links has bw estimate.
							{
								//Option #1: set s(j) = (sum(n(j)) + sum(k(x) * a))*b(j)/sum(b(j))/sum(n(i)) if b(j) > 0 for all links,
								NS_ASSERT_MSG(sumMaxBwKequalZero > 0, "the sumMaxBwKequalZero must be greater than zero");
								newRatio.at(ind) = (double)(sumPktNoCongestion + sumCongested*newScaler)*m_cidToMaxBwMap[measurement->m_cidList.at(ind)]/(sumMaxBwKequalZero*sumPkt);
							}
							else
							{
								//Option #2: set s(j) = (n(j) + sum(k(x)) * a/L)/sum(n(i)) if b(j) = 0 for any link, where L is the number of the links with k(j) = 0.
								//newRatio.at(ind) = (double)(sumPktNoCongestion + sumCongested*newScaler)/(noneCongestedLink*sumPkt);
								newRatio.at(ind) = (double)(measurement->m_totalPktNumList.at(ind) + sumCongested*newScaler/noneCongestedLink)/sumPkt;
							}

						}
					}
					else
					{
						//link down ratio = 0.0;
					}
				}
			}
			else
			{
				//Case #4 (Heavy Congestion): If all links are congested, i.e. k(i) > 0 for all links, the algorithm redistributes traffic among all links in proportion to n(i).
				for (uint8_t ind = 0; ind < measurement->m_links; ind++)
				{
					newRatio.push_back(0.0);
					if(m_linkState->IsLinkUp(measurement->m_cidList.at(ind)))//link is okey
					{
						double newScaler = 0.0;
						if (measurement->m_totalPktNumList.at(ind) < measurement->m_delayViolationPktNumList.at(ind) || sumPkt-sumCongested*newScaler == 0)
						{
							NS_FATAL_ERROR("traffic splitting algorithm condition not meet!");
						}
						//we assume the newScaler < 1.
						//set s(i) = n(i)/sum(n(i))
						newRatio.at(ind) = (double)(measurement->m_totalPktNumList.at(ind) - measurement->m_delayViolationPktNumList.at(ind) * newScaler) / (sumPkt-sumCongested*newScaler);
					}
					else
					{
						//link down ratio = 0.0;
					}
				}

			}
		}

	}

	if (newRatio.size() > 0) //if the algorithm does not need update, the new ratio size will be zero.
	{
		//std::cout << " splitting ratio: ";
		//for (uint8_t ind = 0; ind < measurement->m_links; ind++)
		//{
		//	std::cout << newRatio.at(ind) << " ";
		//}
		//std::cout << "\n";
		//we will use the last link to take care of the rounding error.

		if (p_systemStateSettings->m_adaptiveSplittingBurst)
		{
			//compute a new splitting burst
			
			/*m_splittingBurst = GetMaxSplittingBurst();//start from the max one
			while (m_splittingBurst > GetMinSplittingBurst() && GetMeasurementBurstRequirement() > (int)(measurement->m_splittingBurstRequirementEst)) //while the splitting burst is greater than min_bust and requirement is greater than the estimate.
			{
				//double every time
				m_splittingBurst = m_splittingBurst/2;
			}*/

			int estBurstRequirement = (int)floor(log2((double)(sumPkt*measurement->m_measureIntervalThreshS)
				/(double)(p_systemStateSettings->MIN_PACKET_BURST_PER_INTERVAL*measurement->m_measureIntervalDurationS))); 

			m_splittingBurst = (int)pow(2, std::min(std::max(3, (int)(estBurstRequirement)), 7));
			//std::cout << " requirement est: " << +measurement->m_splittingBurstRequirementEst << " new splitting_burst: " << +m_splittingBurst << std::endl;
		}

		//we use to m_roundingScaler (must be negative), e.g., -0.3. to decrease the ratio more aggressively. Define m(i) as splitting burst for link i and sum(m(i)) equals m_splittingBurst.
		//if s(j) is decreased, m(j) = round(s(j)*m_splittingBurst + m_roundingScaler) //reduce splitting burst more while rounding for link j if s(j) decreasing.
		//else s(k) is equal or increased, m(k) = round((m_splittingBurst - sum(m(j)))*s(k)/sum(s(k))) //distribute the remaining burst to other links.
		std::vector < uint8_t > burstPerLink;
		double newRatioSum = 0;
		int burstSum = 0;
		double decreaseBurstSum = 0; //sum(m(j))
		double equalOrIncreaseRatioSum = 0; //sum(s(k))

		//compute burst for decreased ratio
		for (uint8_t ind = 0; ind < measurement->m_links; ind++)
		{
			burstPerLink.push_back(0); //place holder, will overwrite it later.
			if (newRatio.at(ind) < m_lastRatio.at(ind))
			{
				//s(i) reduced.
				//m(j) = round(s(j)*m_splittingBurst + m_roundingScaler) 
				double mj = std::round(newRatio.at(ind)*m_splittingBurst+m_roundingScaler);
				burstPerLink.at(ind) = mj;
				decreaseBurstSum += mj; //sum(m(j))
			}
			else
			{
				//s(i) increased.
				//burstPerLin will be computed in the next loop.
				equalOrIncreaseRatioSum += newRatio.at(ind);
			}
		}

		NS_ASSERT_MSG(equalOrIncreaseRatioSum, "equalOrIncreaseRatioSum cannot be zero!");

		//compute burst for equal or increased ratio.
		for (uint8_t ind = 0; ind < measurement->m_links; ind++)
		{
			if (newRatio.at(ind) < m_lastRatio.at(ind))
			{
				//s(i) reduced.
				//already computed in the previous loop.
			}
			else
			{
				//s(i) increased.
				//m(k) = round((m_splittingBurst - sum(m(j)))*s(k)/sum(s(k)))
				double mk = std::round( (m_splittingBurst-decreaseBurstSum)*newRatio.at(ind)/equalOrIncreaseRatioSum);
				burstPerLink.at(ind) = mk;
			}
			burstSum += burstPerLink.at(ind);
			newRatioSum += newRatio.at(ind);
		}
		
		if (newRatioSum > 1.001 || newRatioSum < 0.999)
		{
			NS_FATAL_ERROR("The new ratio is not equal 1!!");
		}

		NS_ASSERT_MSG(burstSum != 0, "the sum of burst per link cannot be empty");

		//std::cout << " burst 0: " << +burstPerLink.at(0) << " burst 1: " << +burstPerLink.at(1) << " burst 2: " << +burstPerLink.at(2) << std::endl;

		//take care of rounding error.

		//if total burst size is smaller than the required splitting burst size, increase 1 burst for the highest traffic link?
		//the reason for this it the lowest link may be zero, and it may be intentional, e.g., one link is never used.
		while(burstSum < m_splittingBurst)
		{
			//std::cout << "sum smaller than splitting burst size!!!" << std::endl;
			auto index = std::distance(burstPerLink.begin(),std::max_element(burstPerLink.begin(), burstPerLink.end()));
			burstPerLink.at(index) += 1;
			burstSum += 1;
		}

		//if total burst size is smaller than the required splitting burst size, decrease 1 burst for the highest traffic link.
		while(burstSum > m_splittingBurst)
		{
			//std::cout << "sum greater than splitting burst size!!! burstSum: " << burstSum << std::endl;
			auto index = std::distance(burstPerLink.begin(),std::max_element(burstPerLink.begin(), burstPerLink.end()));
			burstPerLink.at(index) -= 1;
			burstSum -= 1;
		}
		
		//std::cout << "Fix Rounding Error | total: " << +m_splittingBurst << " burst 0: " << +burstPerLink.at(0) << " burst 1: " << +burstPerLink.at(1) << " burst 2: " << +burstPerLink.at(2) << std::endl;
			
		//check if there is any update...
		for (uint8_t ind = 0; ind < measurement->m_links; ind++)
		{
			if (m_lastSplittingIndexList.at(ind) != burstPerLink.at(ind))
			{
				update = true;
				m_lastSplittingIndexList= burstPerLink;
				m_lastRatio = newRatio;
				break;
			}
		}
		/*disable stable algorithm for now*/
	}
	//end of gma2.0 splitting algorithm.

	if(update)
	{
		/*
		std::cout << "RX APP ======= interval: " << measurement->m_measureIntervalDurationS << " s \n";
		for (uint8_t ind = 0; ind < measurement->m_links; ind++)
		{
			std::cout << "[link: " << +ind << ", split ratio:"<<+m_lastSplittingIndexList.at (ind) 
			<< ", violation:"<<measurement->m_delayViolationPktNumList.at (ind)
			<< ", total:" << measurement->m_totalPktNumList.at (ind)<<"] ";
			std::cout << "\n";

			}
		}
		*/
		
		//check if the sum equals splitting burst size;
		uint8_t sumRatio = 0;
		for (uint8_t ind = 0; ind < measurement->m_links; ind++)
		{
			sumRatio += m_lastSplittingIndexList.at (ind);
		}

		NS_ASSERT_MSG(sumRatio == m_splittingBurst, "the summation must equals the splitting burst size");

		if (update)
		{

			p_systemStateSettings->wifiSplitFactor = m_lastSplittingIndexList.at(0); //wifi
			p_systemStateSettings->lteSplitFactor = m_lastSplittingIndexList.at(1); //lte
			p_systemStateSettings->paramL = m_splittingBurst; //L
			p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg();
			p_systemStateSettings->numOfTsuMessages++;
		}
	}
	delete measurement;
	return update;
}

MeasurementManager::MeasurementManager()
{
	measureIntervalThresh = 10;
}

void MeasurementManager::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}

void MeasurementManager::updateSystemSettings()
{

	if(m_alwaysUseGmaTwoAlgorithm)
	{
		//use gma 2.0 algorithm.
		p_systemStateSettings->SPLIT_ALGORITHM = 3;
	}
	//Suppose restart new measurementManager, updates
	measureStartSn = 0;
	lastSn = 0;
	measureIntervalOn = false; // true stands for a measurement interval is tarted
	measureIntervalIndex = 0;		// current measure interval index
	measureIntervalStartTime = 0;

	measureIntervalThresh = p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION;
	if (trafficSplitting)
		delete trafficSplitting;
	trafficSplitting = new TrafficSplitting();
	trafficSplitting->initUnitSystemStateSettings(p_systemStateSettings);
	if (wifi)
		delete wifi;
	wifi = new MeasureDevice(p_systemStateSettings->wifiCid);
	wifi->initUnitSystemStateSettings(p_systemStateSettings);
	if (lte)
		delete lte;
	lte = new MeasureDevice(p_systemStateSettings->lteCid);
	lte->initUnitSystemStateSettings(p_systemStateSettings);

	trafficSplitting->wifi = wifi;
	trafficSplitting->lte = lte;
	measureCycleStart(0);
}

MeasurementManager::~MeasurementManager()
{
	delete trafficSplitting;
	delete wifi;
	delete lte;
}

bool
MeasurementManager::measureCycleStarted()
{
	return measureCycleOn;
}

bool
MeasurementManager::measureIntervalStarted()
{
	return measureIntervalOn;
}

void MeasurementManager::measureCycleStart(int x)
{
	measureIntervalIndex = 0;
	measureStartSn = x;
	measureCycleOn = true;
	measureIntervalOn = false; //the first measure interval will start after lastSn > startSn

	wifi->lastIntervalOwd = INT_MAX; // MA_VALUE stands for unknown
	lte->lastIntervalOwd = INT_MAX;	 // MA_VALUE stands for unknown

	wifi->lastIntervalOwdDiff = 1.0;
	lte->lastIntervalOwdDiff = 1.0;

	//the lost rate is measured during the entire measure cycle (not the last interval).
	wifi->numOfInOrderPacketsPerCycle = 0;
	wifi->numOfMissingPacketsPerCycle = 0;
	wifi->numOfAbnormalPacketsPerCycle = 0;
	lte->numOfInOrderPacketsPerCycle = 0;
	lte->numOfMissingPacketsPerCycle = 0;
	lte->numOfAbnormalPacketsPerCycle = 0;

	wifi->rateEstimationPerCycle = 0;
	lte->rateEstimationPerCycle = 0;
}

bool MeasurementManager::measureIntervalStartConditionCheck(int x, int nextSn)
{
	// return true if measurement cycle is on, last received sn > start sn, and measurement interval is not started yet.
	if (rollOverDiff2(x, nextSn, 16777216) >= 0)
	{ 
		lastSn = x; //last in-order packet 
		return (rollOverDiff2(lastSn, measureStartSn, 16777216) >= 0 && !measureIntervalOn);
	}
	else
		return (false);
}


bool MeasurementManager::restart(long currentTimeMs)
{
	if (currentTimeMs < measureIntervalEndTime || currentTimeMs - measureIntervalEndTime > 1000)
		return(true);
	else
		return(false);

}


void MeasurementManager::measureIntervalStart(long currentTimeMs)
{
	measureIntervalOn = true;
	measureIntervalStartTime = currentTimeMs;

	//initialize measurement parameters
	wifi->sumOwdPerInterval = 0;
	wifi->numOfPacketsPerInterval = 0;
	wifi->numOfDataPacketsPerInterval = 0;
	wifi->numOfDataDelayViolationPerInterval = 0;
	wifi->minOwdPerInterval = INT_MAX;
	wifi->maxOwdPerInterval = INT_MIN;
	wifi->lowerOwdNumPerInterval = 0;

	lte->sumOwdPerInterval = 0;
	lte->numOfPacketsPerInterval = 0;
	lte->numOfDataPacketsPerInterval = 0;
	lte->numOfDataDelayViolationPerInterval = 0;
	lte->minOwdPerInterval = INT_MAX;
	lte->maxOwdPerInterval = INT_MIN;
	lte->lowerOwdNumPerInterval = 0;

	measureIntervalIndex++;

	wifi->receivedBytesIntervalStart = p_systemStateSettings->wifiReceiveNrtBytes;
	lte->receivedBytesIntervalStart = p_systemStateSettings->lteReceiveNrtBytes;

	wifi->resetBurstRateEstimate();
	lte->resetBurstRateEstimate();


	if (lastOwdUpdateTime == 0 || lastOwdUpdateTime > currentTimeMs)
	  lastOwdUpdateTime = currentTimeMs;
	//this interval will last max (RTT)
	measureIntervalThresh = std::max(p_systemStateSettings->lteLinkRtt, p_systemStateSettings->wifiLinkRtt);
	if (3 == p_systemStateSettings->SPLIT_ALGORITHM)
	{
		//double the duration time for gma 2.0
		 measureIntervalThresh = std::max(p_systemStateSettings->MIN_MEASURE_INTERVAL_DURATION, std::min(measureIntervalThresh*2, p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION));
		//measureIntervalThresh = std::max(p_systemStateSettings->MIN_MEASURE_INTERVAL_DURATION, std::min(measureIntervalThresh, p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION));

	}
	else
	{
		 measureIntervalThresh = std::max(p_systemStateSettings->MIN_MEASURE_INTERVAL_DURATION, std::min(measureIntervalThresh, p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION));
	}
	wifi->numOfMissingPacketsPerInterval = 0;
	wifi->numOfAbnormalPacketsPerInterval = 0;

	lte->numOfMissingPacketsPerInterval = 0;
	lte->numOfAbnormalPacketsPerInterval = 0;

}

void MeasurementManager::measureIntervalEndCheck(long currentTimeMs)
{
	if (!measureIntervalOn)
	{
		//measurement interval not started
		return;
	}

	//measurement interval started.
	if (3 == p_systemStateSettings->SPLIT_ALGORITHM)
	{ 
		//GMA 2.0
		if (currentTimeMs > measureIntervalStartTime + p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION || currentTimeMs < measureIntervalStartTime)
		{ //reach maximum interval time (1s)
			measureIntervalEnd(currentTimeMs);
		}
		else if (currentTimeMs >= measureIntervalStartTime + measureIntervalThresh && p_systemStateSettings->MIN_PACKET_BURST_PER_INTERVAL * p_systemStateSettings->paramL < lte->numOfDataPacketsPerInterval + wifi->numOfDataPacketsPerInterval)
		{
			// end this measure interval, if (1) interval lasts  more than max(rtt) & (2) received packets > 10
			measureIntervalEnd(currentTimeMs);
		}

	}
	else {
		//GMA 1.0
		if (currentTimeMs > measureIntervalStartTime + p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION || currentTimeMs < measureIntervalStartTime)
		{ //reach maximum interval time (1s)
			if (p_systemStateSettings->MIN_PACKET_BURST_PER_INTERVAL * p_systemStateSettings->paramL > lte->numOfDataPacketsPerInterval + wifi->numOfDataPacketsPerInterval)
			{ //not enough sample, move all traffic to WiFi
				//not enough sample for splitting algorithm
				measureIntervalEndAbnormal(currentTimeMs);
				if (p_systemStateSettings->gDynamicSplitFlag == 1)
				{ //move all traffic over wifi if dynamic splitting is enabled
					if (p_systemStateSettings->wifiSplitFactor < p_systemStateSettings->paramL)
					{ // check if the traffic already over wifi only
						if (!p_systemStateSettings->gDLAllOverLte && p_systemStateSettings->gIsWifiConnect && p_systemStateSettings->gScreenOnFlag)
						{
							p_systemStateSettings->wifiSplitFactor = p_systemStateSettings->paramL;
							p_systemStateSettings->lteSplitFactor = 0;
							p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg();
							p_systemStateSettings->numOfTsuMessages++;

						}
					}
				}
			}
			else
			{ // reach time limit and have enough samples, end interval and do measurement->
				measureIntervalEnd(currentTimeMs);
			}
		}
		else if (currentTimeMs >= measureIntervalStartTime + measureIntervalThresh && p_systemStateSettings->MIN_PACKET_BURST_PER_INTERVAL * p_systemStateSettings->paramL < lte->numOfDataPacketsPerInterval + wifi->numOfDataPacketsPerInterval)
		{
			// end this measure interval, if (1) interval lasts  more than max(rtt) & (2) received packets > 10
			measureIntervalEnd(currentTimeMs);
		}
	}
}

void MeasurementManager::measureIntervalEndAbnormal(long currenTimeMs)
{ //save measurement and restart
	//save measurements
	if (wifi->numOfPacketsPerInterval > 0)
	{
		//update global variable
		p_systemStateSettings->wifiOwdSum += wifi->sumOwdPerInterval;
		p_systemStateSettings->wifiPacketNum += wifi->numOfPacketsPerInterval;
		p_systemStateSettings->wifiOwdMax = std::max(p_systemStateSettings->wifiOwdMax, wifi->maxOwdPerInterval);
		p_systemStateSettings->wifiOwdMin = std::min(p_systemStateSettings->wifiOwdMin, wifi->minOwdPerInterval);
	}
	if (lte->numOfPacketsPerInterval > 0)
	{
		//update global variable
		p_systemStateSettings->lteOwdSum += lte->sumOwdPerInterval;
		p_systemStateSettings->ltePacketNum += lte->numOfPacketsPerInterval;
		p_systemStateSettings->lteOwdMax = std::max(p_systemStateSettings->lteOwdMax, lte->maxOwdPerInterval);
		p_systemStateSettings->lteOwdMin = std::min(p_systemStateSettings->lteOwdMin, lte->minOwdPerInterval);
    
	}

	//update global variable
	p_systemStateSettings->wifiInorderPacketNum += wifi->numOfInOrderPacketsPerCycle;
	p_systemStateSettings->wifiMissingPacketNum += wifi->numOfMissingPacketsPerCycle;
	p_systemStateSettings->wifiAbnormalPacketNum += wifi->numOfAbnormalPacketsPerCycle;

	p_systemStateSettings->lteInorderPacketNum += lte->numOfInOrderPacketsPerCycle;
	p_systemStateSettings->lteMissingPacketNum += lte->numOfMissingPacketsPerCycle;
	p_systemStateSettings->lteAbnormalPacketNum += lte->numOfAbnormalPacketsPerCycle;

	measureCycleStart(lastSn); //restart a new measurement
	measureIntervalEndTime = currenTimeMs;
}

void MeasurementManager::measureIntervalEnd(long currentTimeMs)
{
	measureIntervalOn = false;
	measureIntervalEndTime = currentTimeMs;

	if (wifi->numOfPacketsPerInterval > 0)
	{
		//update global variable
		p_systemStateSettings->wifiOwdSum += wifi->sumOwdPerInterval;
		p_systemStateSettings->wifiPacketNum += wifi->numOfPacketsPerInterval;
		p_systemStateSettings->wifiOwdMax = std::max(p_systemStateSettings->wifiOwdMax, wifi->maxOwdPerInterval);
		p_systemStateSettings->wifiOwdMin = std::min(p_systemStateSettings->wifiOwdMin, wifi->minOwdPerInterval);

		//WiFi measurement available, update OWD
		int wifiOwd = static_cast<int>(wifi->sumOwdPerInterval / wifi->numOfPacketsPerInterval);
		if (wifiOwd != INT_MAX && wifi->lastIntervalOwd != INT_MAX)
		{
			wifi->lastIntervalOwdDiff = std::abs(1.0 * (wifiOwd - wifi->lastIntervalOwd) / p_systemStateSettings->wifiLinkRtt);
		}
		wifi->lastIntervalOwd = wifiOwd;
		//update rtt based on the diff of data owd and control owd
		if (INT_MAX != p_systemStateSettings->wifiLinkCtrlOwd)
		{
			p_systemStateSettings->wifiLinkRtt = p_systemStateSettings->wifiLinkCtrlRtt + wifiOwd - p_systemStateSettings->wifiLinkCtrlOwd;
		}
		//printf("\n ***** MZ WiFi RTT update | data RTT: %d ctr RTT: %d data owd: %d ctrl owd: %d *****\n", p_systemStateSettings->wifiLinkRtt, p_systemStateSettings->wifiLinkCtrlRtt, wifiOwd, p_systemStateSettings->wifiLinkCtrlOwd);

	}
	if (lte->numOfPacketsPerInterval > 0)
	{
		//update global variable
		p_systemStateSettings->lteOwdSum += lte->sumOwdPerInterval;
		p_systemStateSettings->ltePacketNum += lte->numOfPacketsPerInterval;
		p_systemStateSettings->lteOwdMax = std::max(p_systemStateSettings->lteOwdMax, lte->maxOwdPerInterval);
		p_systemStateSettings->lteOwdMin = std::min(p_systemStateSettings->lteOwdMin, lte->minOwdPerInterval);
    

		//LTE measurement available, update OWD
		int lteOwd = static_cast<int>(lte->sumOwdPerInterval / lte->numOfPacketsPerInterval);
		if (lteOwd != std::numeric_limits<int>::max() && lte->lastIntervalOwd != std::numeric_limits<int>::max())
		{
			lte->lastIntervalOwdDiff = std::abs(1.0 * (lteOwd - lte->lastIntervalOwd) / p_systemStateSettings->lteLinkRtt);
		}
		lte->lastIntervalOwd = lteOwd;

		//update rtt based on the diff of data owd and control owd
		if (INT_MAX != p_systemStateSettings->lteLinkCtrlOwd)
		{
			p_systemStateSettings->lteLinkRtt = p_systemStateSettings->lteLinkCtrlRtt + lteOwd - p_systemStateSettings->lteLinkCtrlOwd;
		}
		//printf("\n ***** MZ LTE RTT update | data RTT: %d ctr RTT: %d data owd: %d ctrl owd: %d *****\n", p_systemStateSettings->lteLinkRtt, p_systemStateSettings->lteLinkCtrlRtt, lteOwd, p_systemStateSettings->lteLinkCtrlOwd);

	}

	//rate estimation based on OWD trend
	//use the max of burst rate in this interval and the average rate in this interval
	long wifiIntervalRate = (p_systemStateSettings->wifiReceiveNrtBytes - wifi->receivedBytesIntervalStart) / (currentTimeMs - measureIntervalStartTime);
	long lteIntervalRate = (p_systemStateSettings->lteReceiveNrtBytes - lte->receivedBytesIntervalStart) / (currentTimeMs - measureIntervalStartTime);
	
	if (0 != wifi->burstRatePerInterval)
	{ //detects a burst
		wifi->rateEstimationPerCycle = std::max(wifi->rateEstimationPerCycle, wifi->burstRatePerInterval);
	}
	
	if (0 != wifi->rateEstimationPerCycle)
	{ // this check make sure the rate estimate is updated only if burst is detected
		wifi->rateEstimationPerCycle = std::max(wifi->rateEstimationPerCycle, wifiIntervalRate);
	}
	//else no enough samples, don't update

	if (0 != lte->burstRatePerInterval)
	{ //detects a burst
		lte->rateEstimationPerCycle = std::max(lte->rateEstimationPerCycle, lte->burstRatePerInterval);
	}

	if (0 != lte->rateEstimationPerCycle)
	{ // this check make sure the rate estimate is updated only if burst is detected
		lte->rateEstimationPerCycle = std::max(lte->rateEstimationPerCycle, lteIntervalRate);
	}

	bool endMeasurement = false;
 	if (p_systemStateSettings->SPLIT_ALGORITHM != 3)
	{
		//GMA1
	    //end measurement cycle condition 1: if both measurement converges.
	    if (measureIntervalIndex >= 2)
	    { //at least measure 2 intervals
			if (p_systemStateSettings->lteSplitFactor == 0)
			{
				if (wifi->lastIntervalOwdDiff < p_systemStateSettings->OWD_CONVERGE_THRESHOLD)
				{
					endMeasurement = true;
				}
			}
			else
			{
				if (std::max(wifi->lastIntervalOwdDiff, lte->lastIntervalOwdDiff) < p_systemStateSettings->OWD_CONVERGE_THRESHOLD)
				{
					endMeasurement = true;
				}
			}
		}

		//end measurement cycle condition 2: if both measurement cannot converge, but the number of intervals meets MAX_MEASURE_INTERVAL
		if (measureIntervalIndex >= p_systemStateSettings->MAX_MEASURE_INTERVAL_NUM)
		{
			endMeasurement = true;
		}
	}
	else
	{
		//GMA2 only needs one interval
		endMeasurement = true;
	}

	//count the number of successive intervals without splitting
	if (p_systemStateSettings->wifiSplitFactor == 0 || p_systemStateSettings->lteSplitFactor == 0)
	{
		if (currentTimeMs - p_systemStateSettings->lastSplittingTime > p_systemStateSettings->resetOWDoffsetTh_s*1000 || currentTimeMs < p_systemStateSettings->lastSplittingTime )//reset Tx OWD-offset after 10 seconds
	   	  p_systemStateSettings->resetOWDoffsetFlag = true;
	}
    else
    {
		  p_systemStateSettings->resetOWDoffsetFlag = false;
		  p_systemStateSettings->lastSplittingTime = currentTimeMs;
	}
	

	if (endMeasurement)
	{

		    //update min Wi-Fi and LTE OWD for non-real-time traffic 
			if (currentTimeMs - lastOwdUpdateTime > p_systemStateSettings->minOwdMeasurementInterval || currentTimeMs < lastOwdUpdateTime || p_systemStateSettings->wifiOwdMinLongTerm == INT_MAX) //reset 10 seconds
			{
				
				//printf("\n measurement end ***** pkt %ld  *** time %ld \n", p_systemStateSettings->wifiPacketNum , currentTimeMs - lastOwdUpdateTime );
				if (p_systemStateSettings->wifiPacketNum > 10 && currentTimeMs - lastOwdUpdateTime > 0 )
				{
					if (p_systemStateSettings->wifiRx_interval == INT_MAX)
						p_systemStateSettings->GMAIPCMessage(2,0,0,false,0); //controlManager.sendWifiProbe(); restart probing 
					p_systemStateSettings->wifiRx_interval = (currentTimeMs - lastOwdUpdateTime ) / p_systemStateSettings->wifiPacketNum ;
				}
				else
				  p_systemStateSettings->wifiRx_interval = INT_MAX;
				

				if (p_systemStateSettings->ltePacketNum > 10 && currentTimeMs - lastOwdUpdateTime > 0 )
				{
				  if (p_systemStateSettings->lteRx_interval == INT_MAX)
						p_systemStateSettings->GMAIPCMessage(3,0,0,false,0); //controlManager.sendWifiProbe(); restart probing 
				  p_systemStateSettings->lteRx_interval = (currentTimeMs - lastOwdUpdateTime ) / p_systemStateSettings->ltePacketNum ;
				}
				else
				  p_systemStateSettings->lteRx_interval = INT_MAX;

				lastOwdUpdateTime = currentTimeMs;
				int max_minOwdPerCycle = std::max(p_systemStateSettings->wifiOwdMin, p_systemStateSettings->lteOwdMin);
				if (max_minOwdPerCycle < 10000) //owd < 10 seconds 
				{
					p_systemStateSettings->wifiOwdTxOffset = std::min(250, max_minOwdPerCycle - p_systemStateSettings->wifiOwdMin); //max = 250ms (1 Byte)
					p_systemStateSettings->lteOwdTxOffset = std::min(250,  max_minOwdPerCycle - p_systemStateSettings->lteOwdMin); //max = 250ms (1 Byte)
					p_systemStateSettings->wifiOwdOffset = p_systemStateSettings->wifiOwdMin - p_systemStateSettings->lteOwdMin;
					
					p_systemStateSettings->wifiOwdMinLongTerm = p_systemStateSettings->wifiOwdMin;
					p_systemStateSettings->lteOwdMinLongTerm = p_systemStateSettings->lteOwdMin;

					int owd_diff_lte_to_wifi = p_systemStateSettings->lteOwdMax - p_systemStateSettings->wifiOwdMin;
					int owd_diff_wifi_to_lte = p_systemStateSettings->wifiOwdMax - p_systemStateSettings->lteOwdMin;
					if (owd_diff_lte_to_wifi > owd_diff_wifi_to_lte)
						p_systemStateSettings->maxReorderingDelay = owd_diff_lte_to_wifi + 20;
					else
						p_systemStateSettings->maxReorderingDelay = owd_diff_wifi_to_lte + 20;


					if (p_systemStateSettings->maxReorderingDelay < p_systemStateSettings->MIN_MAXREORDERINGDELAY)
						p_systemStateSettings->maxReorderingDelay = p_systemStateSettings->MIN_MAXREORDERINGDELAY;
					else if (p_systemStateSettings->maxReorderingDelay > p_systemStateSettings->MAX_MAXREORDERINGDELAY)
						p_systemStateSettings->maxReorderingDelay = p_systemStateSettings->MAX_MAXREORDERINGDELAY;

					p_systemStateSettings->GMAIPCMessage(16, p_systemStateSettings->HRreorderingTimeout, p_systemStateSettings->maxReorderingDelay, false, 0); //update reordering timer
				
				}
				else
				{
					p_systemStateSettings->wifiOwdTxOffset = 0; 
					p_systemStateSettings->lteOwdTxOffset = 0;
					p_systemStateSettings->wifiOwdOffset = 0; 
					p_systemStateSettings->wifiOwdMinLongTerm = INT_MAX;
					p_systemStateSettings->lteOwdMinLongTerm = INT_MAX;

				}

				p_systemStateSettings->wifiOwdMax = INT_MIN;
				p_systemStateSettings->wifiOwdMin = INT_MAX;
				p_systemStateSettings->lteOwdMax = INT_MIN;
				p_systemStateSettings->lteOwdMin = INT_MAX;
				p_systemStateSettings->wifiOwdSum = 0;
				p_systemStateSettings->wifiPacketNum_last_interval = p_systemStateSettings->wifiPacketNum;
				  
				p_systemStateSettings->wifiPacketNum = 0;
				p_systemStateSettings->lteOwdSum = 0;
				p_systemStateSettings->ltePacketNum = 0;
			}

		measureCycleOn = false; // this will end a measurement cycle
		if (INT_MAX == wifi->lastIntervalOwd)
		{ //no owd measurement last interval, we set it to the last packet owd
			wifi->lastIntervalOwd = wifi->lastPacketOwd;
			wifi->minOwdPerInterval = wifi->lastPacketOwd;
			wifi->maxOwdPerInterval = wifi->lastPacketOwd;
		}
		if (INT_MAX == lte->lastIntervalOwd)
		{ //no owd measurement last interval, we set it to the last packet owd
			lte->lastIntervalOwd = lte->lastPacketOwd;
			lte->minOwdPerInterval = lte->lastPacketOwd;
			lte->maxOwdPerInterval = lte->lastPacketOwd;
		}

		//update global variable
		p_systemStateSettings->wifiInorderPacketNum += wifi->numOfInOrderPacketsPerCycle;
		p_systemStateSettings->wifiMissingPacketNum += wifi->numOfMissingPacketsPerCycle;
		p_systemStateSettings->wifiAbnormalPacketNum += wifi->numOfAbnormalPacketsPerCycle;

		p_systemStateSettings->lteInorderPacketNum += lte->numOfInOrderPacketsPerCycle;
		p_systemStateSettings->lteMissingPacketNum += lte->numOfMissingPacketsPerCycle;
		p_systemStateSettings->lteAbnormalPacketNum += lte->numOfAbnormalPacketsPerCycle;

		if (0 == wifi->rateEstimationPerCycle)
		{ //no congestion detected
			if (wifi->rateEstimationLastCycle >= p_systemStateSettings->MAX_RATE_ESTIMATE)
			{
				wifi->rateEstimationPerCycle = p_systemStateSettings->MAX_RATE_ESTIMATE; // set to 1GBps
			}
			else
			{
				wifi->rateEstimationPerCycle = wifi->rateEstimationLastCycle * p_systemStateSettings->RATE_ESTIMATE_K / 100;
			}
		}
		else
		{
			p_systemStateSettings->wifiRate = wifi->rateEstimationPerCycle;
		}

		if (0 == lte->rateEstimationPerCycle)
		{
			if (lte->rateEstimationLastCycle >= p_systemStateSettings->MAX_RATE_ESTIMATE)
			{
				lte->rateEstimationPerCycle = p_systemStateSettings->MAX_RATE_ESTIMATE; // set to 1GBps
			}
			else
			{
				lte->rateEstimationPerCycle = lte->rateEstimationLastCycle * p_systemStateSettings->RATE_ESTIMATE_K / 100;
			}
		}
		else
		{
			p_systemStateSettings->lteRate = lte->rateEstimationPerCycle;
		}

		wifi->rateEstimationLastCycle = wifi->rateEstimationPerCycle;
		lte->rateEstimationLastCycle = lte->rateEstimationPerCycle;

		int wifiPackets = std::max(wifi->packetsBeforeLastLoss, wifi->packetsAfterLastLoss);
		int ltePackets = std::max(lte->packetsBeforeLastLoss, lte->packetsAfterLastLoss);
		
		if(p_systemStateSettings->gDynamicSplitFlag == 1 && !p_systemStateSettings->gDLAllOverLte && p_systemStateSettings->gIsWifiConnect && p_systemStateSettings->gIsLteConnect && p_systemStateSettings->gScreenOnFlag && std::abs(p_systemStateSettings->wifiOwdOffset) < p_systemStateSettings->wifiOwdOffsetMax)
		{
			if (3 == p_systemStateSettings->SPLIT_ALGORITHM)
			{
				//GMA 2.0
				int measureDurationMs = measureIntervalEndTime-measureIntervalStartTime;
				NS_ASSERT_MSG(measureDurationMs > 0, "The duration for a measurement cannot be 0 ms!");

				if (false == trafficSplitting->DelayViolationBasedAlgorithm(wifi->numOfDataDelayViolationPerInterval, wifi->numOfDataPacketsPerInterval, lte->numOfDataDelayViolationPerInterval, lte->numOfDataPacketsPerInterval, measureDurationMs, measureIntervalThresh))
				{
					//printf("\n ***** measuremnt end wifi owd  %d  offset: %d lte owd:  %d *****\n", wifi->lastIntervalOwd, p_systemStateSettings->wifiOwdOffset, lte->lastIntervalOwd );
					measureCycleStart(lastSn);
				}
			}
			else
			{
				//GMA 1.0
				if (false == trafficSplitting->congestionBasedAlgorithm(wifiPackets, ltePackets, static_cast<double>(wifiIntervalRate) / wifi->rateEstimationPerCycle, 0, wifi->lastIntervalOwd - p_systemStateSettings->wifiOwdOffset, lte->lastIntervalOwd))
				{
					//printf("\n ***** measuremnt end wifi owd  %d  offset: %d lte owd:  %d *****\n", wifi->lastIntervalOwd, p_systemStateSettings->wifiOwdOffset, lte->lastIntervalOwd );
					measureCycleStart(lastSn);
				}
			}
		}
		else
		{
			measureCycleStart(lastSn);
		}
		
	}
	else
	{
		//start a new measure interval
		measureIntervalStart(currentTimeMs);
	}
};