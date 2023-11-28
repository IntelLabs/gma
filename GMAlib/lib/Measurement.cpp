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
		if (0 == cid)
		{
			burstStopBytes = p_systemStateSettings->wifiReceiveNrtBytes;
		}
		else if (3 == cid)
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
		if (0 == cid)
		{
			burstStartBytes = p_systemStateSettings->wifiReceiveNrtBytes;
		}
		else if (3 == cid)
		{
			burstStartBytes = p_systemStateSettings->lteReceiveNrtBytes;
		}
	}
}

void MeasureDevice::updateLastPacketOwd(int owdMs)
{
	if (owdMs < 10000)
	{ //only update OWD smaller than 10 s
		if (0 == numOfPacketsPerInterval % p_systemStateSettings->BURST_SAMPLE_FREQUENCY)
		{
			AddDataToBurstRateEstimate(owdMs);
		}
		lastPacketOwd = owdMs;
		numOfPacketsPerInterval++;
		sumOwdPerInterval += lastPacketOwd;

		if (minOwdPerInterval > owdMs)
		{
			minOwdPerInterval = owdMs;
		}
		if (maxOwdPerInterval < owdMs)
		{
			maxOwdPerInterval = owdMs;
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
	numOfDataPacketsPerInterval++;
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

TrafficSplitting::TrafficSplitting()
{
}

void TrafficSplitting::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
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
		if (wifiOwd >= lastDecisionWifiOwd && lastWifiIndex > 0)
		{
			lastWifiIndex += std::min(-1, p_systemStateSettings->wifiIndexChangeAlpha + p_systemStateSettings->STEP_ALPHA_THRESHOLD);
			p_systemStateSettings->wifiIndexChangeAlpha -= 1;
			lastWifiIndex = std::max(0, lastWifiIndex);
			update = true;
		}
	}
	else if (p_systemStateSettings->TOLERANCE_DELAY_BOUND < lteOwd - wifiOwd)
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
	else if (p_systemStateSettings->TOLERANCE_DELAY_BOUND < lteOwd - wifiOwd)
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
			if (p_systemStateSettings->currentSysTimeMs - p_systemStateSettings->lastReceiveLteProbe > 30000)
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
				case 3:
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
		case 3:
			update = delayLossBasedAlgorithm(wifiOwd, lteOwd, wifiPackets, ltePackets);
			break;
		default:
			update = delayBasedAlgorithm(wifiOwd, lteOwd);
			break;
		}
	}
	return update;
}

MeasurementManager::MeasurementManager()
{
	measureIntervalDuration = 10;
}

void MeasurementManager::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}

void MeasurementManager::updateSystemSettings()
{

	//Suppose restart new measurementManager, updates
	measureStartSn = 0;
	lastSn = 0;
	measureIntervalStarted = false; // true stands for a measurement interval is tarted
	measureIntervalIndex = 0;		// current measure interval index
	measureIntervalStartTime = 0;

	measureIntervalDuration = p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION;
	if (trafficSplitting)
		delete trafficSplitting;
	trafficSplitting = new TrafficSplitting();
	trafficSplitting->initUnitSystemStateSettings(p_systemStateSettings);
	if (wifi)
		delete wifi;
	wifi = new MeasureDevice(0);
	wifi->initUnitSystemStateSettings(p_systemStateSettings);
	if (lte)
		delete lte;
	lte = new MeasureDevice(3);
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

void MeasurementManager::measureCycleStart(int x)
{
	measureIntervalIndex = 0;
	measureStartSn = x;
	measurementOn = true;
	measureIntervalStarted = false; //the first measure interval will start after lastSn > startSn

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

bool MeasurementManager::measureIntervalStartConditionCheck(int x)
{
	// return true if measurement cycle is on, last received sn > start sn, and measurement interval is not started yet.
	
	lastSn = x;
	return (rollOverDiff2(lastSn, measureStartSn, 16777216) >= 0 && !measureIntervalStarted);
}

void MeasurementManager::measureIntervalStart(long currentTimeMs)
{
	measureIntervalStarted = true;
	measureIntervalStartTime = currentTimeMs;

	//initialize measurement parameters
	wifi->sumOwdPerInterval = 0;
	wifi->numOfPacketsPerInterval = 0;
	wifi->numOfDataPacketsPerInterval = 0;
	wifi->minOwdPerInterval = INT_MAX;
	wifi->maxOwdPerInterval = INT_MIN;

	lte->sumOwdPerInterval = 0;
	lte->numOfPacketsPerInterval = 0;
	lte->numOfDataPacketsPerInterval = 0;
	lte->minOwdPerInterval = INT_MAX;
	lte->maxOwdPerInterval = INT_MIN;

	measureIntervalIndex++;

	wifi->receivedBytesIntervalStart = p_systemStateSettings->wifiReceiveNrtBytes;
	lte->receivedBytesIntervalStart = p_systemStateSettings->lteReceiveNrtBytes;

	wifi->resetBurstRateEstimate();
	lte->resetBurstRateEstimate();

	//this interval will last max (RTT)
	measureIntervalDuration = std::max(p_systemStateSettings->lteLinkRtt, p_systemStateSettings->wifiLinkRtt);
	measureIntervalDuration = std::max(p_systemStateSettings->MIN_MEASURE_INTERVAL_DURATION, std::min(measureIntervalDuration, p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION));

	wifi->numOfMissingPacketsPerInterval = 0;
	wifi->numOfAbnormalPacketsPerInterval = 0;

	lte->numOfMissingPacketsPerInterval = 0;
	lte->numOfAbnormalPacketsPerInterval = 0;

}

void MeasurementManager::measureIntervalEndCheck(long currentTimeMs)
{
	if (currentTimeMs > measureIntervalStartTime + p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION || currentTimeMs < measureIntervalStartTime)
	{ //reach maximum interval time (1s)
		if (p_systemStateSettings->MIN_PACKET_NUM_PER_INTERVAL > lte->numOfDataPacketsPerInterval + wifi->numOfDataPacketsPerInterval)
		{ //not enough sample, move all traffic to WiFi
			//not enough sample for splitting algorithm
			measureIntervalEndAbnormal(currentTimeMs);
			if (p_systemStateSettings->gDynamicSplitFlag == 1 && p_systemStateSettings->SPLIT_ALGORITHM != 3)
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
		{ // reach time limit and have enough samples, end interval and do measurement.
			measureIntervalEnd(currentTimeMs);
		}
	}
	else if (currentTimeMs >= measureIntervalStartTime + measureIntervalDuration && p_systemStateSettings->MIN_PACKET_NUM_PER_INTERVAL < lte->numOfDataPacketsPerInterval + wifi->numOfDataPacketsPerInterval)
	{
		// end this measure interval, if (1) interval lasts  more than max(rtt) & (2) received packets > 10
		measureIntervalEnd(currentTimeMs);
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
}

void MeasurementManager::measureIntervalEnd(long currentTimeMs)
{
	measureIntervalStarted = false;

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

	if (endMeasurement)
	{
		measurementOn = false; // this will end a measurement cycle
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
			if (false == trafficSplitting->congestionBasedAlgorithm(wifiPackets, ltePackets, static_cast<double>(wifiIntervalRate) / wifi->rateEstimationPerCycle, 0, wifi->lastIntervalOwd - p_systemStateSettings->wifiOwdOffset, lte->lastIntervalOwd))
			{
				measureCycleStart(lastSn);
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