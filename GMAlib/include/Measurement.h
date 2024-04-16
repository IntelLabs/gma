//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : Measurement.h


#ifndef _MEASUREMENT_H
#define _MEASUREMENT_H

#include <cmath>
#include <limits>
#include <climits>
#include "SystemStateSettings.h"
#include <vector>
#include <map>

class MeasureDevice {
private:
    //burst rate estimation
    int minOwdPerBurst = 0;
    int maxOwdPerBurst = INT_MAX;
    int packetCountPerBurst = 0;
    int burstStartTime = 0;
    int burstStopTime = 0;
    long burstStartBytes = 0;
    long burstStopBytes = 0;

public:
	short lastLsn = 0;

    int numOfInOrderPacketsPerCycle = 0;
    int numOfMissingPacketsPerCycle = 0;
    int numOfAbnormalPacketsPerCycle = 0;

    int numOfMissingPacketsPerInterval = 0;
    int numOfAbnormalPacketsPerInterval = 0;

    int packetsBeforeLastLoss = 0;
	int packetsAfterLastLoss = 0;

    int lastPacketOwd = INT_MAX; // unit ms
    long sumOwdPerInterval = 0; // sum of (OWD per packet), unit ms
    int minOwdPerInterval = INT_MAX;
	int lowerOwdNumPerInterval = 0; 
    int maxOwdPerInterval = INT_MIN;
	
    int numOfPacketsPerInterval = 0; // number of packets including data and control
    int numOfDataPacketsPerInterval = 0;

	int numOfDataDelayViolationPerInterval = 0;
    long receivedBytesIntervalStart = 0;// received bytes at the start of interval

    int lastIntervalOwd = INT_MAX; // average OWD (ms) from last measure interval, initial to infinity
    double lastIntervalOwdDiff = 1.0; // Diff(k) in the last measure interval
    char cid = 0;
	
    long burstRatePerInterval = 0; // kBps
    long rateEstimationPerCycle = 0;// kBps
    long rateEstimationLastCycle;// kBps

	SystemStateSettings *p_systemStateSettings = NULL;

	MeasureDevice(char cid);
	void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
	void resetBurstRateEstimate();
	void AddDataToBurstRateEstimate(int owdMs);
	void updateLastPacketOwd(int owdMs, bool dataFlag = false);
	void updateLsn(short lastLsn);
};

class LinkState {
public:
	LinkState();
	void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
	uint8_t GetDefaultLinkCid();
	bool IsLinkUp(uint8_t cid);
	void NoDataDown(uint8_t cid);
private:
	SystemStateSettings *p_systemStateSettings = NULL;
};

class TrafficSplitting {
private:
	int lastDecisionWifiOwd = 0;
	int lastDecisionlteOwd = 0;
	LinkState *m_linkState  = NULL;
	uint32_t m_queueingDelayTargetMs; //will be overwrited later.
	double CONGESTION_SCALER_MAX = 0.5;
	double CONGESTION_SCALER_MIN = 0.1;
	double m_congestionScaler = 0.5; //the scaler a. we use it when the bandwidth estimation is not available..

	bool m_adaptiveCongestionScaler = true; //if enabled, the congestion scaler will be computed dynamically and within the range of [CONGESTION_SCALER_MIN, m_congestionScaler].
	double m_relocateScaler = 0.01; //when there is no congestion, we move some packets from low traffic link to high traffic link. Every time we can move up to m_relocateScaler*total_packets.
	bool m_enableBwEstimate = true;
	uint32_t m_bwHistSize = 10; //track the n(i) for the past 10 intervals.
	std::map< uint8_t, std::vector<double> > m_cidToBwHistMap; // the key is the cid of the link and the value is the history of past bandwidth (packets/s) n(i)/interval_duration measurement.
	std::map< uint8_t, std::vector<uint32_t> > m_cidToKiHistMap; // the key is the cid of the link and the value is the history of past k(i), make sure it is the same size as m_cidToBwHistMap.

	bool m_flowActive = false; //true if a flow is actively sending data
	double m_updateThreshold = 0.03; //if the traffic splitting ratio update is smaller than this threshold, we do not send tsu.
	//bool m_adaptiveSplittingBurst = true; //compute splitting burst based on the received packet sum(n(i)) to speed up convergence time.
	double m_roundingScaler = -0.3; //set to a negative value will reduce the splitting ratio s(i) more aggressively. For example, with m_roundingScaler = -0.3, the int value of s(i) = 2.7 will be round to round(2.7-0.3) = 2.
  	std::vector<double> m_lastRatio;

	struct RxMeasurement
	{
		uint8_t m_links; // total number of active links
		double m_measureIntervalThreshS; //threshS is the minimal time threshold of a measurement, i.e., T1 threshold.
		double m_measureIntervalDurationS; //durationS is the actual time spend during a measurement interval (requires both T1 and T2 are met). If not enough packet is received during T1, durationMs will be greater than threshMs.
		std::vector<uint8_t> m_cidList; //connection ID
		std::vector<uint32_t> m_delayViolationPktNumList; //packet number that violates queueing delay target.
		std::vector<uint32_t> m_totalPktNumList; //the total pkt number in this interval.
		uint32_t m_splittingBurstRequirementEst; //the reference value for splitting burst requirement.
	};
	int GetMinSplittingBurst(); //min is 8
	int GetMaxSplittingBurst(); //max is 128
	int GetMeasurementBurstRequirement(); // T3 threshold to detect link failure.
public:
	MeasureDevice *wifi = NULL;
	MeasureDevice *lte = NULL;
	SystemStateSettings *p_systemStateSettings = NULL;

	TrafficSplitting();
	~TrafficSplitting();
	void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
	bool delayBasedAlgorithm(int wifiOwd, int lteOwd);
	bool delayLossBasedAlgorithm(int wifiOwd, int lteOwd, int wifiPackets, int ltePackets);
	bool congestionBasedAlgorithm(int wifiPackets, int ltePackets, double wifiUti, double lteUti, int wifiOwd, int lteOwd);
	bool DelayViolationBasedAlgorithm(int wifiViolation, int wifiTotalPkt, int lteViolation, int lteTotalPkt, int durationMs, int threshMs); //GMA2.0
};

class MeasurementManager {
private:
    MeasurementManager(const MeasurementManager& src){ /* do not create copies */ }
	MeasurementManager& operator=(const MeasurementManager&){ return *this;}

	int measureStartSn = 0;
	int lastSn = 0;
	bool measureCycleOn = false; //if true, measurement cycle started.
	bool measureIntervalOn = false; // true stands for a measurement interval is started
	int measureIntervalIndex = 0; // current measure interval index
	long measureIntervalStartTime = 0;
	long measureIntervalEndTime = 0;
	long lastOwdUpdateTime = 0;
	long measureIntervalThresh;
	bool m_alwaysUseGmaTwoAlgorithm = false;
public:
	MeasurementManager();
	~MeasurementManager();
	void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
	void updateSystemSettings();

	MeasureDevice *wifi = NULL;
	MeasureDevice *lte = NULL;
	TrafficSplitting *trafficSplitting = NULL;
	SystemStateSettings *p_systemStateSettings = NULL;

	bool measureCycleStarted();
	bool measureIntervalStarted();

	void measureCycleStart(int measureStartSn);
	bool measureIntervalStartConditionCheck(int lastSn, int nextSn);
	void measureIntervalStart(long currentTimeMs);
	bool restart(long currentTimeMs);
	void measureIntervalEndCheck(long currentTimeMs);
	void measureIntervalEndAbnormal(long currenTimeMs);
	void measureIntervalEnd (long currentTimeMs);
};


#endif

