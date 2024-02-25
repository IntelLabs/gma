//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : Measurement.h


#ifndef _MEASUREMENT_H
#define _MEASUREMENT_H

#include <cmath>
#include <limits>
#include <climits>
#include "SystemStateSettings.h"

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
    int maxOwdPerInterval = INT_MIN;
	
    int numOfPacketsPerInterval = 0; // number of packets including data and control
    int numOfDataPacketsPerInterval = 0;

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
	void updateLastPacketOwd(int owdMs);
	void updateLsn(short lastLsn);
};

class TrafficSplitting {
private:
	int lastDecisionWifiOwd = 0;
	int lastDecisionlteOwd = 0;

public:
	MeasureDevice *wifi = NULL;
	MeasureDevice *lte = NULL;
	SystemStateSettings *p_systemStateSettings = NULL;

	TrafficSplitting();
	void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
	bool delayBasedAlgorithm(int wifiOwd, int lteOwd);
	bool delayLossBasedAlgorithm(int wifiOwd, int lteOwd, int wifiPackets, int ltePackets);
	bool congestionBasedAlgorithm(int wifiPackets, int ltePackets, double wifiUti, double lteUti, int wifiOwd, int lteOwd);
};

class MeasurementManager {
private:
    MeasurementManager(const MeasurementManager& src){ /* do not create copies */ }
	MeasurementManager& operator=(const MeasurementManager&){ return *this;}

	int measureStartSn = 0;
	int lastSn = 0;
	bool measureIntervalStarted = false; // true stands for a measurement interval is tarted
	int measureIntervalIndex = 0; // current measure interval index
	long measureIntervalStartTime = 0;
	long measureIntervalEndTime = 0;
	long lastOwdUpdateTime = 0;
	long measureIntervalDuration;
public:
	MeasurementManager();
	~MeasurementManager();
	void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
	void updateSystemSettings();

	bool measurementOn = false;
	MeasureDevice *wifi = NULL;
	MeasureDevice *lte = NULL;
	TrafficSplitting *trafficSplitting = NULL;
	SystemStateSettings *p_systemStateSettings = NULL;

	void measureCycleStart(int measureStartSn);
	bool measureIntervalStartConditionCheck(int lastSn);
	void measureIntervalStart(long currentTimeMs);
	bool restart(long currentTimeMs);
	void measureIntervalEndCheck(long currentTimeMs);
	void measureIntervalEndAbnormal(long currenTimeMs);
	void measureIntervalEnd (long currentTimeMs);
};


#endif

