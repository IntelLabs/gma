
# Measurement Format

An example that using this API is provided in [GMAClient](https://github.com/pinyaras/GMAClient).
- The `gmasim_client.recv()` function returns measurements received from the GMAsim environment, as shown in the following example.
```python
ok_flag, df_list = gmasim_client.recv() #okey_flag==true means this measurement is valid.
df_phy_lte_max_rate = df_list[0] #The lte link capacity measured by each user
df_phy_wifi_max_rate = df_list[1] #The Wi-Fi link capacity measured by each user
df_load = df_list[2] #The load (input traffic throughput) measured by each user
df_rate = df_list[3] #The delivery rate (output traffic throughput) measured by each user, including traffic over LTE link, Wi-Fi link, and ALL (combining both)
df_qos_rate = df_list[4] #The QoS delivery rate (output traffic throughput that meet the QoS requirement) measured by each user, including traffic over LTE link, Wi-Fi link, and ALL (combining both)
df_owd = df_list[5] #The one-way delay measured by each user, including LTE link, Wi-Fi link, and ALL (after reordering out of order packets from both links)
df_split_ratio = df_list[6] #The traffic split ratio (in range of [0, 32]) measured by each user, including LTE link, Wi-Fi link. The LTE split ratio + Wi-Fi split ratio equals 32.
df_ap_id = df_list[7] #The Wi-Fi access point ID and LTE cell ID measured by each user, including LTE link, Wi-Fi link
```

- As an example, the data structure for `df_phy_lte_max_rate` is given below, where start_ts and end_ts stands for the measurement start and end time; cid stands for connection ID (LTE, Wi-Fi or All); direction is either downlink (DL) or uplink (UL); group is either GMA or physical (PHY) layer measurement.
```python
start_ts  end_ts  cid direction group      name  user  value  unit
0    1900.0  2000.0  LTE        DL   PHY  max_rate     0   75.0  mbps
1    1900.0  2000.0  LTE        DL   PHY  max_rate     1   75.0  mbps
2    1900.0  2000.0  LTE        DL   PHY  max_rate     2   75.0  mbps
3    1900.0  2000.0  LTE        DL   PHY  max_rate     3   75.0  mbps
```
