#pragma once

#include <iostream>
#include <string>
#include <list>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define FALSE 0
#define TRUE 1
#define VOID void

typedef char                CHAR;
typedef unsigned char       BYTE;
typedef bool                BOOL;
typedef unsigned short      WORD;
typedef unsigned int        DWORD;
typedef unsigned long long  QWORD;
typedef unsigned long       ULONG_PTR;

typedef struct _TaggedParameter
{
    BYTE TagNumber;
    BYTE TagLength;
} TaggedParameter;

typedef struct _SSID
{
    TaggedParameter Tag;
    char SSID[1];
} SSID;

typedef struct _Channel
{
    TaggedParameter Tag;
    BYTE Channel;
} Channel;

#pragma pack(push, 1)
typedef struct _Radiotap
{
    BYTE HeaderRevision;
    BYTE HeaderPad;
    WORD HeaderLength;
    QWORD PresentFlags;
    BYTE Flags;
    BYTE DataRate;
    WORD ChannelFrequency;
    WORD ChannelFlags;
    BYTE AntennaSignal1;
    BYTE Reserved;
    WORD RXFlags;
    BYTE AntennaSignal2;
    BYTE Antenna;
} Radiotap;
#pragma pack(pop)

typedef struct _BeaconFrame
{
    union
    {
        struct
        {
            WORD Version : 2;
            WORD Type    : 2;
            WORD Subtype : 4;
        };
        WORD FrameControlField;
    };
    WORD Duration;
    union
    {
        BYTE ReceiverMac[6];
        BYTE DestinationMac[6];
    };
    union
    {
        BYTE TransmitterMac[6];
        BYTE SourceMac[6];
    };
    BYTE BSSID[6];
    WORD FragmentNumber : 4;
    WORD SequenceNumber : 12;

    BOOL IsBeacon();
} BeaconFrame;

#pragma pack(push, 4)
typedef struct _WirelessManagement
{
    struct
    {
        QWORD Timestamp;
        WORD BeaconInterval;
        WORD CapabilitiesInformation;
    } Fixed;
    BYTE TaggedData[1];

    SSID *GetSSID();
    Channel *GetChannel();
} WirelessManagement;
#pragma pack(pop)

typedef struct _IEEE_80211
{
    Radiotap Radio;
    BeaconFrame Beacon;
    WirelessManagement Management;
} IEEE_80211;

typedef struct _AP
{
    BYTE BSSID[6];
    CHAR *ESSID;
    DWORD Beacons;
    CHAR PWR;
    BYTE Channel;
} AP;

class airodump
{
private:
    pthread_t ThreadId;
    pthread_t HoppingThreadId;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    pcap_t *pcap;

public:
    std::list<AP*> AP_List;
    DWORD channel;

    airodump(char* dev);
    VOID start();
    VOID stop();
    pcap_t *getpcap();
    char *getdev();
};

VOID Capture(airodump *lpairodump);