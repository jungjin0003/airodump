#include "airodump.hpp"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void SetCursorPos(int XPos, int YPos)
{
    printf("\033[%d;%dH", YPos+1, XPos+1);
}

void PrintDump(airodump *lpairodump)
{
    struct winsize w;
    ioctl(0, TIOCGWINSZ, &w);
    static unsigned short line;

    pthread_mutex_lock(&mutex);
    if (line != w.ws_row - 4)
    {
        line = w.ws_row - 4;
        system("clear");
        SetCursorPos(0, 3);
        printf(" %-17s   %3s  %7s  %2s  %s\n", "BSSID", "PWR", "Beacons", "CH", "ESSID");
    }

    SetCursorPos(0, 1);
    printf(" CH : %02d", lpairodump->channel);

    SetCursorPos(0, 4);
    for (AP *ap : lpairodump->AP_List)
    {
        if (line == 0)
            break;
        std::cout << ' ';
        for (int i = 0; i < 6; i++)
        {
            printf("%02x", ap->BSSID[i]);
            if (i != 5)
                std::cout << ':';
        }
        printf("   %3d  %7d  %2d  %s\n", ap->PWR, ap->Beacons, ap->Channel, ap->ESSID);
        line--;
    }
    pthread_mutex_unlock(&mutex);
}

void ChannelHopping(airodump *lpairodump)
{
    char command[64];
    char *dev = lpairodump->getdev();
    srand(time(NULL));
    while (true)
    {
        lpairodump->channel = (rand() % 14) + 1;
        sprintf(command, "iwconfig %s channel %d", dev, lpairodump->channel);
        system(command);
        usleep(100000);
    }
}

BOOL BeaconFrame::IsBeacon()
{
    if (Subtype == 8 && Type == 0)
        return true;
    return false;
}

SSID *WirelessManagement::GetSSID()
{
    TaggedParameter *Tag = (TaggedParameter *)TaggedData;
    while (Tag->TagNumber != 0x00)
    {
        Tag = (TaggedParameter *)((ULONG_PTR)Tag + 2 + Tag->TagLength);
    }
    
    return (SSID *)Tag;
}

Channel *WirelessManagement::GetChannel()
{
    TaggedParameter *Tag = (TaggedParameter *)TaggedData;
    while (Tag->TagNumber != 0x03)
    {
        Tag = (TaggedParameter *)((ULONG_PTR)Tag + 2 + Tag->TagLength);
    }
    
    return (Channel *)Tag;
}

airodump::airodump(char* dev)
{
    this->dev = dev;
    this->pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, this->errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return;
    }
}

VOID airodump::start()
{
    // Capture(this);
    int res = pthread_create(&this->ThreadId, NULL, (void*(*)(void*))Capture, this);
    if (res != 0)
    {
        std::cout << "pthread_create failed\n" << std::endl;
        exit(-1);
    }
    res = pthread_create(&this->HoppingThreadId, NULL, (void*(*)(void*))ChannelHopping, this);
    if (res != 0)
    {
        std::cout << "pthread_create failed\n" << std::endl;
        exit(-1);
    }
    pthread_detach(this->HoppingThreadId);
    pthread_detach(this->ThreadId);
}

VOID airodump::stop()
{
    pthread_cancel(this->ThreadId);
}

pcap_t *airodump::getpcap()
{
    return this->pcap;
}

char *airodump::getdev()
{
    return this->dev;
}

VOID Capture(airodump *lpairodump)
{
    std::cout << std::endl << std::endl << std::endl;
    printf(" %-17s   %3s  %7s  %2s  %s\n", "BSSID", "PWR", "Beacons", "CH", "ESSID");
    pcap_t *pcap = lpairodump->getpcap();
    while (true)
    {
        struct pcap_pkthdr *header;
        const unsigned char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        IEEE_80211 *IEEE_80211 = (struct _IEEE_80211 *)packet;

        if (IEEE_80211->Beacon.IsBeacon() == false)
            continue;

        bool bNewAP = true;
        SSID* ssid = IEEE_80211->Management.GetSSID();
        Channel *channel = IEEE_80211->Management.GetChannel();

        pthread_mutex_lock(&mutex);
        for (AP *ap : lpairodump->AP_List)
        {
            if (memcmp(ap->BSSID, IEEE_80211->Beacon.SourceMac, 6) == 0)
            {
                ap->Beacons++;
                ap->PWR = IEEE_80211->Radio.AntennaSignal1;
                bNewAP = false;
                break;
            }
        }
        pthread_mutex_unlock(&mutex);

        if (bNewAP)
        {
            AP *NewAP = (AP *)malloc(sizeof(AP));
            NewAP->Beacons = 1;
            NewAP->PWR = IEEE_80211->Radio.AntennaSignal1;
            memcpy(NewAP->BSSID, IEEE_80211->Beacon.SourceMac, 6);
            NewAP->ESSID = (CHAR *)malloc(ssid->Tag.TagLength + 1);
            memcpy(NewAP->ESSID, ssid->SSID, ssid->Tag.TagLength);
            NewAP->ESSID[ssid->Tag.TagLength] = 0x00;
            NewAP->Channel = channel->Channel;
            pthread_mutex_lock(&mutex);
            lpairodump->AP_List.push_back(NewAP);
            pthread_mutex_unlock(&mutex);
        }

        PrintDump(lpairodump);
    }
}