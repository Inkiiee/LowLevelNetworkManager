#ifndef SENDER_H
#define SENDER_H

#include <QObject>
#include <pcap/pcap.h>
#include "receiver.h"

class Sender: public QObject
{
    Q_OBJECT
private:
    pcap_t * net;
    Receiver * recv = nullptr;

public:
    Sender(pcap_t* n, Receiver* r, QObject* parent=nullptr): net(n), QObject(parent){
        recv = r;
    }
    bool send_arp_request(const QString& sender_ip, const QString& receiever_ip, const QString& sender_mac = "");
    bool send_ping(const QString& target_ip, int size);
    bool set_mac_addr(quint8* addr, const QString& mac){
        auto token = mac.split(":");
        if(token.size() != 6) return false;

        for(int i=0; i<6; i++){
            addr[i] = (quint8)token[i].toInt(nullptr, 16);
        }
        return true;
    }
    bool set_ip_addr(quint8* addr, const QString& ip){
        auto token = ip.split(".");
        if(token.size() != 4) return false;

        for(int i=0; i<4; i++){
            addr[i] = (quint8)token[i].toInt();
        }
        return true;
    }
    void send_packet(quint8* packet, int len){
        pcap_sendpacket(net, packet, len);

    }
signals:
    void error(const QString& msg);
};

#endif // SENDER_H
