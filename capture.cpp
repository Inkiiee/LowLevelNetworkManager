#include "capture.h"
#include "network_headers.h"

#include <QDateTime>
#include <QString>

QString Capture::get_detail(qint64 index){
    QString detail;
    Ethernet* ethe = (Ethernet*)(packet_vec[index].data());
    detail += ethe->get_info();

    if(ethe->get_type() == "ARP"){
        Arp* arp = (Arp*)(ethe->get_body());
        detail += arp->get_info();
    }
    else if(ethe->get_type() == "IPv4"){
        Ip4Pkt* ip = (Ip4Pkt*)(ethe->get_body());
        detail += ip->get_info();

        if(ip->get_protocol() == "ICMP"){
            Icmp* icmp = (Icmp*)(ip->get_body());
            detail += icmp->get_info();
        }
        else if(ip->get_protocol() == "UDP"){
            Udp* udp = (Udp*)(ip->get_body());
            detail += udp->get_info();

            quint8 src_ip[4];
            quint8 dst_ip[4];
            quint16 length = udp->get_length();
            recv->str_to_ip_addr(src_ip, ip->get_source());
            recv->str_to_ip_addr(dst_ip, ip->get_destination());
            auto cs = udp->cal_checksum(src_ip, dst_ip, length);
            detail += ("\tcal checksum: " + QString::number(cs) + "\n");

            if(udp->get_destination() == 53 || udp->get_source() == 53){
                Dns* dns = (Dns*)(udp->get_body());
                detail += dns->get_info();
            }
        }
    }

    detail+="\n-------------Hex----------------";
    for(int i=0; i<packet_vec[index].size(); i++){
        if(i % 16 == 0) detail += "\n";
        else if(i % 16 == 8) detail += "\t";
        detail += QString::asprintf("%02X ", ((quint8*)(ethe))[i]);
    }
    return detail;
}

void Capture::start() {
    start_time = QDateTime::currentSecsSinceEpoch();
    connect(recv, &Receiver::recv_packet, this, &Capture::proccess_packet);
}

void Capture::proccess_packet(qint64 sec, qint64 usec, QByteArray packet){
    if(isPause) return;

    double time = static_cast<double>(sec - start_time);
    time += (static_cast<double>(usec) / 1000000);
    qint64 length = packet.length();
    qint64 idx = packet_vec.size();
    packet_vec.push_back(packet);
    QString src = "";
    QString dst = "";
    QString protocol = "";

    const Ethernet * ethe = reinterpret_cast<const Ethernet*>(packet.constData());
    QString type = ethe->get_type();
    if(type == "ARP"){
        protocol = type;
        src = ethe->get_src();
        dst = ethe->get_dst();
    }
    else if(type == "IPv4"){
        protocol = type;
        Ip4Pkt* ippkt = (Ip4Pkt*)(((quint8*)ethe) + 14);

        src = ippkt->get_source();
        dst = ippkt->get_destination();
        protocol = ippkt->get_protocol();
        if(protocol == "UDP"){
            Udp* udp = (Udp*)(ippkt->get_body());
            if(udp->get_source() == 53 || udp->get_destination() == 53)
                protocol = "DNS";
        }
    }
    else if(type == "RARP"){
        protocol = type;
        src = ethe->get_src();
        dst = ethe->get_dst();
    }
    else if(type == "X.25" || type == "NetBIOS"){
        protocol = type;
        src = ethe->get_src();
        dst = ethe->get_dst();
    }

    emit captured(idx, time, src, dst, protocol, length);
}
