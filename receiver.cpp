#include <qDebug>
#include "receiver.h"
#include "network_headers.h"

void Receiver::start(){
    pcap_loop(net, -1, [](u_char* user, const struct pcap_pkthdr* h, const u_char* packet){
        Receiver * recv = (Receiver*)user;
        QMap<QString, QString> packet_state;

        const Ethernet* ethe = (const Ethernet*)packet;
        packet_state["Target_Mac"] = ethe->get_dst();
        packet_state["Source_Mac"] = ethe->get_src();
        packet_state["Network_Protocol"] = ethe->get_type();

        if(packet_state["Network_Protocol"] == "ARP"){
            Arp* arp = (Arp*)(ethe->get_body());
            packet_state["Source_IP"] = recv->addr_to_str(arp->get_spa(), arp->proto_addr_len);
            packet_state["Target_IP"] = recv->addr_to_str(arp->get_tpa(), arp->proto_addr_len);
            packet_state[packet_state["Network_Protocol"] + "_Type"] = arp->get_op();
        }
        else if(packet_state["Network_Protocol"] == "IPv4"){
            Ip4Pkt* ip = (Ip4Pkt*)(ethe->get_body());
            packet_state["Source_IP"] = ip->get_source();
            packet_state["Target_IP"] = ip->get_destination();
            packet_state[packet_state["Network_Protocol"]+"_Type"] = ip->get_protocol();

            const auto& payload_type = packet_state[packet_state["Network_Protocol"] + "_Type"];
            if(payload_type == "UDP"){
                Udp* udp = (Udp*)(ip->get_body());
                packet_state["Source_Port"] = QString::number(udp->get_source());
                packet_state["Target_Port"] = QString::number(udp->get_destination());
                if(udp->get_source() == 53 || udp->get_destination() == 53){
                    packet_state["Application_Protocol"] = "DNS";
                    Dns* dns = (Dns*)(udp->get_body());
                    packet_state[packet_state["Application_Protocol"] + "_Type"] = dns->get_type();
                }
            }
            else if(payload_type == "ICMP"){
                Icmp * icmp = (Icmp*)(ip->get_body());
                packet_state["Application_Protocol"] = payload_type;
                packet_state[packet_state["Application_Protocol"] + "_Type"] = icmp->icmp_type_to_string();
            }
        }

        for (QMap<QString, PacketEvent>::Iterator it = recv->check_lists.begin(); it != recv->check_lists.end(); ++it) {
            auto key = it.key();
            auto val = it.value();
            bool match = true;

            for(QMap<QString, QString>::Iterator iter = val.check_list.begin(); iter != val.check_list.end(); ++iter){
                const auto& check = iter.key();
                const auto& check_val = iter.value();

                if(packet_state.contains(check)){
                    const auto& packet_state_val = packet_state[check];
                    if(packet_state_val != check_val){
                        match = false;
                        break;
                    }
                }
                else{
                    match = false;
                    break;
                }
            }

            if(match){
                val.routine((u_char*)recv, packet_state, packet, h->caplen);
            }
        }

        recv->emit_recv_packet(h->ts.tv_sec, h->ts.tv_usec, QByteArray((const char*)packet, h->caplen));
    }, (u_char*)this);
}

void Receiver::emit_recv_packet(qint64 sec, qint64 usec, const QByteArray& packet){
    emit recv_packet(sec, usec, packet);
}

QString Receiver::addr_to_str(const QByteArray& array, quint8 len){
    QString separator;
    int shape;
    QString str_addr;

    if(len == 4){
        separator = ".";
        shape = 10;
    }else if(len == 6){
        separator = ":";
        shape = 16;
    }else{
        return "";
    }

    for(int i=0; i<len; i++){
        str_addr+=QString::number((quint8)array[i], shape);
        if(i != (len - 1)) str_addr+=separator;
    }

    return str_addr;
}

void Receiver::str_to_ip_addr(quint8* addr, const QString& str){
    auto token = str.split(".");
    for(int i=0; i<4; i++)
        addr[i] = token[i].toInt();
}

void Receiver::str_to_mac_addr(quint8* addr, const QString& str){
    auto token = str.split(":");
    for(int i=0; i<6; i++)
        addr[i] = token[i].toInt(nullptr, 16);
}
