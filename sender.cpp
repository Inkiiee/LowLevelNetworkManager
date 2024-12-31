#include "sender.h"
#include "network_headers.h"
#include "network_consts.h"

#include <qDebug>
#include <QTimer>

bool Sender::send_ping(const QString& target_ip, int size){
    QString target = target_ip;
    if(recv->variables.contains(target))
        target = recv->variables[target];
    if(!recv->mac_table.contains(target)){
        send_arp_request("MY_IP", target, "MY_MAC");
        return false;
    }

    quint8 src_mac[6];
    quint8 dst_mac[6];
    quint8 sip[4];
    quint8 tip[4];
    set_mac_addr(src_mac, recv->variables["MY_MAC"]);
    set_mac_addr(dst_mac, recv->mac_table[target]);
    set_ip_addr(sip, recv->variables["MY_IP"]);
    set_ip_addr(tip, target);

    std::unique_ptr<quint8[]> pkt(new quint8[size]);
    Ethernet* ethe = (Ethernet*)(pkt.get());
    ethe->set_dst(dst_mac);
    ethe->set_src(src_mac);
    ethe->set_op(htons(proto_ipv4));
    Ip4Pkt* ip = (Ip4Pkt*)(ethe->get_body());
    ip->set_default_header(4150, size-14, ip->get_fragment(0, 0), 1, sip, tip);
    Icmp* icmp = (Icmp*)(ip->get_body());
    icmp->type = icmp_type_echo_request;
    icmp->code = 0;
    icmp->set_id(1);
    icmp->set_seq(80);
    icmp->set_checksum(icmp->cal_checksum(size - (ethe->get_header_size() + ip->get_header_len())));
    pcap_sendpacket(net, pkt.get(), size);

    return true;
}

bool Sender::send_arp_request(const QString& sender_ip, const QString& receiever_ip, const QString& sender_mac){
    quint8 src_ip[4];
    quint8 dst_ip[4];
    quint8 src_mac[6];
    quint8 dst_mac[6];

    QString str_user_mac;
    QString str_sip;
    QString str_tip;
    int i;

    i = 0;
    for(const auto& addr_token : sender_ip.split("."))
        src_ip[i] = (quint8)(addr_token.toInt());

    i = 0;
    for(const auto& addr_token : receiever_ip.split("."))
        dst_ip[i] = (quint8)(addr_token.toInt());

    for(i=0; i<6; i++)
        dst_mac[i] = (quint8)0xff;

    if(sender_mac.isEmpty()){
        if(recv->variables.contains("MY_MAC")){
            str_user_mac = recv->variables["MY_MAC"];
        }
        else{
            emit error("MY_MAC is not set. please try later");
            return false;
        }
    }
    else{
        str_user_mac = sender_mac;
    }

    if(recv->variables.contains(str_user_mac))
        str_user_mac = recv->variables[str_user_mac];

    if(!set_mac_addr(src_mac, str_user_mac)){
        emit error("Source Mac address is not correct");
        return false;
    }

    str_sip = sender_ip;
    str_tip = receiever_ip;
    if(recv->variables.contains(str_sip))
        str_sip = recv->variables[str_sip];
    if(recv->variables.contains(str_tip))
        str_tip = recv->variables[str_tip];

    if(!set_ip_addr(src_ip, str_sip)){
        qDebug()<<str_sip;
        emit error("Source IP address is not correct");
        return false;
    }
    if(!set_ip_addr(dst_ip, str_tip)){
        qDebug()<<str_tip;
        emit error("Target IP address is not correct");
        return false;
    }

    quint8 arp_packet[1024];
    auto ethernet_header = (Ethernet*)arp_packet;
    ethernet_header->set_dst(dst_mac);
    ethernet_header->set_src(src_mac);
    ethernet_header->set_op(htons(proto_arp));
    int header_size = ethernet_header->get_header_size();
    auto arp_header = (Arp*)(ethernet_header->get_body());
    arp_header->set_hard_type(htons(1));
    arp_header->set_hard_addr_len(6);
    arp_header->set_proto_type(htons(proto_ipv4));
    arp_header->set_proto_addr_len(4);
    arp_header->set_op(htons(arp_request));
    arp_header->set_sha(src_mac);
    arp_header->set_spa(src_ip);
    arp_header->set_tha(dst_mac);
    arp_header->set_tpa(dst_ip);
    header_size += arp_header->get_header_size();

    pcap_sendpacket(net, arp_packet, header_size);
    return true;
}
