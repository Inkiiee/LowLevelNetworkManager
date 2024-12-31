#ifndef NETWORK_HEADERS_H
#define NETWORK_HEADERS_H

#include <QtTypes>
#include <QString>
#include "network_consts.h"
#include <pcap/pcap.h>

struct Ethernet{
    quint8 destination[6];
    quint8 source[6];
    quint8 op[2];

    QString get_info(){
        QString info = "[Ethernet]";
        info+=("\n\tDst: " + get_dst());
        info+=("\n\tSrc: " + get_src());
        info+=("\n\tPayload type: " + get_type());
        info+=("\n");
        return info;
    }
    int get_header_size(){return 14;}
    void set_dst(quint8* addr){
        for(int i=0; i<6; i++)
            destination[i] = addr[i];
    }
    void set_src(quint8* addr){
        for(int i=0; i<6; i++)
            source[i] = addr[i];
    }
    void set_op(quint16 val){
        *(quint16*)op = val;
    }
    QString get_dst() const {
        QString address = "";
        for(int i=0; i<6; i++){
            address += QString::number(destination[i], 16);
            if(i!=5) address += ":";
        }
        return address;
    }
    QString get_src() const {
        QString address = "";
        for(int i=0; i<6; i++){
            address += QString::number(source[i], 16);
            if(i!=5) address += ":";
        }
        return address;
    }
    QString get_type() const {
        quint16 * op_val = (quint16*)op;
        if(*op_val == htons(0x0800))
            return "IPv4";
        else if(*op_val == htons(0x86dd))
            return "IPv6";
        else if(*op_val == htons(0x8191))
            return "NetBIOS";
        else if(*op_val == htons(0x0805))
            return "X.25";
        else if(*op_val == htons(0x0806))
            return "ARP";
        else if(*op_val == htons(0x0835))
            return "RARP";
        else
            return "Unknown";
    }
    quint8* get_body() const {
        return ((quint8*)this + 14);
    }
};

struct Arp{
    quint8 hardware[2];
    quint8 protocol[2];
    quint8 hard_addr_len;
    quint8 proto_addr_len;
    quint8 op[2];

    QString get_info(){
        QString info = "[Arp]";
        info+=("\n\tHardware Type: " + get_hardware_type());
        info+=("\n\tProtocol Type: " + get_protocol_type());
        info+=("\n\tHardware length: " + QString::number(hard_addr_len));
        info+=("\n\tProtocol length: " + QString::number(proto_addr_len));
        info+=("\n\tSender Hardware Addr: " + get_string_address(get_sha(), hard_addr_len));
        info+=("\n\tSender Protocol Addr: " + get_string_address(get_spa(), proto_addr_len));
        info+=("\n\tTarget Hardware Addr: " + get_string_address(get_tha(), hard_addr_len));
        info+=("\n\tTarget Protocol Addr: " + get_string_address(get_tpa(), proto_addr_len));
        info+=("\n\tArp Operation: " + get_op());
        info+=("\n");
        return info;
    }
    int get_header_size(){
        return 8 + (2*hard_addr_len + 2*proto_addr_len);
    }
    void set_hard_type(quint16 val){
        *(quint16*)hardware = val;
    }
    void set_proto_type(quint16 val){
        *(quint16*)protocol = val;
    }
    void set_hard_addr_len(quint8 val){
        hard_addr_len = val;
    }
    void set_proto_addr_len(quint8 val){
        proto_addr_len = val;
    }
    void set_op(quint16 val){
        *(quint16*) op = val;
    }
    void set_sha(quint8* addr){
        auto sha = ((quint8*)this + 8);
        for(int i=0; i<hard_addr_len; i++)
            sha[i] = addr[i];
    }
    void set_spa(quint8* addr){
        auto spa = ((quint8*)this + 8 + hard_addr_len);
        for(int i=0; i<proto_addr_len; i++)
            spa[i] = addr[i];
    }
    void set_tha(quint8* addr){
        auto tha = ((quint8*)this + 8 + hard_addr_len + proto_addr_len);
        for(int i=0; i<hard_addr_len; i++)
            tha[i] = addr[i];
    }
    void set_tpa(quint8* addr){
        auto tpa = ((quint8*)this + 8 + hard_addr_len + proto_addr_len + hard_addr_len);
        for(int i=0; i<proto_addr_len; i++)
            tpa[i] = addr[i];
    }
    QString get_string_address(const QByteArray& addr, quint8 len){
        QString str_addr;
        QString sep = " ";
        int shape = 16;

        if(len == 4){
            shape = 10;
            sep = ".";
        }
        else if(len == 6){
            shape = 16;
            sep = ":";
        }

        for(int i=0; i<len; i++){
            str_addr += QString::number((quint8)addr[i], shape);
            if(i != (len - 1)) str_addr += sep;
        }
        return str_addr;
    }
    QString get_hardware_type(){
        quint16 type = *(quint16*)hardware;
        if(type == htons(0)) return "Reserved";
        else if(type == htons(1)) return "Ethernet(10Mb)";
        else if(type == htons(2)) return "Ethernet(3Mb)";
        else if(type == htons(3)) return "RadioAX.25";
        else if(type == htons(4)) return "TokenRing";
        else if(type == htons(5)) return "Chaos";
        else if(type == htons(6)) return "IEEE802Nets";
        else if(type == htons(7)) return "ARCNET";
        else if(type == htons(8)) return "HyperChannel";
        else if(type == htons(10)) return "AutonetShortAddress";
        else if(type == htons(13)) return "UltraLink";
        else if(type == htons(14)) return "SMDS";
        else if(type == htons(15)) return "FrameRelay";
        else if(type == htons(16)) return "ATM";
        else if(type == htons(17)) return "HDLC";
        else if(type == htons(18)) return "FibreChannel";
        else if(type == htons(19)) return "ATM";
        else if(type == htons(24)) return "IEEE1394.1995";
        else if(type == htons(28)) return "HIPARP";
        else if(type == htons(29)) return "IPAndARPOverISO";
        else if(type == htons(30)) return "ARPSec";
        else if(type == htons(35)) return "PureIP";
        else if(type == htons(38)) return "UnifiedBus";
        else if(type == htons(257)) return "AEthernet";
        else return "Unknown";
    }
    QString get_protocol_type(){
        quint16 type = *(quint16*)protocol;
        if(type == htons(proto_ipv4)) return "IPv4";
        else if(type == htons(proto_arp)) return "ARP";
        else if(type == htons(proto_frame_relay_arp)) return "Frame Relay ARP";
        else if(type == htons(proto_pptp)) return "Point-to-Point Tunneling Protocol(PPTP)";
        else if(type == htons(proto_gsmp)) return "General Switch Management Protocol (GSMP)";
        else if(type == htons(proto_rarp)) return "RARP";
        else if(type == htons(proto_ipv6)) return "IPv6";
        else if(type == htons(proto_mpls)) return "MPLS";
        else if(type == htons(proto_mpls_width_upstream)) return "MPLS width upstream-assigned label";
        else if(type == htons(proto_ppp_over_ethernet_discovery_stage)) return "PPP over Ethernet (PPPoE) Discovery Stage";
        else if(type == htons(proto_ppp_over_ethernet_session_stage)) return "PPP over Ethernet (PPPoE) Session Stage";
        else if(type == htons(proto_customer_vlan)) return "IEEE Std 802.1Q Customer VLAN Tag Type";
        else if(type == htons(proto_ethernet_passive_optical_network)) return "IEEE Std 802.3 Ethernet Passive Optical Network";
        else if(type == htons(proto_port_based_network_access_control)) return "IEEE Std 802.1X Port-based network access control";
        else if(type == htons(proto_service_vlan)) return "IEEE Std 802.1Q Service VLAN tag identifier";
        else if(type == htons(proto_local_experimental_ethertype)) return "IEEE Std 802 Local Experimental Ethertype";
        else if(type == htons(proto_local_experimental_ethertype2)) return "IEEE Std 802 Local Experimental Ethertype";
        else if(type == htons(proto_oui_extended_ethertype)) return "IEEE Std 802 OUI Extended Ethertype";
        else if(type == htons(proto_pre_authentication)) return "IEEE Std 802.11i Pre-Authentication";
        else if(type == htons(proto_lldp)) return "IEEE Std 802.1AB Link Layer Discovery Protocol (LLDP)";
        else if(type == htons(proto_media_access_control_security)) return "IEEE Std 802.1AE Media Access Control Security";
        else if(type == htons(proto_mvrp)) return "IEEE Std 802.1ak Multiple VLAN Registration Protocol(MVRP)";
        else if(type == htons(proto_mmrp)) return "IEEE Std 802.1Q Multiple Multicast Registration Protocol (MMRP)";
        else if(type == htons(proto_fast_roaming_remote_request)) return "IEEE Std 802.11r Fast Roaming Remote Request";
        else return "Unknown";
    }
    QString get_op(){
        quint16 type = *(quint16*)op;
        if(type == htons(arp_reserverd)) return "Reserved";
        else if(type == htons(arp_request)) return "Request";
        else if(type == htons(arp_reply)) return "Reply";
        else if(type == htons(arp_request_reverse)) return "Request Reverse";
        else if(type == htons(arp_reply_reverse)) return "Reply Reverse";
        else if(type == htons(arp_drarp_request)) return "DRARP Request";
        else if(type == htons(arp_drarp_reply)) return "DRARP Reply";
        else if(type == htons(arp_drarp_error)) return "DRARP Error";
        else if(type == htons(arp_inarp_request)) return "InARP Request";
        else if(type == htons(arp_inarp_reply)) return "InARP Reply";
        else if(type == htons(arp_arp_nak)) return "ARP NAK";
        else if(type == htons(arp_mars_request)) return "MARS Request";
        else if(type == htons(arp_mars_multi)) return "MARS Multi";
        else if(type == htons(arp_mars_mserv)) return "MARS MServ";
        else if(type == htons(arp_mars_join)) return "MARS Join";
        else if(type == htons(arp_mars_leave)) return "MARS Leave";
        else if(type == htons(arp_mars_nak)) return "MARS NAK";
        else if(type == htons(arp_mars_unserv)) return "MARS Unserv";
        else if(type == htons(arp_mars_sjoin)) return "MARS SJoin";
        else if(type == htons(arp_mars_sleave)) return "MARS SLeave";
        else if(type == htons(arp_mars_grouplist_request)) return "MARS Grouplist Request";
        else if(type == htons(arp_mars_grouplist_reply)) return "MARS Grouplist reply";
        else if(type == htons(arp_mars_redirect_map)) return "MARS Redirect Map";
        else if(type == htons(arp_mapos_unarp)) return "MAPOS UNARP";
        else if(type == htons(arp_op_exp1)) return "OP EXP1";
        else if(type == htons(arp_op_exp2)) return "OP EXP2";
        else return "Unknown";
    }

    QByteArray get_sha(){
        quint8* packet = (quint8*)this;
        quint8* sender_hardware_address = &(packet[8]);
        QByteArray sha;
        sha.append((const char*)sender_hardware_address, (qsizetype)hard_addr_len);

        return sha;
    }
    QByteArray get_spa(){
        quint8* packet = (quint8*)this;
        quint8* sender_protocol_address = &(packet[8 + hard_addr_len]);
        QByteArray spa;
        spa.append((const char*)sender_protocol_address, (qsizetype)proto_addr_len);

        return spa;
    }
    QByteArray get_tha(){
        quint8* packet = (quint8*)this;
        quint8* target_hardware_address = &(packet[8 + hard_addr_len + proto_addr_len]);
        QByteArray tha;
        tha.append((const char*)target_hardware_address, (qsizetype)hard_addr_len);

        return tha;
    }
    QByteArray get_tpa(){
        quint8* packet = (quint8*)this;
        quint8* target_protocol_address = &(packet[8 + hard_addr_len + hard_addr_len + proto_addr_len]);
        QByteArray tpa;
        tpa.append((const char*)target_protocol_address, (qsizetype)proto_addr_len);

        return tpa;
    }
};

struct Ip4Pkt{
    quint8 ver_and_ihl;
    quint8 service;
    quint8 total_length[2];
    quint8 identification[2];
    quint8 fragment[2];
    quint8 ttl;
    quint8 protocol;
    quint8 headerChecksum[2];
    quint8 source[4];
    quint8 destination[4];

    QString get_info(){
        QString info="[IPv4]";
        info+=("\n\tVersion: " + QString::number(get_ver()));
        info+=("\n\tHeader length: " + QString::number(get_header_len()));
        info+=("\n\tService: " + QString::number(get_service(), 16));
        info+=("\n\tTotal length: " + QString::number(get_total_length()));
        info+=("\n\tIdentification: " + QString::number(get_identification()));
        info+=("\n\tFragment offset: " + QString::number(get_fragment_offset()) + " (" + get_fragment_flags() + ")");
        info+=("\n\tTTL(Time To Live): " + QString::number(get_ttl()));
        info+=("\n\tPayload Type: " + get_protocol());
        info+=("\n\tChecksum: " + QString::number(get_header_checksum()) + " cal: " + QString::number(cal_checksum()));
        info+=("\n\tSrc: " + get_source());
        info+=("\n\tDst: " + get_destination());
        info+=("\n");
        return info;
    }
    void set_total_length(quint16 len){
        *(quint16*)total_length = htons(len);
    }
    void set_checksum(quint16 cs){
        *(quint16*)headerChecksum = htons(cs);
    }
    void set_default_header(quint16 id, quint16 length, quint16 frag, quint8 proto, quint8* sip, quint8* tip){
        ver_and_ihl = (4 << 4) | 5;
        service = 0;
        *(quint16*)total_length = htons(length);
        *(quint16*)identification = htons(id);
        *(quint16*)fragment = htons(frag);
        protocol = proto;
        ttl = 128;
        for(int i=0; i<4; i++){
            source[i] = sip[i];
            destination[i] = tip[i];
        }
        *(quint16*)headerChecksum = htons(cal_checksum());
    }
    quint16 get_fragment(quint16 frag_opt, quint16 offset){
        quint16 frag = 0;
        frag = (frag_opt << 13) | offset;
        return frag;
    }
    int get_ver(){
        return (ver_and_ihl & 0xf0) >> 4;
    }
    int get_header_len(){
        return (ver_and_ihl & 0x0f) * 4;
    }
    quint8 get_service(){
        return service;
    }
    quint16 get_total_length(){
        quint16 total = ntohs(*(quint16*)total_length);
        return total;
    }
    quint16 get_identification(){
        quint16 id = ntohs(*(quint16*)identification);
        return id;
    }
    quint16 get_fragment_offset(){
        quint16 offset = ntohs((*(quint16*)fragment) & 0x1fff);
        return offset;
    }
    QString get_fragment_flags(){
        QString flags = "";
        if(fragment[0] & 0x80){flags+="Invalid Fragment";}

        if(!flags.isEmpty())flags+="|";
        if(fragment[0] & 0x40){flags+="Can't frag|";}
        else{flags+="Can frag|";}

        if(fragment[0] & 0x20){flags+="No Last";}
        else{flags+="Last";}

        return flags;
    }
    quint8 get_ttl(){return ttl;}
    QString get_protocol(){
        if(protocol == 1) return "ICMP";
        else if(protocol == 2) return "IGMP";
        else if(protocol == 6) return "TCP";
        else if(protocol == 9) return "IGMP";
        else if(protocol == 17) return "UDP";
        else if(protocol == 47) return "GRE";
        else if(protocol == 50) return "ESP";
        else if(protocol == 51) return "AH";
        else if(protocol == 57) return "SKIP";
        else if(protocol == 88) return "EIGRP";
        else if(protocol == 89) return "OSPF";
        else if(protocol == 115) return "L2TP";
        else return "Unknown(" + QString::number(protocol)+")";
    }
    quint16 get_header_checksum(){
        quint16 cs = ntohs(*(quint16*)headerChecksum);
        return cs;
    }
    QString get_source(){
        QString ip;
        for(int i=0; i<4; i++){
            ip+=(QString::number(source[i]));
            if(i!=3) ip+=".";
        }
        return ip;
    }
    QString get_destination(){
        QString ip;
        for(int i=0; i<4; i++){
            ip+=(QString::number(destination[i]));
            if(i!=3) ip+=".";
        }
        return ip;
    }
    quint16 cal_checksum(){
        quint8 header_size = get_header_len();
        quint32 sum = 0;
        auto ptr = (quint8*)this;

        for(int i=0; i<header_size; i+=2){
            auto data = *(quint16*)(ptr + i);
            data = ntohs(data);
            sum+=data;
        }
        if(header_size % 2 == 1){
            quint32 data = (*(quint8*)(ptr + header_size - 1) << 8);
            sum += data;
        }
        sum -= get_header_checksum();
        while(sum>>16){
            auto carry = (sum>>16)&0xffff;
            sum = (sum & 0xffff) + carry;
        }
        return ~sum;
    }
    quint8* get_body(){
        return ((quint8*)this + get_header_len());
    }
};

struct Icmp{
    quint8 type;
    quint8 code;
    quint8 checksum[2];
    quint8 identifier[2];
    quint8 sequence[2];

    QString get_info(){
        QString info = "[Icmp]";
        info+=("\n\tType: " + icmp_type_to_string());
        info+=("\n\tCode: " + QString::number(get_icmp_code()));
        info+=("\n\tChecksum: " + QString::number(get_icmp_checksum()));
        info+=("\n\tidentifier: " + QString::number(get_icmp_id()));
        info+=("\n\tSequence: " + QString::number(get_sequence()));
        info+=("\n");
        return info;
    }
    void set_id(quint16 id){
        *(quint16*)identifier = htons(id);
    }
    void set_seq(quint16 seq){
        *(quint16*)sequence = htons(seq);
    }
    void set_checksum(quint16 cs){
        *(quint16*)checksum = htons(cs);
    }
    int get_header_size(){return 8;}
    quint8 get_icmp_type(){return type;}
    quint8 get_icmp_code(){return code;}
    quint16 get_icmp_checksum(){
        quint16 val = ntohs(*(quint16*)checksum);
        return val;
    }
    quint16 get_icmp_id(){
        quint16 val = ntohs(*(quint16*)identifier);
        return val;
    }
    quint16 get_sequence(){
        quint16 val = ntohs(*(quint16*)sequence);
        return val;
    }
    QString icmp_type_to_string(){
        if(type == icmp_type_echo_reply) return "Echo Reply";
        else if(type == icmp_type_destination_unreachable) return "Destination Unreachable";
        else if(type == icmp_type_redirect) return "Redirect";
        else if(type == icmp_type_echo_request) return "Echo Request";
        else if(type == icmp_type_time_exceeded) return "Time Exceeded";
        else if(type == icmp_type_parameter_problem) return "Parameter Problem";
        else if(type == icmp_type_timestamp_request) return "Timestamp Request";
        else if(type == icmp_type_timestamp_reply) return "Timestamp Reply";
        else return "Unknown";
    }
    quint16 cal_checksum(int len){
        quint32 total = 0;
        quint8* ptr = (quint8*)this;
        int isLast = -1;

        if(len % 2 == 1){
            isLast = len - 1;
            len-=1;
        }

        for(int i=0; i<len; i+=2){
            auto data = *(quint16*)(ptr + i);
            data = ntohs(data);
            total += data;
            total = (total & 0xff0000) + (total & 0xffff);
        }
        if(isLast != -1){
            quint16 last = *(quint8*)(ptr + isLast) << 8;
            total += last;
        }
        total -= get_icmp_checksum();
        while(total>>16){
            quint32 carry = (total>>16) & 0xffff;
            total = (total & 0xffff) + carry;
        }

        return ~total;
    }
    quint8* get_body(){
        return ((quint8*)this + 8);
    }
};

struct pseudo_udp_header{
    quint8 src_ip[4];
    quint8 dst_ip[4];
    quint8 placeholder;
    quint8 protocol;
    quint8 len[2];

    void set_header(quint8* sip, quint8* tip, quint16 length){
        for(int i=0; i<4; i++){
            src_ip[i] = sip[i];
            dst_ip[i] = tip[i];
        }
        protocol = 17;
        placeholder = 0;
        *(quint16*)len = htons(length);
    }
};

struct Udp{
    quint8 source_port[2];
    quint8 destination_port[2];
    quint8 length[2];
    quint8 checksum[2];

    QString get_info(){
        QString info = "[Udp]";
        info+=("\n\tSrc Port: " + QString::number((get_source())));
        info+=("\n\tDst Port: " + QString::number((get_destination())));
        info+=("\n\tLength: " + QString::number((get_length())));
        info+=("\n\tChecksum: " + QString::number((get_checksum())));
        info+=("\n");

        return info;
    }
    void set_checksum(quint16 cs){
        *(quint16*)checksum = htons(cs);
    }
    void set_length(quint16 len){
        *(quint16*)length = htons(len);
    }
    void set_source(quint16 port){
        *(quint16*)source_port = htons(port);
    }
    void set_destination(quint16 port){
        *(quint16*)destination_port = htons(port);
    }
    quint8 * get_body(){return ((quint8*)this + 8);}
    quint16 get_source(){
        return ntohs(*(quint16*)source_port);
    }
    quint16 get_destination(){
        return ntohs(*(quint16*)destination_port);
    }
    quint16 get_length(){
        return ntohs(*(quint16*)length);
    }
    quint16 get_checksum(){
        return ntohs(*(quint16*)checksum);
    }
    quint16 cal_checksum(quint8* sip, quint8* tip, quint16 length){
        pseudo_udp_header temp_header;
        temp_header.set_header(sip, tip, length);
        quint32 sum = 0;

        quint8* ptr = (quint8*)(&temp_header);
        for(int i=0; i < 12; i+=2){
            sum += ntohs(*(quint16*)(ptr + i));
            sum = (sum & 0xff0000) + (sum & 0xffff);
        }
        int len = length;
        ptr = (quint8*)(this);
        for(int i=0; i < (len - 1); i+=2){
            sum += ntohs(*(quint16*)(ptr + i));
            sum = (sum & 0xff0000) + (sum & 0xffff);
        }
        if(len % 2 == 1){
            quint16 data = *(quint8*)(ptr + len - 1);
            data = data<<8;
            sum += data;
        }
        sum -= get_checksum();
        while(sum>>16){
            quint32 carry = (sum >> 16) & 0xffff;
            sum = (sum & 0xffff) + carry;
        }
        return ~sum;
    }
};

struct DnsQuery{
    QString name;
    quint8 type[2];
    quint8 cl[2];
    quint8* next;

    quint16 get_type(){
        return ntohs(*(quint16*)type);
    }
    quint16 get_class(){
        return ntohs(*(quint16*)cl);
    }
    QString get_class_info(){
        quint16 class_info = get_class();
        if(class_info == dns_class_in) return "IN(" + QString::number(class_info) + ")";
        else if(class_info == dns_class_ch) return "CH(" + QString::number(class_info) + ")";
        else if(class_info == dns_class_hs) return "HS(" + QString::number(class_info) + ")";
        else if(class_info == dns_class_any) return "ANY(" + QString::number(class_info) + ")";
        else return "Unknown(" + QString::number(class_info) + ")";
    }
    QString get_type_info(){
        quint16 type_info = get_type();
        if(type_info == dns_type_a) return "A(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_aaaa) return "AAAA(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_cname) return "CNAME(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_mx) return "MX(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_ns) return "NS(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_ptr) return "PTR(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_soa) return "SOA(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_srv) return "SRV(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_txt) return "TEXT(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_any) return "ANY(" + QString::number(type_info) + ")";
        else return "Unknown(" + QString::number(type_info) + ")";
    }
};
struct DnsAnswer{
    QString name;
    quint8 type[2];
    quint8 cl[2];
    quint8 ttl[4];
    quint8 length[2];
    QVector<quint8> rdata;
    quint8* next;

    quint16 get_type(){
        return ntohs(*(quint16*)type);
    }
    quint16 get_class(){
        return ntohs(*(quint16*)cl);
    }
    quint32 get_ttl(){
        return ntohl(*(quint32*)ttl);
    }
    quint16 get_length(){
        return ntohs(*(quint16*)length);
    }
    QString get_class_info(){
        quint16 class_info = get_class();
        if(class_info == dns_class_in) return "IN(" + QString::number(class_info) + ")";
        else if(class_info == dns_class_ch) return "CH(" + QString::number(class_info) + ")";
        else if(class_info == dns_class_hs) return "HS(" + QString::number(class_info) + ")";
        else if(class_info == dns_class_any) return "ANY(" + QString::number(class_info) + ")";
        else return "Unknown(" + QString::number(class_info) + ")";
    }
    QString get_type_info(){
        quint16 type_info = get_type();
        if(type_info == dns_type_a) return "A(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_aaaa) return "AAAA(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_cname) return "CNAME(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_mx) return "MX(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_ns) return "NS(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_ptr) return "PTR(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_soa) return "SOA(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_srv) return "SRV(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_txt) return "TEXT(" + QString::number(type_info) + ")";
        else if(type_info == dns_type_any) return "ANY(" + QString::number(type_info) + ")";
        else return "Unknown(" + QString::number(type_info) + ")";
    }
};
struct Dns{
    quint8 id[2];
    quint8 flags[2];
    quint8 questions[2];
    quint8 answers[2];
    quint8 authoritys[2];
    quint8 additionals[2];

    void set_id(quint16 iden){*(quint16*)id = htons(iden);}
    void set_flags(quint16 f){*(quint16*)flags = htons(f);}
    void set_num_of_questions(quint16 num){*(quint16*)questions = htons(num);}
    void set_num_of_answers(quint16 num){*(quint16*)answers = htons(num);}
    void set_num_of_authoritys(quint16 num){*(quint16*)authoritys = htons(num);}
    void set_num_of_additionals(quint16 num){*(quint16*)additionals = htons(num);}

    QString get_info(){
        QString info = "[Dns]";
        info+=("\n\tIdentifier: " + QString::number(get_id()));
        info+=("\n\tFlags: " + QString::number(get_flag()));
        bool flag_valid = get_flag_valid();
        info+=("\n\t\tValidation: " + QString(flag_valid ? "Valid" : "Not valid"));
        if(flag_valid){
            info+=("\n\t\tType: " + get_type());
            info+=("\n\t\tOpcode: " + get_opcode());
            info+=("\n\t\tAA: " + get_aa());
            info+=("\n\t\tTC: " + get_tc());
            info+=("\n\t\tRD: " + get_rd());
            info+=("\n\t\tRA: " + get_ra());
            info+=("\n\t\tRCODE: " + get_flag_recode());
        }
        info+=("\n\tNum of Questions: " + QString::number(get_num_of_questions()));
        info+=("\n\tNum of Answers: " + QString::number(get_num_of_answers()));
        info+=("\n\tNum of Authoritys: " + QString::number(get_num_of_authoritys()));
        info+=("\n\tNum of Additionals: " + QString::number(get_num_of_addtionals()));

        quint8* msg = ((quint8*)this + 12);
        int num = get_num_of_questions();
        if(num > 0){
            info+=("\n\tQueries");
            for(int i=0; i<num; i++){
                info+=("\n\t\t--------------------------");
                auto query = parse_query(msg);
                info+=("\n\t\tName: " + query.name);
                info+=("\n\t\tType: " + query.get_type_info());
                info+=("\n\t\tClass: " + query.get_class_info());
                msg = query.next;
            }
        }
        num = get_num_of_answers();
        if(num > 0){
            info+=("\n\tAnswer");
            for(int i=0; i<num; i++){
                info+=("\n\t\t--------------------------");
                auto answer = parse_answer(msg);
                info+=("\n\t\tName: " + answer.name);
                info+=("\n\t\tType: " + answer.get_type_info());
                info+=("\n\t\tClass: " + answer.get_class_info());
                info+=("\n\t\tTTL: " + QString::number(answer.get_ttl()));
                info+=("\n\t\tLength: " + QString::number(answer.get_length()));
                info+="\n\t\t";
                for(const auto& d: answer.rdata){
                    info+=(QString::asprintf("%02X ", d));
                }
                msg = answer.next;
            }
        }
        return info;
    }
    quint16 get_id(){
        return ntohs(*(quint16*)id);
    }
    quint16 get_flag(){
        return ntohs(*(quint16*)flags);
    }
    QString get_type(){
        return get_flag() & dns_reply ? "DNS Reply" : "DNS Query";
    }
    QString get_opcode(){
        auto op_flag = get_flag() & 0x7800;
        if(op_flag == dns_op_std_query) return "Standard Query";
        else if(op_flag == dns_op_reverse_search) return "Reverse Search";
        else if(op_flag == dns_op_state_server) return "Request Server State";
        else return "Unknown";
    }
    QString get_aa(){
        auto aa_val = get_flag() & 0x0400;
        if(aa_val == dns_aa) return "Authoritative Answer";
        else return "No Authoritative Answer";
    }
    QString get_tc(){
        auto tc_val = get_flag() & 0x0200;
        if(tc_val == dns_tc) return "Message Truncation";
        else return "Message Not Truncation";
    }
    QString get_rd(){
        auto rd_val = get_flag() & 0x0100;
        if(rd_val == dns_rd) return "Recursion Desired";
        else return "Not Recursion Desired";
    }
    QString get_ra(){
        auto ra_val = get_flag() & 0x0080;
        if(ra_val == dns_ra) return "Recursion Available";
        else return "Not Recursion Available";
    }
    bool get_flag_valid(){
        auto reserved = get_flag() & 0x0070;
        if(reserved == 0) return true;
        else return false;
    }
    QString get_flag_recode(){
        auto recode = get_flag() & 0x0008;
        if(recode == dns_recode_normal) return "Normal";
        else if(recode == dns_recode_error_format) return "Format Error";
        else if(recode == dns_recode_error_name) return "Domain Name Error";
        else if(recode == dns_recode_failed_server) return "Failed Server";
        else if(recode == dns_recode_not_support) return "Not Support";
        else if(recode == dns_recode_refused) return "Refused";
        else return "Unknown Recode";
    }
    quint16 get_num_of_questions(){
        return ntohs(*(quint16*)questions);
    }
    quint16 get_num_of_answers(){
        return ntohs(*(quint16*)answers);
    }
    quint16 get_num_of_authoritys(){
        return ntohs(*(quint16*)authoritys);
    }
    quint16 get_num_of_addtionals(){
        return ntohs(*(quint16*)additionals);
    }
    quint8* get_body(){
        return ((quint8*)this + 12);
    }
    quint8* parse_name(quint8* name_ptr, QString& name){
        char name_buf[1024];
        quint8 num = *(name_ptr++);
        int idx = 0;

        while(true){
            for(int i=0; i<num; i++)
                name_buf[idx++] = *(name_ptr++);
            num = *(name_ptr++);
            if(num != 0)
                name_buf[idx++] = '.';
            else{
                name_buf[idx] = 0;
                break;
            }
        }
        name = QString(name_buf);
        return name_ptr;
    }

    DnsQuery parse_query(quint8* name_ptr){
        DnsQuery query;
        quint16 num = ntohs(*((quint16*)name_ptr));
        quint8* name_offset = name_ptr;

        if(num & 0xC000){
            name_offset = (quint8*)this + (num & 0x3fff);
            parse_name(name_offset, query.name);
            name_ptr += 2;
        }
        else
            name_ptr = parse_name(name_offset, query.name);

        for(int i=0; i<2; i++)
            query.type[i] = *(name_ptr++);
        for(int i=0; i<2; i++)
            query.cl[i] = *(name_ptr++);
        query.next = name_ptr;

        return query;
    }
    DnsAnswer parse_answer(quint8* name_ptr){
        DnsAnswer answer;
        quint16 num = ntohs(*((quint16*)name_ptr));
        quint8* name_offset = name_ptr;

        if(num & 0xC000){
            name_offset = (quint8*)this + (num & 0x3fff);
            parse_name(name_offset, answer.name);
            name_ptr += 2;
        }
        else
            name_ptr = parse_name(name_offset, answer.name);

        for(int i=0; i<2; i++)
            answer.type[i] = *(name_ptr++);
        for(int i=0; i<2; i++)
            answer.cl[i] = *(name_ptr++);
        for(int i=0; i<4; i++)
            answer.ttl[i] = *(name_ptr++);
        for(int i=0; i<2; i++)
            answer.length[i] = *(name_ptr++);

        quint16 len = ntohs(*(quint16*)(answer.length));
        for(int i=0; i<len; i++)
            answer.rdata.push_back(*(name_ptr++));
        answer.next = name_ptr;
        return answer;
    }
};

#endif // NETWORK_HEADERS_H
