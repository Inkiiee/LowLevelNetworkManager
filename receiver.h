#ifndef RECEIVER_H
#define RECEIVER_H

#include <QObject>
#include <pcap/pcap.h>
#include <QMap>

struct PacketEvent{
    QMap<QString, QString> check_list;
    std::function<void(u_char* user, const QMap<QString, QString>& packet_state, const u_char* packet, int len)> routine;
};

class Receiver: public QObject
{
    Q_OBJECT
private:
    pcap_t * net;
    QMap<QString, PacketEvent> check_lists;
public:
    Receiver(pcap_t * n, QObject* llnm):net(n){ this->llnm = llnm; }
    void emit_recv_packet(qint64 sec, qint64 usec, const QByteArray& packet);

    QMap<QString, QString> mac_table;
    QMap<QString, QString> variables;
    QObject* llnm;
    QString addr_to_str(const QByteArray& array, quint8 len);
    void str_to_ip_addr(quint8* addr, const QString& str);
    void str_to_mac_addr(quint8* addr, const QString& str);
    void add_packet_event(const QString& event_id, const PacketEvent& event){
        check_lists[event_id] = event;
    }
    void del_packet_event(const QString& event_id){
        if(check_lists.contains(event_id))
            check_lists.remove(event_id);
    }

public slots:
    void start();
signals:
    void recv_packet(qint64 sec, qint64 usec, QByteArray packet);

    friend PacketEvent;
};

#endif // RECEIVER_H
