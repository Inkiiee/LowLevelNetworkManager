#ifndef LOWLEVELNETWORKMANAGER_H
#define LOWLEVELNETWORKMANAGER_H

#include <QObject>
#include <QDebug>
#include <pcap/pcap.h>
#include "capture.h"
#include <QNetworkInterface>
#include "receiver.h"
#include "sender.h"

class LowLevelNetworkManager: public QObject
{
    Q_OBJECT
private:
    pcap_t * device = nullptr;
    pcap_if_t * devs = nullptr;
    char err_buf[PCAP_ERRBUF_SIZE];
    char buf[1<<16];
    QString TAG;
    Capture * cap = nullptr;

    void message(const QString& msg){qDebug()<<TAG<<": "<<msg;}
public:
    LowLevelNetworkManager(QObject* parent = nullptr): QObject(parent){
        TAG = "LowLevelNetworkManager";
    }
    Receiver* recv = nullptr;
    Sender * send = nullptr;

    QString address_to_string(struct sockaddr* addr);
    QString protocol_type(struct sockaddr* addr);
    QString target_domain;
    QString fake_ip;
    QString target_ip;
    QString gateway_ip;
    QTimer* dns_spoof_timer;

    Q_INVOKABLE void get_interfaces();
    Q_INVOKABLE void connect_interface(int idx);
    Q_INVOKABLE void reqCap();
    Q_INVOKABLE QString show_variables();
    Q_INVOKABLE QString show_mac_table();
    Q_INVOKABLE void pause_or_play_capture(){cap->pause_or_play();}
    Q_INVOKABLE void clear_capture(){cap->clear_vec();}
    Q_INVOKABLE bool send_ping(const QString& target, const QString& num){ return send->send_ping(target, num.toInt()); }
    Q_INVOKABLE QString request_detail_capture(qint64 index){return cap->get_detail(index);}
    Q_INVOKABLE bool arp_spoof(const QString& target, const QString& fake_ip, const QString& fake_mac){ return send->send_arp_request(fake_ip, target, fake_mac); }
    Q_INVOKABLE bool start_dns_spoof(const QString& target_ip, const QString& gateway_ip, const QString& domain, const QString& fake_ip);
    Q_INVOKABLE bool stop_dns_spoof();
public slots:
    void onCaptured(qint64 no, double time, const QString& src, const QString& dst, const QString& proto, qint64 length){
        emit capturedData(no, time, src, dst, proto, length);
    }
signals:
    void error(const QString& error);
    void interfaceSearch(const QString& name, const QString& descript, const QString& detail);
    void connectSuccess();
    void capturedData(qint64 no, double time, const QString& src, const QString& dst, const QString& proto, qint64 length);
};

#endif // LOWLEVELNETWORKMANAGER_H
