#ifndef CAPTURE_H
#define CAPTURE_H

#include <QThread>
#include <pcap/pcap.h>
#include <receiver.h>

class Capture : public QObject
{
    Q_OBJECT
private:
    Receiver* recv;
    QVector<QByteArray> packet_vec;
    qint64 start_time;
    bool isPause = false;
public:
    Capture(Receiver * r, QObject* parent=nullptr): recv(r), QObject(parent){}
    void pause_or_play(){isPause = !isPause;}
    void clear_vec(){packet_vec.clear();}
    QString get_detail(qint64 index);
public slots:
    void proccess_packet(qint64 sec, qint64 usec, QByteArray packet);
signals:
    void captured(qint64 no, double time, const QString& src, const QString& dst, const QString& proto, qint64 length);
public slots:
    void start();
};

#endif // CAPTURE_H
