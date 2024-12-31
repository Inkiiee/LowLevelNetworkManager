#include <QGuiApplication>
#include <QQmlApplicationEngine>

#include "lowlevelnetworkmanager.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    qmlRegisterType<LowLevelNetworkManager>("LowLevelNetworkManager", 1, 0, "LLNManager");

    QQmlApplicationEngine engine;
    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &app,
        []() { QCoreApplication::exit(-1); },
        Qt::QueuedConnection);
    engine.loadFromModule("NetworkScanner", "Main");

    return app.exec();
}
