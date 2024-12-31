import QtQuick
import QtQuick.Controls
import Qt.labs.qmlmodels
import LowLevelNetworkManager 1.0

Window {
    width: 800
    height: 450
    visible: true
    title: qsTr("Hello World")

    LLNManager{
        id: llnm
        onError: function(msg){popupText.text = msg; popup.open();}
        onInterfaceSearch: function(name, descript, detail){add_item(name, descript, detail);}
        onConnectSuccess: {stackView.push("qrc:/home.qml");}
        onCapturedData: function(no, time, src, dst, proto, length){
            add_captured_packet(no, time, src, dst, proto, length);
        }
    }

    ListModel{id: netInterfaceListModel}
    TableModel{
        id: packetModel
        TableModelColumn{display: "No";}
        TableModelColumn{display: "Time"}
        TableModelColumn{display: "Source"}
        TableModelColumn{display: "Destination"}
        TableModelColumn{display: "Protocol"}
        TableModelColumn{display: "Length"}
    }

    function add_item(ifName, ifDescr, detail){
        netInterfaceListModel.append({name: ifName, description: ifDescr, detailInfo: detail});
    }

    function add_captured_packet(no, time, src, dst, proto, length){
        packetModel.appendRow({
            No: no, Time: time.toFixed(2), Source: src, Destination: dst, Protocol: proto, Length: length
        });
    }

    StackView{
        id: stackView
        anchors.fill: parent
        initialItem: "qrc:/interface_search.qml"
    }

    Popup{
        id: popup
        anchors.centerIn: parent
        width: parent.width * 0.5
        height: parent.height * 0.4
        Rectangle{
            anchors.fill: parent
            color: "black"

            Text{
                id: popupText
                anchors.centerIn: parent
                color: "green"
                font.bold: true
            }
        }
    }
}
