import QtQuick
import QtQuick.Controls

ApplicationWindow {
    id: packetDetailInfo
    title: "packet detail"
    visible: true
    width: 350
    height: 600

    property string detail: ""
    Flickable{
        anchors.fill: parent
        contentHeight: 100000
        Rectangle{
            anchors.fill: parent
            color: "black"
            border.color: "green"

            Text{
                id: detailText
                anchors.fill: parent
                font.bold: true
                color: "green"
                text: packetDetailInfo.detail
            }
        }
    }
}
