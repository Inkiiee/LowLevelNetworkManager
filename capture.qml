import QtQuick
import Qt.labs.qmlmodels

Item {
    objectName: "Capture"
    Rectangle{
        id:capturePage
        anchors.fill: parent
        color: "black"
        Grid{
            id:headerGrid
            anchors.top: capturePage.top
            width: parent.width
            height: 20
            rows: 1
            property var headerWidths: [0.06, 0.12, 0.24, 0.24, 0.17, 0.17]
            property var headerNames: ["No", "Time", "Sender", "Destination", "Protocol", "Length"]
            z: 5

            Repeater{
                model: 6
                Rectangle{
                    color: "black"
                    border.color: "green"
                    width: headerGrid.headerWidths[index] * headerGrid.width
                    height: parent.height

                    Text{
                        anchors.centerIn: parent
                        text: headerGrid.headerNames[index]
                        color: "green"
                        font.bold: true
                    }
                }
            }
        }

        TableView{
            id: packetTable
            anchors{
                left: parent.left
                right: parent.right
                bottom: parent.bottom
                top: headerGrid.bottom
            }
            rowSpacing: 1
            clip: true
            property var columnWidths: [0.06, 0.12, 0.24, 0.24, 0.17, 0.17]
            columnWidthProvider: function(column){return capturePage.width * columnWidths[column];}
            model: packetModel

            selectionModel: ItemSelectionModel{
                id:tableSelector
                model: packetTable.model
            }

            delegate: Rectangle{
                implicitHeight: 20
                border.color: "green"
                border.width: 0.5

                color: packetTable.currentRow === model.row ? "#0D451E" : "#424242"
                clip: true

                Text{
                    text: display
                    color: "green"
                    anchors.centerIn: parent
                }
            }
            onCurrentRowChanged: {
                if(packetTable.currentRow === -1) return;
                var detail = llnm.request_detail_capture(packetTable.currentRow);
                var comp = Qt.createComponent("qrc:/capture_detail_info.qml");
                var newWindow = comp.createObject(capturePage, {"detail" : detail});
                newWindow.show();
            }
        }
    }

    Rectangle{
        id: captureControlBtn
        anchors{
            bottom: parent.bottom
            right: parent.right
            bottomMargin: 20
            rightMargin: 20
        }
        width: 40
        height: 40
        radius: 5
        color: "#424242"
        border.color: "green"
        property bool pause: false

        Image{
            id: captureControlIcon
            anchors.centerIn: parent
            width: parent.width * 0.7
            height: parent.height * 0.7
            source: captureControlBtn.pause ? "qrc:/icons/play_icon.png" : "qrc:/icons/pause_icon.png"
            fillMode: Image.PreserveAspectFit
        }
        MouseArea{
            anchors.fill: parent
            onPressed: {captureControlBtn.color = "#0D451E";}
            onReleased: {captureControlBtn.color = "#424242"; llnm.pause_or_play_capture(); captureControlBtn.pause = !captureControlBtn.pause;}
        }
    }

    Rectangle{
        id: captureRemoveBtn
        anchors{
            bottom: parent.bottom
            right: captureControlBtn.left
            bottomMargin: 20
            rightMargin: 20
        }
        width: 40
        height: 40
        radius: 5
        color: "#424242"
        border.color: "green"

        Image{
            anchors.centerIn: parent
            width: parent.width * 0.7
            height: parent.height * 0.7
            source: "qrc:/icons/remove_icon.png"
            fillMode: Image.PreserveAspectFit
        }
        MouseArea{
            anchors.fill: parent
            onPressed: {captureRemoveBtn.color = "#0D451E";}
            onReleased: {
                captureRemoveBtn.color = "#424242";
                packetTable.selectionModel.clearCurrentIndex();
                llnm.clear_capture();
                packetModel.clear();
            }
        }
    }

    Component.onCompleted: {llnm.reqCap();}
}
