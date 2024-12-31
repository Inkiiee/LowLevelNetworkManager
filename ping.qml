import QtQuick
import QtQuick.Controls

Item {
    objectName: "Ping"
    Rectangle{
        anchors.fill: parent
        color: "black"
        border.color: "green"

        TextField{
            id: targetIp
            anchors{
                top: parent.top
                left: parent.left
                topMargin: 30
                leftMargin: 10
            }
            width: 200

            Text{
                anchors{
                    bottom: parent.top
                    left: parent.left
                    bottomMargin: 10
                }
                color: "green"
                text: "Target IP"
            }
        }

        TextField{
            id: packetSize
            anchors{
                top: parent.top
                left: targetIp.right
                topMargin: 30
                leftMargin: 30
            }
            width: 100

            Text{
                anchors{
                    bottom: parent.top
                    left: parent.left
                    bottomMargin: 10
                }
                color: "green"
                text: "Packet size"
            }
        }

        Rectangle{
            id: button
            anchors{
                top: parent.top
                left: packetSize.right
                topMargin: 30
                leftMargin: 30
            }

            width: 100
            height: targetIp.height
            color: "#424242"
            border.color: "green"
            radius: 5

            Text{anchors.centerIn: parent; color: "green"; text: "send"}
            MouseArea{
                anchors.fill: parent
                onPressed: {if(!isSending){button.color = "#0D451E";}}
                property bool isSending: false
                onReleased: {
                    if(isSending) return;

                    button.color = "#424242";
                    if(targetIp.text === "" || packetSize.text === ""){
                        popupText.text = "Target Ip and Packet size must fill";
                        popup.open();
                        return;
                    }
                    else if(isNaN(Number(packetSize.text))){
                        popupText.text = "packet size must integer"
                        popup.open();
                        return;
                    }

                    var target = targetIp.text;
                    var size = packetSize.text;

                    var success = llnm.send_ping(target, size);
                    console.log(success);
                    while(!success){
                        isSending = true;
                        success = llnm.send_ping(target, size);
                    }
                    isSending = false;
                }
            }
        }
    }
}
