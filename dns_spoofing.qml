import QtQuick
import QtQuick.Controls

Item {
    objectName: "Dns Spoofing"
    Rectangle{
        anchors.fill: parent
        color: "black"
        border.color: "green"

        TextField{
            id: targetIp
            anchors{
                left: parent.left
                top: parent.top
                leftMargin: 20
                topMargin:30
            }
            color: "green"
            width: 300
            Text{
                anchors{bottom: parent.top; bottomMargin: 5}
                color: "green"
                font.bold: true
                text: "Target IP"
            }
        }
        TextField{
            id: gatewayIp
            anchors{
                left: parent.left
                top: targetIp.bottom
                leftMargin: 20
                topMargin:30
            }
            color: "green"
            width: 300
            Text{
                anchors{bottom: parent.top; bottomMargin: 5}
                color: "green"
                font.bold: true
                text: "Gateway IP"
            }
        }
        TextField{
            id: targetDomain
            anchors{
                left: parent.left
                top: gatewayIp.bottom
                leftMargin: 20
                topMargin:30
            }
            color: "green"
            width: 300
            Text{
                anchors{bottom: parent.top; bottomMargin: 5}
                color: "green"
                font.bold: true
                text: "Target Domain"
            }
        }
        TextField{
            id: fakeIp
            anchors{
                left: parent.left
                top: targetDomain.bottom
                leftMargin: 20
                topMargin:30
            }
            color: "green"
            width: 300
            Text{
                anchors{bottom: parent.top; bottomMargin: 5}
                color: "green"
                font.bold: true
                text: "Fake IP"
            }
        }

        Rectangle{
            id: startBtn
            anchors{left: targetIp.right; leftMargin: 50; top: targetIp.top}
            width: 100
            height: 50
            border.color: "green"
            color: "#424242"
            radius: 5
            property bool started: false

            Text{
                anchors.centerIn: parent
                color: startBtn.start ? "#5E5E5E" : "green"
                font.bold: true
                text: "Start Spoof"
            }

            MouseArea{
                anchors.fill: parent
                onPressed: {
                    if(!startBtn.started){parent.color = "#0D451E";}
                }
                onReleased: {
                    if(!startBtn.started){
                        parent.color = "#424242";
                        if(targetIp.text === "" || gatewayIp.text === "" || targetDomain.text === "" || fakeIp.text === ""){
                            popupText.text ="Target IP, Gateway IP, Target Domain and Fake IP must fill";
                            popup.open();
                            return;
                        }
                        startBtn.started = true;
                        llnm.start_dns_spoof(targetIp.text, gatewayIp.text, targetDomain.text, fakeIp.text);
                    }
                }
            }
        }
        Rectangle{
            id: stopBtn
            anchors{left: startBtn.left; top: startBtn.bottom}
            width: 100
            height: 50
            border.color: "green"
            color: "#424242"
            radius: 5

            Text{
                anchors.centerIn: parent
                color: !startBtn.start ? "#5E5E5E" : "green"
                font.bold: true
                text: "Start Spoof"
            }

            MouseArea{
                anchors.fill: parent
                onPressed: {parent.color = "#0D451E";}
                onReleased: {parent.color = "#424242";}
            }
        }
    }
}
