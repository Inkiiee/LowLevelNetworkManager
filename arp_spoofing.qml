import QtQuick
import QtQuick.Controls

Item {
    objectName: "Arp Spoofing"
    Rectangle{
        id: arpSpf
        anchors.fill: parent
        color: "black"
        border.color: "green"

        TextField{
            id: targetIp
            anchors{
                left: parent.left
                top: parent.top
                leftMargin: 10
                topMargin: 30
            }
            width: parent.width * 0.6
            color: "green"
            Text{
                anchors{bottom: parent.top; bottomMargin: 5}
                color: "green"
                font.bold: true
                text: "Target IP"
            }
        }
        TextField{
            id: fakeIp
            anchors{
                left: parent.left
                top: targetIp.bottom
                leftMargin: 10
                topMargin: 30
            }
            width: parent.width * 0.6
            color: "green"
            Text{
                anchors{bottom: parent.top; bottomMargin: 5}
                color: "green"
                font.bold: true
                text: "Fake IP"
            }
        }
        TextField{
            id: fakeMac
            anchors{
                left: parent.left
                top: fakeIp.bottom
                leftMargin: 10
                topMargin: 30
            }
            width: parent.width * 0.6
            color: "green"
            Text{
                anchors{bottom: parent.top; bottomMargin: 5}
                color: "green"
                font.bold: true
                text: "Fake MAC"
            }
        }
        Rectangle{
            id: spoofingBtn
            anchors{
                top: fakeMac.bottom
                topMargin: 20
                left: parent.left
                right: parent.right
            }
            height: 50
            color: "#424242"
            radius: 10
            border.color: "green"
            property bool isSpf: false

            Text{
                anchors.centerIn: parent
                color: "green"
                font.bold: true
                text: "Spoofing"
            }

            MouseArea{
                anchors.fill: parent
                onPressed: { spoofingBtn.color = "#0D451E"; }
                onReleased: {
                    spoofingBtn.color = "#424242";
                    if(targetIp.text === "" || fakeIp.text === "" || fakeMac.text === ""){
                        popupText.text = "targetIP, fakeIP and fakeMac must fill";
                        popup.open();
                        return;
                    }

                    spfTimer.targetIPs.push(targetIp.text);
                    targetIp.text = "";
                    spfTimer.fakeIPs.push(fakeIp.text);
                    fakeIp.text = "";
                    spfTimer.fakeMacs.push(fakeMac.text);
                    fakeMac.text = "";
                    spoofingBtn.isSpf = true;
                }
            }
        }

        Rectangle{
            id: stopSpoofingBtn
            anchors{
                top: spoofingBtn.bottom
                topMargin: 20
                left: parent.left
                right: parent.right
            }
            height: 50
            color: "#424242"
            radius: 10
            border.color: "green"

            Text{
                anchors.centerIn: parent
                color: "green"
                font.bold: true
                text: "Stop Spoofing"
            }

            MouseArea{
                anchors.fill: parent
                onPressed: { if(spoofingBtn.isSpf){stopSpoofingBtn.color = "#0D451E";}}
                onReleased: {
                    stopSpoofingBtn.color = "#424242";
                    if(!spoofingBtn.isSpf){
                        return;
                    }

                    spoofingBtn.isSpf = false;
                    resultText.text = "Stopped Spoofing";
                }
            }
        }

        Rectangle{
            anchors.top: stopSpoofingBtn.bottom;
            anchors.topMargin: 30
            anchors.bottom: parent.bottom
            anchors.bottomMargin: 30
            anchors.left: parent.left
            anchors.right: parent.right
            border.color: "green"

            Flickable{
                anchors.fill: parent
                contentHeight: parent.height * 100
                clip: true
                Text{
                    id: resultText
                    anchors.fill: parent
                    anchors.leftMargin: 20
                    color: "green"
                    font.bold: true
                }
            }
        }

        Timer{
            id: spfTimer
            interval: 100
            repeat: spoofingBtn.isSpf
            running: spoofingBtn.isSpf

            property var targetIPs: []
            property var fakeIPs: []
            property var fakeMacs: []
            onTriggered: {
                resultText.text = "";
                for(var i=0; i < targetIPs.length; i++){
                    var target = targetIPs[i];
                    var fake_ip = fakeIPs[i];
                    var fake_mac = fakeMacs[i];

                    resultText.text = resultText.text + "[SPOOF]\n" + "target: " + target + "\n" + "fake ip: " + fake_ip + "\nfake mac: " + fake_mac;
                    var result = llnm.arp_spoof(target, fake_ip, fake_mac);
                    resultText.text += ("\n"+result+"\n");
                    if(!result) {
                        targetIPs = [];
                        fakeIPs = [];
                        fakeMacs = [];
                        spoofingBtn.isSpf = false;
                    }
                }
            }
        }
    }
}
