import QtQuick

Item {
    id: search

    Rectangle{
        id: titleRect
        anchors.top: parent.top
        width: parent.width * 0.3
        height: parent.height / 8
        color: "black"
        border.color: "green"
        z:5

        Text{
            id: title
            anchors.centerIn: parent
            color: "green"
            font.bold: true
            font.pixelSize: parent.width / text.length
            text: "network interface"
            opacity: 0.5
        }
    }

    Rectangle{
        id: contentRect
        anchors{
            top: titleRect.bottom
            bottom: parent.bottom
            left: parent.left
        }
        width: parent.width * 0.3
        color: "black"
        border.color: "green"
        Component.onCompleted: {llnm.get_interfaces(); netInterfaceList.currentIndex = -1;}

        ListView{
            id: netInterfaceList
            anchors.fill: parent

            model: netInterfaceListModel

            delegate: Item{
                width: netInterfaceList.width
                height: netInterfaceList.height / 4

                Rectangle{
                    anchors.fill: parent
                    color: "green"

                    Grid{
                        anchors.centerIn: parent
                        width: parent.width * 0.99
                        height: parent.height * 0.95
                        columns: 1
                        Rectangle{
                            width: parent.width
                            height: parent.height/2
                            color: netInterfaceList.currentIndex === index ? "#0D451E" : "#424242"
                            Text{
                                anchors.centerIn: parent
                                color: "green"
                                font.pixelSize: parent.width / text.length > 8 ? parent.width / text.length : 8
                                text: model.name
                                font.bold: true
                            }
                        }

                        Rectangle{
                            width: parent.width
                            height: parent.height/2
                            color: netInterfaceList.currentIndex == index ? "#0D451E" : "#424242"
                            Text{
                                anchors.centerIn: parent
                                color: "green"
                                font.pixelSize: parent.width / (text.length * 3)
                                text: model.description
                                font.bold: true
                            }
                        }
                    }
                    MouseArea{
                        anchors.fill: parent
                        onPressed:{netInterfaceList.currentIndex = index;}
                        onReleased: {interfaceDetailTitle.text = model.name; interfaceDetail.text = (model.detailInfo);}
                    }
                }
            }
        }
    }

    Rectangle{
        anchors{top: parent.top; right:parent.right}
        width: parent.width * 0.7
        height: parent.height
        color: "black"

        Text{
            id: interfaceDetailTitle
            anchors{top: parent.top; left: parent.left; leftMargin: 10}
            width: parent.width
            height: titleRect.height
            font.bold: true
            verticalAlignment: Text.AlignVCenter
            color: "green"
            opacity: 0.7
            font.pixelSize: title.font.pixelSize
        }

        Text{
            id: interfaceDetail
            anchors{top: interfaceDetailTitle.bottom; left: interfaceDetailTitle.left; leftMargin: 10; bottom: parent.bottom}
            color: "green"
            font.bold: true
            text: "";
        }

        Rectangle{
            id: reSearchBtn
            anchors{bottom: parent.bottom; left: parent.left; leftMargin: 10}
            width: parent.width/2 - 20
            height: titleRect.height
            color: "#424242"
            border.color: "green"
            radius: 5

            Text{
                anchors.centerIn: parent
                font.bold: true
                color: "green"
                text: "re-search"
            }

            MouseArea{
                anchors.fill: parent
                onPressed: {
                    parent.color = "#0D451E";
                    netInterfaceListModel.clear();
                    netInterfaceList.currentIndex = -1;
                    interfaceDetail.text = "";
                    interfaceDetailTitle.text = "";
                }
                onReleased: {parent.color = "#424242"; llnm.get_interfaces();}
            }
        }

        Rectangle{
            id: connectBtn
            anchors{bottom: parent.bottom; left: reSearchBtn.right; leftMargin: 20}
            width: parent.width/2 - 20
            height: titleRect.height
            color: "#424242"
            border.color: "green"
            radius: 5

            Text{
                anchors.centerIn: parent
                font.bold: true
                color: "green"
                text: "connect"
            }

            MouseArea{
                anchors.fill: parent
                onPressed: {parent.color = "#0D451E";}
                onReleased: {
                    if(netInterfaceList.currentIndex === -1){return;}
                    parent.color = "#424242";
                    llnm.connect_interface(netInterfaceList.currentIndex);
                }
            }
        }
    }
}
