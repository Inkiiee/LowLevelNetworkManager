import QtQuick
import QtQuick.Controls

Item {
    Rectangle{
        id: titleRect
        anchors.top: parent.top
        width: parent.width * 0.3
        height: parent.height / 8
        color: "black"
        border.color: "green"
        z: 5

        Text{
            id: title
            anchors.centerIn: parent
            color: "green"
            font.bold: true
            font.pixelSize: parent.width / text.length
            text: "Network Tasks"
            opacity: 0.5
        }
    }
    
    Rectangle{
        id: menuRect
        anchors{left: parent.left; bottom: parent.bottom; top: titleRect.bottom}
        width: titleRect.width
        height: parent.height - titleRect.height
        color: "black"
        border.color: "green"
        
        ListModel{id: menuListModel}
        ListView{
            id: menuList
            anchors.fill: parent
            model: menuListModel
            delegate: Item{
                width: menuList.width
                height: menuList.height / 7

                Rectangle{
                    anchors.fill: parent
                    color: menuList.currentIndex === index ? "#0D451E" : "#424242"
                    border.color: "green"

                    Text{
                        anchors.centerIn: parent
                        font.bold: true
                        font.pixelSize: parent.height / 4
                        color: "green"
                        text: model.text
                    }

                    MouseArea{
                        anchors.fill: parent
                        onClicked: {
                            var temp = [];
                            for(var item = menuStackView.pop(); item !== null && item.objectName !== model.text; item = menuStackView.pop()){
                                temp.push(item);
                            }
                            for(var i=0; i<temp.length; i++){
                                menuStackView.push(temp[i]);
                            }

                            if(item === null){
                                menuStackView.push(model.page);
                            }
                            else{
                                menuStackView.push(item);
                            }

                            menuList.currentIndex = index;
                        }
                    }
                }
            }
        }
        Component.onCompleted: {
            menuListModel.append({text: "Capture", page: "qrc:/capture.qml"});
            menuListModel.append({text: "Show Variable", page: "qrc:/show_vals.qml"});
            menuListModel.append({text: "Arp Spoofing", page: "qrc:/arp_spoofing.qml"});
            menuListModel.append({text: "Ping", page: "qrc:/ping.qml"});
            menuListModel.append({text: "Dns Spoofing", page: "qrc:/dns_spoofing.qml"});
            menuList.currentIndex = -1;
        }
    }

    StackView{
        id: menuStackView
        anchors{
            left: menuRect.right
            right: parent.right
            top: parent.top
            bottom: parent.bottom
        }
        initialItem: "qrc:/defaultPage.qml"
    }
}
