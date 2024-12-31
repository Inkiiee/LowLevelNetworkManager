import QtQuick

Item {
    objectName: "Show Variable"
    Rectangle{
        anchors.fill: parent
        color: "black"
        Text{
            id: varText
            anchors.fill: parent
            color: "green"
            font.bold: true
        }
        Component.onCompleted: {
            var vars = llnm.show_variables();
            var table = llnm.show_mac_table();

            varText.text = vars + "\nMac table\n" + table;
        }
        Timer{
            repeat: true
            interval: 500
            onTriggered: {
                var vars = llnm.show_variables();
                var table = llnm.show_mac_table();

                varText.text = vars + "\nMac table\n" + table;
            }
            running: true
        }
    }
}
