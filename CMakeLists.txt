cmake_minimum_required(VERSION 3.16)

project(NetworkScanner VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Quick)

qt_standard_project_setup(REQUIRES 6.5)

qt_add_executable(appNetworkScanner
    main.cpp
)

qt_add_qml_module(appNetworkScanner
    URI NetworkScanner
    VERSION 1.0
    QML_FILES
        Main.qml
        SOURCES lowlevelnetworkmanager.h lowlevelnetworkmanager.cpp
        RESOURCES resource.qrc
        SOURCES capture.h capture.cpp
        SOURCES network_consts.h
        SOURCES network_headers.h
        SOURCES sender.h sender.cpp
        SOURCES receiver.h receiver.cpp
)

qt_add_resources(appNetworkScanner RESOURCE ./resource.qrc)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
set_target_properties(appNetworkScanner PROPERTIES
#    MACOSX_BUNDLE_GUI_IDENTIFIER com.example.appNetworkScanner
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

target_link_libraries(appNetworkScanner
    PRIVATE Qt6::Quick
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ext_libs/WpdPack/Include)
target_link_libraries(appNetworkScanner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/ext_libs/WpdPack/Lib/x64/Packet.lib
    ${CMAKE_CURRENT_SOURCE_DIR}/ext_libs/WpdPack/Lib/x64/wpcap.lib
)

include(GNUInstallDirs)
install(TARGETS appNetworkScanner
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
