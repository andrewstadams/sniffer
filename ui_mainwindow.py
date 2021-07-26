# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'mainwindow.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(800, 600)
        self.actionOpenFile = QAction(MainWindow)
        self.actionOpenFile.setObjectName(u"actionOpenFile")
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.gridLayout = QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName(u"gridLayout")
        self.tabWidget = QTabWidget(self.centralwidget)
        self.tabWidget.setObjectName(u"tabWidget")
        self.tab_report = QWidget()
        self.tab_report.setObjectName(u"tab_report")
        self.gridLayout_report = QGridLayout(self.tab_report)
        self.gridLayout_report.setObjectName(u"gridLayout_report")
        self.tableWidget_report = QTableWidget(self.tab_report)
        self.tableWidget_report.setObjectName(u"tableWidget_report")

        self.gridLayout_report.addWidget(self.tableWidget_report, 0, 0, 1, 1)

        self.tabWidget.addTab(self.tab_report, "")
        self.tab_packet = QWidget()
        self.tab_packet.setObjectName(u"tab_packet")
        self.gridLayout_packet = QGridLayout(self.tab_packet)
        self.gridLayout_packet.setObjectName(u"gridLayout_packet")
        self.tableWidget_packet = QTableWidget(self.tab_packet)
        self.tableWidget_packet.setObjectName(u"tableWidget_packet")

        self.gridLayout_packet.addWidget(self.tableWidget_packet, 0, 0, 1, 1)

        self.tabWidget.addTab(self.tab_packet, "")

        self.gridLayout.addWidget(self.tabWidget, 0, 0, 1, 1)

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QMenuBar(MainWindow)
        self.menubar.setObjectName(u"menubar")
        self.menubar.setGeometry(QRect(0, 0, 800, 21))
        self.menuFile = QMenu(self.menubar)
        self.menuFile.setObjectName(u"menuFile")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(u"statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.menubar.addAction(self.menuFile.menuAction())
        self.menuFile.addAction(self.actionOpenFile)

        self.retranslateUi(MainWindow)

        self.tabWidget.setCurrentIndex(0)


        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"Sniffer", None))
        self.actionOpenFile.setText(QCoreApplication.translate("MainWindow", u"Open File...", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_report), QCoreApplication.translate("MainWindow", u"Report", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_packet), QCoreApplication.translate("MainWindow", u"Packet", None))
        self.menuFile.setTitle(QCoreApplication.translate("MainWindow", u"File", None))
    # retranslateUi

