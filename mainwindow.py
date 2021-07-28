from PySide2.QtWidgets import QMainWindow, QFileDialog, QTableWidgetItem
from PySide2.QtCore import Slot
from ui_mainwindow import Ui_MainWindow
from sniffer import Sniffer

class MainWindow(QMainWindow):

    def __init__(self):
        # User Interface
        super(MainWindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.actionOpenFile.triggered.connect(self.open_file)
        # Sniffer
        self.sniffer = Sniffer()

    @Slot()
    def open_file(self):
        self.sniffer.run(QFileDialog.getOpenFileName(self, 'Open File', '.', 'BIN File (*.bin)')[0])
        self.set_table_packet(self.sniffer.get_packet())
        self.set_table_report(self.sniffer.get_report())

    def set_table_packet(self, packet:list):
        # Table
        self.ui.tableWidget_packet.clear()
        self.ui.tableWidget_packet.setColumnCount(4)
        self.ui.tableWidget_packet.setRowCount(len(packet))
        self.ui.tableWidget_packet.setHorizontalHeaderLabels(['Character', 'Decimal', 'Binary', 'Hexadecimal'])
        # Information
        for row, item in enumerate(packet):
            character = 'null' if item.character == '\x00' else item.character
            self.ui.tableWidget_packet.setItem(row, 0, QTableWidgetItem(character))
            self.ui.tableWidget_packet.setItem(row, 1, QTableWidgetItem(item.decimal))
            self.ui.tableWidget_packet.setItem(row, 2, QTableWidgetItem(item.binary))
            self.ui.tableWidget_packet.setItem(row, 3, QTableWidgetItem(item.hexadecimal))

    def set_table_report(self, report:list):
        # Table
        self.ui.tableWidget_report.clear()
        self.ui.tableWidget_report.setColumnCount(2)
        self.ui.tableWidget_report.setRowCount(len(report))
        self.ui.tableWidget_report.horizontalHeader().hide()
        self.ui.tableWidget_report.verticalHeader().hide()
        self.ui.tableWidget_report.setColumnWidth(0, 250)
        self.ui.tableWidget_report.horizontalHeader().setStretchLastSection(True)
        # Information
        for row, item in enumerate(report):
            self.ui.tableWidget_report.setItem(row, 0, QTableWidgetItem(item.name))
            self.ui.tableWidget_report.setItem(row, 1, QTableWidgetItem(item.data))