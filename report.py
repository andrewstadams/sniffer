from collections import namedtuple

Field = namedtuple('Field', ['name', 'data'])

class Report:

    def __init__(self):
        self.report = list()

    def get(self):
        return self.report

    def append(self, name:str, data:str):
        self.report.append(Field(name, data))

    def clear(self):
        self.report.clear()