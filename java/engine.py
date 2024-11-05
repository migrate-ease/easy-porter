#!/usr/bin/env python3
# coding=utf-8
from java.tools.java_migrator import MigrationCheck


class JavaEngine(object):
    def __init__(self):
        self.tool = MigrationCheck()

    def java_pump(self, migrated_list):
        """
        Start the task of checking whether packages can be shared.
        param migrated_list: -> list
            Parsing results of command line arguments.
        return: -> None
        """
        csv_log_path, compressed_list = self.tool.detection_entrance(migrated_list)

        return csv_log_path, compressed_list
