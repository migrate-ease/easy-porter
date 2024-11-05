#!/usr/bin/env python3
# coding=utf-8
import os

from python.tools.python_migrator import CompatibilityCheck
from tools.constant import constant
from tools.error import MyError
from tools.logger import MyLog

logger = MyLog(constant.udf_log_path)


class PythonEngine(object):

    def __init__(self):
        self.check_tool = CompatibilityCheck()

    def python_pump(self, paras_list, csv_log_path, verify_zip_list):
        """
        Start the task of checking whether packages can be shared.
        """
        try:
            ret = self.check_tool.exec_check_multithreading(paras_list, csv_log_path, verify_zip_list)
            if ret != 0 and csv_log_path:
                logger.error('Unexpected error occurred in python engine, remove [{}]'.format(csv_log_path))
                if os.path.exists(csv_log_path):
                    os.remove(csv_log_path)
        except Exception as e:
            MyError().display(MyError().report(e, 'PythonEngine', "exec_check", 'error'))
            if csv_log_path:
                logger.error('Unexpected error occurred in python engine, remove [{}]'.format(csv_log_path))
                if os.path.exists(csv_log_path):
                    os.remove(csv_log_path)
