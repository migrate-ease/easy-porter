#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import threading
import time


class MyLog(object):
    """
    Log Manager
    """
    _instance_lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not hasattr(MyLog, "_instance"):
            with MyLog._instance_lock:
                if not hasattr(MyLog, "_instance"):
                    MyLog._instance = object.__new__(cls)
        return MyLog._instance

    def __init__(self, log_path):
        self.log_path = log_path
        if os.path.isdir(log_path):
            if not os.path.exists(log_path):
                os.makedirs(log_path, exist_ok=True)
            self.logname = os.path.join(log_path, 'ep_{}.log'.format(time.strftime('%Y%m%d%H%M%S')))
        else:
            if self.log_path == '/apsara/easyPorter':
                if not os.path.exists(log_path):
                    os.makedirs(log_path, exist_ok=True)
            dir_path = os.path.split(log_path)[0]
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            self.logname = os.path.join('{}.log'.format(log_path))
        if not self.log_path:
            # 创建一个FileHandler，用于写到本地日志文件
            self.fh = logging.FileHandler(self.logname, encoding='utf-8')
        else:
            self.fh = logging.FileHandler(self.logname, mode='a', encoding='utf-8')

    def __console(self, level, message, engine='python'):
        if engine:
            fm = '[%(asctime)s] [{}] %(message)s'.format(engine.capitalize())
        else:
            fm = '[%(asctime)s] [Python] %(message)s'
        self.formatter = logging.Formatter(fm, datefmt='%Y-%m-%d %H:%M:%S %z')
        self.fh.setFormatter(self.formatter)
        self.fh.setLevel(logging.DEBUG)
        self.logger = logging.getLogger(self.logname)
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self.fh)
        # 判断日志级别
        if level == 'info':
            self.logger.info(message)
        elif level == 'debug':
            self.logger.debug(message)
        elif level == 'warning':
            self.logger.warning(message)
        elif level == 'error':
            self.logger.error(message)

        # removeHandler在记录日志之后移除句柄，避免日志输出重复问题
        self.logger.removeHandler(self.fh)
        # 关闭打开的文件
        self.fh.close()

    def debug(self, message, engine='python'):
        self.__console('debug', message, engine)

    def info(self, message, engine='python'):
        self.__console('info', message, engine)

    def warning(self, message, engine='python'):
        self.__console('warning', message, engine)

    def error(self, message, engine='python'):
        self.__console('error', message, engine)
