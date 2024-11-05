#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/8/30 13:42
# file: initializer.py
import os

from tools.command_parses import CommandParse as cp
from tools.constant import constant
from tools.logger import MyLog
from tools.utils import clear_log

paras_list = cp().command_parameter_parse()
# 执行过程日志
class_udf = paras_list[6]
if class_udf == 'udf':
    constant.udf_log_path = '/apsara/easyPorter'
clear_log(constant.udf_log_path)
# 自定义日志输出路径
if paras_list[14]:
    constant.udf_log_path = os.path.abspath(paras_list[14])
# 初始化监控日志
logger = MyLog(constant.udf_log_path)
constant.logger = logger
