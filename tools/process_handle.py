#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/7/21 15:17
# file: process_handle.py
from multiprocessing import cpu_count


class ProcessHandle(object):
    """
    Initialize the number of easyPorter processes based on the specified - n and the number of test machine CPUs
    """
    __instance = None

    def __init__(self):
        self.process_nu = 1

    def get_process_nu(self, specified_nu):
        try:
            cpu_nu = cpu_count()
            if specified_nu:
                if cpu_nu < specified_nu:
                    self.process_nu = cpu_nu
                else:
                    self.process_nu = specified_nu
            else:
                self.process_nu = cpu_nu - 1 if cpu_nu - 2 > 1 else 1

        except Exception:
            self.process_nu = 1
