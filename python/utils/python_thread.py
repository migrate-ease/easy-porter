#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/7/11 15:15
# file: python_thread.py
import threading
import traceback


class MyThread(threading.Thread):
    def __init__(self, target, args=()):
        self._target = target
        self._args = args
        super().__init__(target=target, args=args)
        self._result = None

    def run(self):
        try:
            self._result = self._target(*self._args)
        except Exception as e:
            print(e)
            traceback.print_exc()

    @property
    def get_result(self):
        return self._result
