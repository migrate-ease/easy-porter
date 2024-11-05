#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/2/10 18:00
# file: request_util.py
import requests

from tools.error import MyError


class MyRequests(object):
    myerror = MyError()

    def get(self, url, data, headers=None):
        try:
            r = requests.get(url, params=data, headers=headers)
            r.encoding = 'utf-8'
            json_r = r.json()
            return json_r
        except TimeoutError as e:
            self.myerror.display(self.myerror.report(e, TimeoutError.__name__, "requests", url))
            return {}
        except BaseException as e:
            self.myerror.display(self.myerror.report(e, BaseException.__name__, "requests", url))
            return {}

    def post(self, url, data, headers=None):
        try:
            r = requests.post(url, data=data, headers=headers)
            r.encoding = 'utf-8'
            json_r = r.json()
            return json_r
        except TimeoutError as e:
            self.myerror.display(self.myerror.report(e, TimeoutError.__name__, "requests", url))
            return {}
        except BaseException as e:
            self.myerror.display(self.myerror.report(e, BaseException.__name__, "requests", url))
            return {}
