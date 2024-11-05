#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import time
from tools.constant import schedule_tag


def progress_bar(all_num=1, schedule=None):
    text = "#"
    try:
        if all_num < 1:
            print(
                "\rProgress:{}{} {:.2f}% [{}/{}] Scanning        "
                "\n".format(text * 100, "_" * 0, 100.00,
                            0, 0), end='', flush=True)
        else:
            if schedule_tag is False:
                time.sleep(0.6)
                print(
                    "\rProgress:{}{} {:.2f}% [{}/{}] Scanning        "
                    "\n".format(text * 100, "_" * 0, (all_num / all_num) * 100,
                                all_num,
                                all_num), end='', flush=True)
            else:
                while schedule_tag:
                    now_num = schedule.qsize()
                    schedule_num = all_num + 1
                    if now_num < all_num:
                        print('\rProgress:{}{}| {:.2f}% [{}/{}] Scanning'.format(
                            text * (int(100 / schedule_num * now_num)),
                            "_" * (int(100 / schedule_num * (schedule_num - now_num))),
                            (now_num / schedule_num) * 100, now_num, all_num), end='')
                        for i in range(3):
                            print(".", end='', flush=True)
                            time.sleep(1)
                    else:
                        if all_num == 1:
                            print(
                                "\rProgress:{}{} {:.2f}% [{}/{}] Scanning".format(text * 90,
                                                                                  "_" * 10,
                                                                                  90, 0,
                                                                                  all_num), end='')

                        else:
                            print(
                                "\rProgress:{}{} {:.2f}% [{}/{}] Scanning".format(
                                    text * (int(100 / schedule_num * all_num)),
                                    "_" * (int(100 / schedule_num * (schedule_num - all_num))),
                                    (all_num / schedule_num) * 100,
                                    all_num - 1,
                                    all_num), end='')
                        for i in range(3):
                            print(".", end='', flush=True)
                            time.sleep(1)
                        break
    except Exception:
        time.sleep(1)
        if all_num >= 1:
            print(
                "\rProgress:{}{} {:.2f}% [{}/{}] Scanning              "
                "\n".format(text * 100, "_" * 0, (all_num / all_num) * 100,
                            all_num,
                            all_num), end='', flush=True)
        else:
            print(
                "\rProgress:{}{} {:.2f}% [{}/{}] Scanning        "
                "\n".format(text * 100, "_" * 0, 100.00,
                            0, 0), end='', flush=True)
