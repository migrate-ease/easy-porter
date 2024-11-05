#!/usr/bin/env python
# -*- coding: utf-8 -*-
import math
import time
import sys

from tools.constant import constant


def progress_bar(all_total_nu, total_queue, inner_queue, engine):
    """
    :param all_total_nu: Total number of all files
    :param total_queue:Message queue for all file progress
    :param inner_queue:Message queue for inner file progress
    :param engine: Current engine name
    :return:
    """
    rate_dict = {}
    # 检测对象无文件
    if all_total_nu == 0:
        progress_text = constant.standard_text.format('#' * 100, "{:<8}".format('100.00%'), 0, 0)
        print(progress_text)

    progress_text = constant.standard_text.format('_' * 100, "{:<8}".format('0.00%'), 0, all_total_nu)
    while True:
        # 当前引擎发生变化或者进度条打印标志为False时，停止进度条输出
        if engine != constant.progress_engine or not constant.schedule_tag:
            break
        # 打印上一次进度条
        loop_char(progress_text)
        # 获取外部完成个数
        finish_nu = total_queue.qsize()
        current_rate = math.floor(finish_nu / all_total_nu * 10000) / 10000 if all_total_nu != 0 else 0
        # 文件数小于100个时，统计内部进度
        if all_total_nu < 100:
            # 从队列中一次取4个数据
            for i in range(4):
                try:
                    info_item = inner_queue.get_nowait()
                    project = info_item.get('project', "")
                    rate_dict[project] = info_item
                except Exception:
                    break
            # 内部zip有进度时进行计算
            if rate_dict:
                finish_nu = total_queue.qsize()  # 重新计算长度
                current_rate = math.floor(finish_nu / all_total_nu * 10000) / 10000 if all_total_nu != 0 else 0
                # 计算rate_dict中所有zip 的总进度
                inner_current_rate = get_inner_rate(rate_dict, all_total_nu)
                current_rate = current_rate + math.floor(
                    inner_current_rate / all_total_nu * 10000) / 10000 if all_total_nu != 0 else 0
        constant.current_rate = current_rate
        progress_text = constant.standard_text.format(
            '#' * (int(constant.current_rate * 100)) + '_' * (100 - (int(constant.current_rate * 100))),
            "{:<8}".format("{:.2f}%".format(constant.current_rate * 100)),
            finish_nu,
            all_total_nu
        )
        if finish_nu == all_total_nu:
            constant.current_rate = 0.9999
            progress_text = constant.standard_text.format(
                '#' * 99 + '_' * 1,
                "{:<8}".format("99.99%"),
                all_total_nu - 1,
                all_total_nu
            )


def progress_bar_stop(all_total_nu):
    """
    Active stop progress bar
    :param all_total_nu: Total number of all files
    :return:
    """
    if constant.current_rate <= 0.6:
        differential_value = (1 - constant.current_rate) / 4
        rate_list = [constant.current_rate + differential_value * i for i in range(1, 4)]
        for current_rate in rate_list:
            progress_text = constant.standard_text.format(
                '#' * (int(current_rate * 100)) + '_' * (100 - (int(current_rate * 100))),
                "{:<8}".format("{:.2f}%".format(current_rate * 100)),
                0,
                all_total_nu
            )
            loop_char(progress_text, False)
    progress_text = constant.standard_text.format('#' * 100, "{:<8}".format('100.00%'),
                                                  all_total_nu, all_total_nu)
    progress_text += ' ' * 15
    print(progress_text)


def get_inner_rate(inner_rate_dict, all_total_nu):
    """
    Get the execution progress of all internal zip files
    :param inner_rate_dict: A dictionary that stores the progress of all internal files.
    :param all_total_nu: Total number of all files
    :return:
        current_rate: Current internal file progress
    """
    current_nu = 0
    total_nu = 0
    current_rate = 0
    for project, info_dict in inner_rate_dict.items():
        inner_total_nu = info_dict.get('total', 0)
        inner_current_nu = info_dict.get('current', 0)
        if inner_total_nu == inner_current_nu:
            continue
        current_rate += math.floor(current_nu / total_nu * 10000) / 10000 / all_total_nu if total_nu != 0 else 0
    return current_rate


def loop_char(progress_text, loop_tag=True):
    """
    Cyclic character at the end of progress bar
    :param progress_text: A string containing a progress bar.
    :param loop_tag:Whether all cycles
    :return:
    """
    if loop_tag:
        temp_loop_list = constant.loop_list
    else:
        temp_loop_list = constant.loop_list[0:5]
    for char in temp_loop_list:
        if not constant.schedule_tag:
            break
        sys.stdout.write('\r{} {}'.format(progress_text, char))
        sys.stdout.flush()
        time.sleep(0.3)
