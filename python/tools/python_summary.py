#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/1/9 17:25
# file: python_summary.py
import csv
import json
import os
from itertools import zip_longest

from python.tools.python_constant import Constant
from python.utils.python_utils import get_file_name
from tools.error import MyError
from tools.normalized_output import NormalizedOutput


class Summary(object):
    """
    Format output summary log
    """

    def __init__(self):
        self.output_terms = ["PROJECT", "LOCATION", "NAME", "MD5", "CATEGORY", "TYPE", "INCOMPATIBILITY",
                             "ADVICE", "UPGRADE", "PACKAGE", "VERSION", "FROM", "DOWNLOAD", "ACTION", "UNVERFIED"]  # 表头
        self.output_terms_udf = ["PROJECT", "NAME", "CATEGORY", "TYPE", "INCOMPATIBILITY",
                                 "UPGRADE", "NAME-SO", "PACKAGE", "VERSION", "ACTION", "STATUS"]  # odps 表头
        self.content = "{0:<15}: {1:<20} \n" \
                       "{2:<15}: {3:<20} \n" \
                       "{4:<15}: {5:<20} \n" \
                       "{6:<15}: {7:<20} \n" \
                       "{8:<15}: {9:<20} \n" \
                       "{10:<15}: {11:<20} \n"
        self.myerror = MyError()

    def init_csv(self, class_udf, log_type, detection_object, execution_results,
                 detection_command, execution_detection_time):
        """
        Initialize csv header
        """
        if class_udf == 'udf':
            header = [self.output_terms_udf]
        elif class_udf == 'xarch':
            header = self.get_xarch_header(detection_object, execution_results, detection_command,
                                           execution_detection_time)
            header.append(self.output_terms)
        else:
            NormalizedOutput().log_normalized_output(log_type, Constant.log_path + '.csv', detection_object,
                                                     execution_results, detection_command, execution_detection_time,
                                                     'python')
            header = [self.output_terms]
        self.write_csv_log(Constant.log_path, header)

    def get_xarch_header(self, detection_object, execution_results, detection_command, execution_detection_time):
        scanned_format_list = ["Scanned Infos:", "OBJECTS(-f/-d)", "COMMAND",
                               "EXECUTOR(whoami)", "TIME(date)"]
        summary_format_list = ["Summary:", "NOARCH", "AARCH64", "x86_64", "UNCERTAIN", "FAILED",
                               "WARNING", "TOTAL"]
        execute_format_list = ["Executed Configuration:", "NODE(uname -n)", "CPU(uname -p)",
                               "OS(lsb_release -d)", "KERNEL(uname -r)"]
        detailed_arg = "Detailed Results as Follows:"
        who_info = NormalizedOutput().get_command_result('whoami')
        node_info = NormalizedOutput().get_command_result('uname -n')
        cpu_info = NormalizedOutput().get_command_result('uname -p')
        os_info = NormalizedOutput().get_command_result('lsb_release -d').split(':')[-1].strip(' ')
        kernel_info = NormalizedOutput().get_command_result('uname -r')
        scanned_info = ["", "\n".join(detection_object), detection_command,
                        who_info, execution_detection_time]
        summary_info = ["", str(execution_results[0]), str(execution_results[1]), str(execution_results[2]),
                        str(execution_results[3]), str(execution_results[4]), str(execution_results[5]),
                        str(execution_results[6])]
        execute_info = ["", node_info, cpu_info, os_info, kernel_info]

        return [scanned_format_list, scanned_info, summary_format_list,
                summary_info, execute_format_list, execute_info, [detailed_arg]]

    def summary_content(self, summary_result, log_type, class_udf):
        """
        Classification output log
        param summary_result: -> dict
            Dictionary of log contents.
        param log_type: -> string
            The type of output log.
        param class_udf: -> string
            The flag of udf.
        param so_compatible_dict: -> dict
            The flag of -b.
        """
        if log_type == 'txt':
            self.summary_content_txt(summary_result)
        elif log_type == 'csv':
            if class_udf == 'udf':
                self.summary_content_csv_class(summary_result)
            elif class_udf == 'xarch':
                self.summary_content_csv_xarch(summary_result)
            else:
                self.summary_content_csv(summary_result)
        elif log_type == 'json':
            if class_udf == 'cs':
                self.summary_content_json_cs(summary_result)
            else:
                self.summary_content_json_normal(summary_result)

    def get_all_fields(self, summary_result, is_compatibility, category, is_zip):
        if is_zip:
            if category == -1:
                category = 'NULL'
            elif category != 1:
                category = 'P{}'.format(category)
            name_list = summary_result[1].get('name_list', [])
            advice_list = summary_result[1].get('advice_list', [])
            version_list = summary_result[1].get('version_list', [])
            package_list = summary_result[1].get('package_list', [])
            from_list = summary_result[1].get('from_list', [])
            download_list = summary_result[1].get('download_list', [])
            action_list = summary_result[1].get('action_list', [])
            unverified_list = summary_result[1].get('unverified_list', [])
        else:
            version = summary_result[1].get('version', '')
            name_list = [os.path.split(summary_result[0])[-1]] if is_compatibility == 'NO' else []
            advice_list = [summary_result[1].get('advice', '')]
            action_list = [summary_result[1].get('action', '')]
            from_list = [summary_result[1].get('type_src', '')]
            package_list = [summary_result[1].get('package', '')]
            version_list = [version]
            download_list = [summary_result[1].get('repo_url', '')]

            if is_compatibility == 'YES':
                category = '1'
            elif is_compatibility == 'TBV':
                category = 'P0'
            else:
                category = 'P2' if version and version != '\t' else 'P5'
            unverified_list = []
        return [name_list, advice_list, action_list, from_list, package_list,
                version_list, download_list, category, unverified_list]

    def summary_content_txt(self, summary_result):
        """
        Format txt output content
        param summary_result: -> dict
            Dictionary of log contents.
        """
        all_content = ''
        temp_list = list()  # 用于去重

        summary_result_lsit = sorted(summary_result.items(), key=lambda x: x[1]['sort'], reverse=False)

        for summary_result in summary_result_lsit:
            is_compatibility = summary_result[1].get('is_compatibility', '')
            if is_compatibility == 'YES':
                continue
            file_path = summary_result[0]  # LOCATION
            project = os.path.split(file_path[:file_path.rfind(os.path.sep)])[-1]  # PROJECT
            file_name = get_file_name(summary_result[0])  # NAME
            file_md5 = summary_result[1].get('md5', '')  # MD5
            if file_name + file_md5 + project in temp_list:
                continue
            temp_list.append(file_name + file_md5 + project)
            file_type = summary_result[1].get('type', '')
            category = summary_result[1].get('category', '')
            is_zip = summary_result[1].get('type', False)
            name_list, advice_list, action_list, from_list, package_list, version_list, download_list, \
                category, unverified_list = self.get_all_fields(summary_result, is_compatibility, category, is_zip)
            if category in [1, '1', 'NULL', 'P0']:
                name_list = ['NULL']
                advice_list = ['NULL']
                package_list = ['NULL']
                version_list = ['NULL']
                action_list = ['NULL']
                from_list = ['NULL']
                download_list = ['NULL']
            incompatible = ','.join(name_list)
            advice = ','.join(advice_list)
            upgrade = ','.join(name_list)
            package = ','.join(package_list)
            version = ','.join(version_list)
            type_src = ','.join(from_list)
            repo_url = ','.join(download_list)
            action = ','.join(action_list)
            unverified = ','.join(unverified_list)
            # PROJECT;LOCATION;NAME;MD5;CATEGORY;TYPE;INCOMPATIBILITY;ADVICE;UPGRADE;PACKAGE;VERSION;FROM;DOWNLOAD;ACTION;
            armcontent = ';'.join([project, file_path, file_name, file_md5, category, file_type, incompatible,
                                   advice, upgrade, package, version, type_src, repo_url, action, unverified])
            armcontent += ';\n'
            all_content += armcontent
        self.write_txt_log(Constant.log_path, all_content)

    def summary_content_csv(self, summary_result):
        """
        Format csv output content
        param summary_result: -> dict
            Dictionary of log contents.
        """
        all_content_list = []
        temp_list = list()  # 用于去重

        summary_result_list = sorted(summary_result.items(), key=lambda x: x[1]['sort'], reverse=False)

        for summary_result in summary_result_list:
            if not summary_result:
                continue
            file_type = summary_result[1].get('type', '')
            is_zip = summary_result[1].get('is_zip', False)
            file_path = summary_result[0]
            is_compatibility = summary_result[1].get('is_compatibility', '')
            if is_compatibility == 'WARNING':
                continue
            project = os.path.split(file_path[:file_path.rfind(os.path.sep)])[-1]
            file_name = get_file_name(summary_result[0])
            file_md5 = summary_result[1].get('md5', '')
            category = summary_result[1].get('category', '')
            temp_list.append(file_name + file_md5 + project)
            location = os.path.split(file_path)[0]
            name_list, advice_list, action_list, from_list, package_list, version_list, download_list, \
                category, unverified_list = self.get_all_fields(summary_result, is_compatibility, category, is_zip)
            upgrade_list = name_list
            # TBV文件嵌套层级较深时，并且文件个数比 不兼容文件多时，取值 180，防止单元格超限
            cut_nu = len(advice_list) // 180 + (1 if len(action_list) % 100 > 0 else 0) \
                if len(action_list) > len(unverified_list) else \
                len(unverified_list) // 180 + (1 if len(unverified_list) % 100 > 0 else 0)
            if category in [1, '1', 'NULL', 'P0']:
                name_list = ['NULL']
                advice_list = ['NULL']
                upgrade_list = ['NULL']
                package_list = ['NULL']
                version_list = ['NULL']
                action_list = ['NULL']
                from_list = ['NULL']
                download_list = ['NULL']

            # 防止单元格超限30000
            incom_list = self.cut_field(name_list, cut_nu)
            advice_list = self.cut_field(advice_list, cut_nu)
            upgrade_list = self.cut_field(upgrade_list, cut_nu)
            package_list = self.cut_field(package_list, cut_nu)
            version_list = self.cut_field(version_list, cut_nu)
            from_list = self.cut_field(from_list, cut_nu)
            download_list = self.cut_field(download_list, cut_nu)
            action_list = self.cut_field(action_list, cut_nu)
            unverified_list = self.cut_field(unverified_list, cut_nu)

            for csv_data in zip_longest([project], [location], [file_name], [file_md5], [category],
                                        [file_type], incom_list, advice_list, upgrade_list, package_list,
                                        version_list, from_list, download_list, action_list, unverified_list,
                                        fillvalue='NULL'):
                if not any(csv_data):
                    continue
                temp_data = list(csv_data)
                temp_data[0] = project
                temp_data[1] = location
                temp_data[2] = file_name
                temp_data[3] = file_md5
                temp_data[4] = category
                temp_data[5] = file_type
                all_content_list.append(temp_data)

        self.write_csv_log(Constant.log_path, all_content_list)

    def summary_content_csv_class(self, summary_result):
        """
        Format csv output content by class udf
        param summary_result: -> dict
            Dictionary of log contents.
        """
        all_content_list = []
        temp_list = list()  # 用于去重
        summary_result_list = sorted(summary_result.items(), key=lambda x: x[1]['sort'], reverse=False)

        for summary_result in summary_result_list:
            if not summary_result:
                continue
            is_compatibility = summary_result[1].get('is_compatibility', '')
            if is_compatibility == 'WARNING':
                continue
            file_type = summary_result[1].get('type', '')
            skip = summary_result[1].get('skip', 0)
            if skip:
                continue
            status = '0' if is_compatibility == 'ERROR' else '1'
            category = summary_result[1].get('category', '')
            file_name = get_file_name(summary_result[0])
            file_path = summary_result[0]
            project = os.path.split(file_path[:file_path.rfind(os.path.sep)])[-1]
            file_md5 = summary_result[1].get('md5', '')
            if file_path + file_md5 + project in temp_list:
                continue
            temp_list.append(file_name + file_md5 + project)
            is_zip = summary_result[1].get('is_zip', False)
            if is_zip:
                if category == -1:
                    category = 'NULL'
                elif category == 3:
                    category = 4
                name_list = summary_result[1].get('name_list', [])
                name_so_list = name_list
                version_list = summary_result[1].get('version_list', [])
                package_list = summary_result[1].get('package_list', [])
                action_list = summary_result[1].get('action_list', [])
            else:
                version = summary_result[1].get('version', '')
                if is_compatibility == 'YES':
                    category = 1
                elif is_compatibility == 'TBV':
                    category = 0
                elif is_compatibility == 'ERROR':
                    category = 'NULL'
                else:
                    category = 2 if version and version != '\t' else 5
                advice = summary_result[1].get('advice', '')
                action = summary_result[1].get('action', '')
                package = summary_result[1].get('package', '')
                name_list = [os.path.split(summary_result[0])[-1]] if is_compatibility != 'YES' else ['NULL']
                name_so_list = [advice] if not advice.startswith('Need') and advice else ['NULL']
                action_list = [action] if action else ['NULL']
                package_list = [package] if package else ['NULL']
                version_list = [version] if version and version != '\t' else ['NULL']
            upgrade = file_type
            if category in [1, 'NULL', 0] and is_zip:
                name_list = ['NULL']
                name_so_list = ['NULL']
                upgrade = 'NULL'
                package_list = ['NULL']
                version_list = ['NULL']
                action_list = ['NULL']
            # action 最长不超过 120字符，30000/120  取值250
            cut_nu = len(action_list) // 250 + (1 if len(action_list) % 100 > 0 else 0)
            # 防止单元格超限30000
            incom_list = self.cut_field(name_list, cut_nu)
            name_so_list = self.cut_field(name_so_list, cut_nu)
            version_list = self.cut_field(version_list, cut_nu)
            package_list = self.cut_field(package_list, cut_nu)
            action_list = self.cut_field(action_list, cut_nu)

            for csv_data in zip_longest([project], [file_name], [category], [file_type], incom_list, [upgrade],
                                        name_so_list, package_list, version_list, action_list, fillvalue='NULL'):
                if not any(csv_data):
                    continue
                temp_data = list(csv_data)
                temp_data[0] = project
                temp_data[1] = file_name
                temp_data[2] = category
                temp_data[3] = file_type
                temp_data[4] = temp_data[4].replace('\n', ':')
                temp_data[5] = upgrade
                temp_data.append(status)
                all_content_list.append(temp_data)

        self.write_csv_log(Constant.log_path, all_content_list)

    def summary_content_csv_xarch(self, summary_result):
        """
        Format csv output content by class udf
        param summary_result: -> dict
            Dictionary of log contents.
        """
        all_content_list = []
        temp_list = list()  # 用于去重

        summary_result_list = sorted(summary_result.items(), key=lambda x: x[1]['sort'], reverse=False)

        for summary_result in summary_result_list:
            if not summary_result:
                continue
            category = summary_result[1].get('category', '')
            if category == 'warning':
                continue
            file_type = summary_result[1].get('type', '')
            file_name = get_file_name(summary_result[0])
            file_path = summary_result[0]
            project = os.path.split(file_path[:file_path.rfind(os.path.sep)])[-1]
            file_md5 = summary_result[1].get('md5', '')
            if file_path + file_md5 + project in temp_list:
                continue
            temp_list.append(file_name + file_md5 + project)
            is_zip = summary_result[1].get('is_zip', False)
            unverified_list = []
            if is_zip:
                incom_list = summary_result[1].get('name_list', [])  # INCOMPATIBILITY
                version_list = summary_result[1].get('version_list', [])
                package_list = summary_result[1].get('package_list', [])
                action_list = summary_result[1].get('action_list', [])
                location = os.path.split(file_path)[0]
                advice_list = summary_result[1].get('advice_list', [])  # ADVICE
                upgrade_list = summary_result[1].get('upgrade_list', [])  # UPGRADE
                type_src_list = summary_result[1].get('type_src_list', [])  # FROM
                repo_url_list = summary_result[1].get('download_list', [])  # DOWNLOAD
                unverified_list = summary_result[1].get('unverified_list', [])
            else:
                incom_list = [os.path.split(summary_result[0])[-1]] if category == 'x86_64' else []
                version_list = [summary_result[1].get('version', '')]
                package_list = [summary_result[1].get('package', '')]
                action_list = [summary_result[1].get('action', '')]
                location = os.path.split(file_path)[0]
                advice_list = [summary_result[1].get('advice', '')]  # ADVICE
                upgrade_list = [summary_result[1].get('upgrade', '')]  # UPGRADE
                type_src_list = [summary_result[1].get('type_src', '')]  # FROM
                repo_url_list = [summary_result[1].get('repo_url', '')]  # DOWNLOAD
            # action 最长不超过 120字符，30000/120  取值250
            cut_nu = len(action_list) // 250 + (1 if len(action_list) % 100 > 0 else 0)
            # 防止单元格超限30000
            incom_list = self.cut_field(incom_list, cut_nu)
            advice_list = self.cut_field(advice_list, cut_nu)
            version_list = self.cut_field(version_list, cut_nu)
            upgrade_list = self.cut_field(upgrade_list, cut_nu)
            package_list = self.cut_field(package_list, cut_nu)
            from_list = self.cut_field(type_src_list, cut_nu)
            download_list = self.cut_field(repo_url_list, cut_nu)
            action_list = self.cut_field(action_list, cut_nu)
            unverified_list = self.cut_field(unverified_list, cut_nu) if unverified_list else []

            for csv_data in zip_longest([project], [location], [file_name], [file_md5], [category],
                                        [file_type], incom_list, advice_list, upgrade_list, package_list,
                                        version_list, from_list, download_list, action_list, unverified_list,
                                        fillvalue=''):
                if not any(csv_data):
                    continue
                temp_data = list(csv_data)
                temp_data[0] = project
                temp_data[1] = location
                temp_data[2] = file_name
                temp_data[3] = file_md5
                temp_data[4] = category
                temp_data[5] = file_type
                all_content_list.append(temp_data)

        self.write_csv_log(Constant.log_path, all_content_list)

    def cut_field(self, field, cut_nu):
        """
        Slice fields according to cell limitations
        param field: -> string
            Source Field String
        param cut_nu: -> int
            Slice count
        Return field_list -> list
            List of sliced strings
        """
        # action 最长不超过 120字符，30000/120 250
        field_list = []
        for i in range(cut_nu):
            field_cut = field[180 * i: 180 * (i + 1)]
            field_list.append('\n'.join(field_cut))
            if 180 * (i + 1) >= len(field):
                break
        return field_list

    def summary_content_json_cs(self, summary_result):
        """
        Format json output content
        param summary_result: -> dict
            Dictionary of log contents.
        """
        summary_dict = Constant.summary_dict_cs
        file_path = summary_result['json_info']["file_path"]
        if file_path.endswith('/'):
            file_path = file_path[:-1]
        warning_count = summary_result['json_info'].get('warning_count', 0)
        summary_dict['file_summary'] = {
            "py": {"count": summary_result['json_info']['py_file_count'],
                   "fileName": "Python SCRIPT",
                   "loc": summary_result['json_info']['py_line_count']},
            "pyc": {"count": summary_result['json_info']['pyc_file_count'],
                    "fileName": "Python COMPILED Data", "loc": 0},
            "so": {"count": summary_result['json_info']['so_file_count'],
                   "fileName": "SO/ELF Data", "loc": 0},
            "whl": {"count": summary_result['json_info']['whl_file_count'],
                    "fileName": "WHEEL Archived Data", "loc": 0},
            "egg": {"count": summary_result['json_info']['egg_file_count'],
                    "fileName": "Egg files", "loc": 0},
            "zip": {"count": summary_result['json_info']['zip_file_count'],
                    "fileName": "ZIP Archived Data", "loc": 0},
            "other": {"count": summary_result['json_info']['other_file_count'],
                      "fileName": "Other Files", "loc": 0}
        }
        summary_dict['issues'] = summary_result['json_info']["issues"]
        for issue in summary_dict['issues']:
            summary_dict['issue_summary'][issue['issue_type']['type']]['count'] += 1
        summary_dict['total_issue_count'] = len(summary_dict['issues'])
        summary_dict['root_directory'] = summary_result['json_info']['root_directory']  # -d 指定的文件夹
        summary_dict['source_dirs'] = summary_result['json_info']['source_dirs']  # root_directory下所有目录
        summary_dict['source_files'] = summary_result['json_info']['source_files']  # root下的所有检测文件
        self.write_json_log(Constant.log_path, summary_dict)

    def summary_content_json_cs_v1(self, summary_result):
        """
        Format json output content
        param summary_result: -> dict
            Dictionary of log contents.
        """
        summary_dict = Constant.summary_dict_cs
        file_path = summary_result['json_info']["file_path"]
        if file_path.endswith('/'):
            file_path = file_path[:-1]
        warning_count = summary_result['json_info'].get('warning_count', 0)
        summary_dict['file_summary'] = {
            "py": {"count": summary_result['json_info']['py_file_count'],
                   "fileName": "Python SCRIPT",
                   "loc": summary_result['json_info']['py_line_count']},
            "pyc": {"count": summary_result['json_info']['pyc_file_count'],
                    "fileName": "Python COMPILED Data", "loc": 0},
            "so": {"count": summary_result['json_info']['so_file_count'],
                   "fileName": "SO/ELF Data", "loc": 0},
            "whl": {"count": summary_result['json_info']['whl_file_count'],
                    "fileName": "WHEEL Archived Data", "loc": 0},
            "egg": {"count": summary_result['json_info']['egg_file_count'],
                    "fileName": "Egg files", "loc": 0},
            "zip": {"count": summary_result['json_info']['zip_file_count'],
                    "fileName": "ZIP Archived Data", "loc": 0},
            "other": {"count": summary_result['json_info']['other_file_count'],
                      "fileName": "Other Files", "loc": 0}
        }
        summary_dict['issues'] = summary_result['json_info']["issues"]
        for issue in summary_dict['issues']:
            summary_dict['issue_summary'][issue['issue_type']['type']]['count'] += 1
        summary_dict['issue_summary']['Warning']['count'] = warning_count
        summary_dict['total_issue_count'] = len(summary_dict['issues']) + warning_count
        summary_dict['total_issue_count'] = len(summary_dict['issues'])
        summary_dict['root_directory'] = summary_result['json_info']['root_directory']  # -d 指定的文件夹
        summary_dict['source_dirs'] = summary_result['json_info']['source_dirs']  # root_directory下所有目录
        summary_dict['source_files'] = summary_result['json_info']['source_files']  # root下的所有检测文件
        self.write_json_log(Constant.log_path, summary_dict)

    def summary_content_json_normal(self, summary_result):
        """
        Format json output content
        param summary_result: -> dict
            Dictionary of log contents.
        """
        temp_list = []
        summary_dict = Constant.summary_dict
        summary_dict['details'] = []
        summary_result_list = sorted(summary_result.items(), key=lambda x: x[1]['sort'], reverse=False)

        for summary_result in summary_result_list:
            is_compatibility = summary_result[1].get('is_compatibility', '')
            if is_compatibility == 'YES':
                continue
            file_path = summary_result[0]  # LOCATION
            project = os.path.split(file_path[:file_path.rfind(os.path.sep)])[-1]  # PROJECT
            file_name = get_file_name(summary_result[0])  # NAME
            file_md5 = summary_result[1].get('md5', '')  # MD5
            if file_name + file_md5 + project in temp_list:
                continue
            temp_list.append(file_name + file_md5 + project)
            location = file_path.split(project)[0] + project
            file_type = summary_result[1].get('type', '')  # TYPE
            is_zip = summary_result[1].get('is_zip', False)
            category = summary_result[1].get('category', '')
            if is_zip:
                if category == -1:
                    category = 'NULL'
                elif category != 1:
                    category = 'P{}'.format(category)
                name_list = summary_result[1].get('name_list', [])
                advice_list = summary_result[1].get('advice_list', [])
                version_list = summary_result[1].get('version_list', [])
                package_list = summary_result[1].get('package_list', [])
                from_list = summary_result[1].get('from_list', [])
                download_list = summary_result[1].get('download_list', [])
                action_list = summary_result[1].get('action_list', [])
            else:
                version = summary_result[1].get('version', '')
                name_list = [os.path.split(summary_result[0])[-1]] if is_compatibility == 'NO' else []
                advice_list = [summary_result[1].get('advice', '')]
                action_list = [summary_result[1].get('action', '')]
                from_list = [summary_result[1].get('type_src', '')]
                package_list = [summary_result[1].get('package', '')]
                version_list = [version]
                download_list = [summary_result[1].get('repo_url', '')]

                if is_compatibility == 'YES':
                    category = '1'
                elif is_compatibility == 'TBV':
                    category = 'P0'
                else:
                    category = 'P2' if version and version != '\t' else 'P5'
            detail_dict = dict()
            detail_dict['project'] = project
            detail_dict['location'] = location
            detail_dict['name'] = file_name
            detail_dict['md5'] = file_md5
            detail_dict['category'] = category
            detail_dict['type'] = file_type
            detail_dict['incompatibility'] = []
            if category != 'P0':
                for detail_item in zip(name_list, advice_list, name_list, package_list, version_list, from_list,
                                       download_list, action_list):
                    if not detail_item[0]:
                        continue
                    temp_dict = {
                        "item": detail_item[0],  # INCOMPATIBILITY
                        "advice": detail_item[1],  # ADVICE
                        "upgrade": detail_item[2],  # UPGRADE
                        "package": detail_item[3],  # PACKAGE
                        "version": detail_item[4],  # VERSION
                        "from": detail_item[5],  # FROM
                        "download": detail_item[6],  # DOWNLOAD
                        "action": detail_item[7],  # ACTION
                    }
                    detail_dict['incompatibility'].append(temp_dict)
            summary_dict['details'].append(detail_dict)
        self.write_json_log(Constant.log_path, summary_dict)

    def create_issues(self, file_path, lineno, snippet, issue_type, check_type, advice=None, current_version=None):
        issue_type_dict = {
            'Error': {
                "des": "FILE_BROKEN_REMARK",
                "type": "Error"
            },
            'OtherIssue': {
                "des": "TO_BE_VERIFIED_REMARK",
                "type": "OtherIssue"
            },
            'ArchSpecificLibraryIssue': {
                "des": "INCOMPATIBLE_LIBRARY_FOUND_REMARK",
                "type": "ArchSpecificLibraryIssue"
            },
            'PythonImportIssue': {
                "des": "PYTHON_IMPORT_FOUND_REMARK",
                "type": "PythonImportIssue"
            },
            'LinuxCommandIssue': {
                "des": "LINUX_COMMAND_FOUND_REMARK",
                "type": "LinuxCommandIssue"
            },
            'AppReferenceIssue': {
                "des": "FILE_NOT_FOUND_REMARK",
                "type": "AppReferenceIssue"
            },
        }
        checkpoint_dict = {
            "py_so_exists": ("Non-existent so libraries have been referred in the script.",
                             "‘so’ libraries referred must be installed in the project."),
            "py_so_compatible": ("Incompatible so libraries have been referred in the script.",
                                 "'so' libraries referred must be upgraded or compiled as compatible."),
            "py_linux_compatible": ("Invalid commands have been referred in the script.",
                                    "Commands referred must be installed in the environment."),
            "py_fi_compatible": ("Incompatible imports have been associated in the script.",
                                 "Automatically be solved with compatible imports."),
            "so_exist": ["Non-existent '{}' libraries have been here.",
                         "Need to be added with compatible 'so' libraries."],
            "so_compatible": ["Incompatible '{}' libraries have been here.",
                              "Need to be upgraded or compiled as compatible."],
            "other_compatible": ["Beyond the support types of current engine.",
                                 "Need to be verified."]
        }
        suffix = file_path.split('.')[-1]
        issue = {
            "checkpoint": checkpoint_dict[check_type][0] if not check_type.startswith('so') else checkpoint_dict[
                check_type][0].format(suffix),
            "description": checkpoint_dict[check_type][1],
            "filename": file_path,
            "issue_type": issue_type_dict[issue_type],
            "lineno": lineno,
            "current": current_version,
            "snippet": snippet,
            "advice": advice
        }
        return issue

    def write_txt_log(self, log_path, summary_content):
        """
        Format output txt document
        """
        assert isinstance(summary_content, str), 'Parameter: "summary_content" should be string.'
        try:
            with open("{}.log".format(log_path), 'a', encoding='utf-8') as f:
                f.write(summary_content + '\n')
        except FileNotFoundError as e:
            self.myerror.display(self.myerror.report(e, FileNotFoundError.__name__, "open", log_path))

    def write_csv_log(self, log_path, summary_list):
        """
        Format output csv document
        """
        assert isinstance(summary_list, list), 'Parameter: "summary_list" should be list.'

        if log_path.split('.')[-1] != 'csv':
            log_path = "{}.csv".format(log_path)
        try:
            # 在写入csv文件中，出现了乱码 使用utf_8_sig
            with open(log_path, 'a', encoding='utf_8_sig', newline="") as c:
                f_csv = csv.writer(c)
                f_csv.writerows(summary_list)
        except FileNotFoundError as e:
            self.myerror.display(self.myerror.report(e, FileNotFoundError.__name__, "open", log_path))

    def write_json_log(self, log_path, summary_dict):
        """
        Format output json document
        """
        assert isinstance(summary_dict, dict), 'Parameter: "summary_dict" should be dict.'
        # 在写入csv文件中，出现了乱码 使用utf_8_sig
        try:
            with open(log_path + '.json', 'a', encoding='utf-8') as j:
                if os.path.getsize(log_path + '.json'):
                    j.write(',\n')
                json.dump(summary_dict, j, ensure_ascii=False, indent=2)
                j.flush()
        except FileNotFoundError as e:
            self.myerror.display(self.myerror.report(e, FileNotFoundError.__name__, "open", log_path))
