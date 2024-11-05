#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/1/10 15:15
# file: python_constant.py
import os
import time


class Constant(object):
    """
    Record constant
    """
    dir_white_list = ['.idea', '.git']  # 不扫描文件夹白名单
    java_white_list = ['class', 'java', 'jar']  # python不扫描文件白名单
    zip_suffix_list = ['zip', 'tar', 'gz', 'gzip', 'jar', '(jar)']  # 压缩包格式
    python_check_type = ['py', 'so', 'zip', 'gzip', 'bz', 'xz']

    current_path = os.getcwd()
    time_str = time.strftime('%Y%m%d%H%M%S', time.localtime(int(round(time.time() * 1000)) / 1000))

    log_path = os.path.join(current_path, 'result_' + time_str + '_python')  # 不兼容-error-兼容
    save_log_path = None
    summary_dict = {}
    summary_dict_cs_v1 = {
        "arch": "aarch64",
        "branch": "",
        "commit": "",
        "errors": [],
        "file_summary": {
            "py": {
                "count": 0,
                "fileName": "",
                "loc": ""
            },
            "so": {
                "count": 0,
                "fileName": "",
                "loc": ""
            },
            "other": {
                "count": 0,
                "fileName": "",
                "loc": ""
            }
        },
        "git_repo": "",
        "issue_summary": {
            "ArchSpecificLibraryIssue": {
                "count": 0,
                "des": "INCOMPATIBLE_LIBRARY_FOUND_REMARK"
            },
            "Error": {
                "count": 0,
                "des": "FILE_BROKEN_REMARK"
            },
            "PythonImportIssue": {
                "count": 0,
                "des": "PYTHON_IMPORT_FOUND_REMARK"
            },
            "OtherIssue": {
                "count": 0,
                "des": "TO_BE_VERIFIED_REMARK"
            },
            "LinuxCommandIssue": {
                "count": 0,
                "des": "LINUX_COMMAND_FOUND_REMARK"
            },
            "AppReferenceIssue": {
                "count": 0,
                "des": "FILE_NOT_FOUND_REMARK"
            },
            "Warning": {
                "count": 0,
                "des": "FILE_IRRELEVANT_REMARK"
            }
        },
        "issue_type_config": "",
        "issues": [],
        "language_type": "Python",
        "march": "",
        "output": "",
        "progress": True,
        "quiet": False,
        "remarks": [],
        "root_directory": "",
        "source_dirs": [],
        "source_files": [],
        "target_os": "OpenAnolis",
        "total_issue_count": 0
    }
    summary_dict_cs = {
        "arch": "aarch64",
        "branch": "",
        "commit": "",
        "errors": [],
        "file_summary": {
            "py": {
                "count": 0,
                "fileName": "",
                "loc": ""
            },
            "so": {
                "count": 0,
                "fileName": "",
                "loc": ""
            },
            "other": {
                "count": 0,
                "fileName": "",
                "loc": ""
            }
        },
        "git_repo": "",
        "issue_summary": {
            "ArchSpecificLibraryIssue": {
                "count": 0,
                "des": "INCOMPATIBLE_LIBRARY_FOUND_REMARK"
            },
            "Error": {
                "count": 0,
                "des": "FILE_BROKEN_REMARK"
            },
            "PythonImportIssue": {
                "count": 0,
                "des": "PYTHON_IMPORT_FOUND_REMARK"
            },
            "OtherIssue": {
                "count": 0,
                "des": "TO_BE_VERIFIED_REMARK"
            },
            "LinuxCommandIssue": {
                "count": 0,
                "des": "LINUX_COMMAND_FOUND_REMARK"
            },
            "AppReferenceIssue": {
                "count": 0,
                "des": "FILE_NOT_FOUND_REMARK"
            }
        },
        "issue_type_config": "",
        "issues": [],
        "language_type": "Python",
        "march": "",
        "output": "",
        "progress": True,
        "quiet": False,
        "remarks": [],
        "root_directory": "",
        "source_dirs": [],
        "source_files": [],
        "target_os": "OpenAnolis",
        "total_issue_count": 0
    }
    suffix_dict = {
        'txt': '.log',
        'csv': '.csv',
        'json': '.json',
    }
