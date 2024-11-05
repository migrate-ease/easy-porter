#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/1/4 11:05
# file: python_utils.py
import os
import re
import shutil
import subprocess

import magic

from tools.error import MyError
from tools.filter_rules import suffix_dict
from tools.utils import find_file_type_by_colon


def clear_last_log():
    """
    Determine whether the file or folder exists. If it does not exist, create it.
    param folder_path: -> string
        The absolute path of the file or folder.
    return: -> None
    """
    # 清理log
    clear_command = 'rm -rf ./*.log ./*.csv ./*.json'
    subprocess.call(clear_command, shell=True)


def execute_cmd(cmd):
    """
    Exec linux command and get result.
    param cmd:
        Linux command.
    return:
        code and result.
    """
    returncode, output = subprocess.getstatusoutput(cmd)
    return returncode, output


def create_folder(folder_path):
    """
    Create folders.
    param folder_path: -> string
        Path to the folder to be created.
    return: -> None
    """
    if not os.path.exists(folder_path):
        create_command = "mkdir -p {}".format(folder_path)
        subprocess.call(create_command, shell=True)
    return


def check_linux_command_compatibility(command):
    """
    Check Linux commands whether it is compatible on arm64 platform.
    param command -> string:
        Linux command.
    return bool
        true: compatible
        false: incompatible
    """
    if command.startswith('%s') or command.startswith('"%s"') or command.startswith("'%s'"):
        return True
    return shutil.which(command.strip("'").strip('"')) is not None


def get_py_so_result(file_path, lines):
    """
    Get the so file list in the py file.
    param file_path: -> string:
        The absolute path of the file.
    return: dict
        Return matching results.
    """
    re_str = "LoadLibrary\([\'\"](.*?)[\'\"]\)"
    result = dict()

    for nu, line in lines:
        find_list = re.findall(re_str, line, re.S)
        if find_list:
            so_path = os.path.abspath(os.path.join(os.path.split(file_path)[0], find_list[0]))
            if so_path not in result:
                result[so_path] = dict()
                result[so_path]['nu'] = list()
            result[so_path]['nu'].append(nu + 1)

    return result


def get_py_linux_command_list(lines):
    """
    Get the linux command list in the py file.
    param file_path: -> string:
        The absolute path of the file.
    return: dict
        Return matching results dict, include nu and command.
    """
    re_str_list = ["execl\([\'\"](\S*?)\s.*?[\'\"]\)", "system\([\'\"](\S*?)\s.*?[\'\"]\)",
                   "popen\([\'\"](\S*?)\s.*?[\'\"][ \)]",
                   "getstatusoutput\([\'\"](\S*?)\s.*?[\'\"].*?\)", "getoutput\([\'\"](\S*?)\s.*?[\'\"].*?\)",
                   "subprocess.call\([\'\"](\S*?)\s.*?[\'\"].*?\)", "subprocess.Popen\([\'\"](\S*?)\s.*?[\'\"].*?\)"]
    result = dict()

    for nu, line in lines:
        for re_str in re_str_list:
            find_list = re.findall(re_str, line, re.S)
            if find_list:
                command_list = [command.split(' ')[0] for command in find_list]
                result[nu] = dict()
                result[nu]['source_command'] = find_list
                result[nu]['check_command'] = command_list
    return result


def check_linux_command(command_list):
    temp = []
    for command in command_list:
        ret = check_linux_command_compatibility(command)
        if ret:
            temp.append(1)
        else:
            temp.append(0)
    if all(temp):
        return 1
    else:
        return 0


def py_from_import_pkg_list(file_path, file_lines):
    """
    Get the from import pkg list in the py file.
    param file_path: -> string:
        The absolute path of the file.
    return: list
        Return matching results.
    """
    re_str = "from (.*?) import"
    result = dict()

    for nu, line in file_lines:
        if not line.strip().startswith('from'):
            continue
        if nu not in result:
            result[nu] = dict()

        pkg_name = re.findall(re_str, line, re.S)
        if pkg_name:
            if pkg_name[0].startswith('..'):
                pkg_list = pkg_name[0].strip('..').split('.')
                pkg_path = '../' + '/'.join(pkg_name[0].strip('..').split('.')) + '.py'
            elif pkg_name[0].startswith('.'):
                pkg_list = pkg_name[0].strip('.').split('.')
                pkg_path = './' + '/'.join(pkg_name[0].strip('.').split('.')) + '.py'
            else:
                pkg_list = pkg_name[0].split('.')
                pkg_path = '/'.join(pkg_name[0].strip().split('.')) + '.py'

            pkg_path = os.path.join(os.path.split(file_path)[0], pkg_path)

            if '.' in pkg_name[0]:
                pkg_name = pkg_name[0].strip().split('.')[-1]
            else:
                pkg_name = pkg_name[0]

            result[nu]['nu'] = nu
            result[nu]['pkg_name'] = pkg_name
            result[nu]['pkg_list'] = pkg_list
            result[nu]['pkg_path'] = pkg_path
            result[nu]['line'] = line

    return result


def file_lines_no_annotation(file_path):
    """
    Get the file content filtered out of comments
    param file_path: -> string
        The absolute path of the file.
    Return:
        The file content filtered out of comments
    """
    file_lines = []
    file_line_count = 0

    try:
        with open(file_path, 'rb') as pyf:
            single_quotes_flag = False
            double_quotes_flag = False
            for nu, line in enumerate(pyf.readlines()):
                file_line_count += 1
                line = line.strip()
                if line.startswith(b'#'):
                    continue
                # 过滤空行
                if line == b'':
                    continue
                # 注释 单引号 ''' 开头
                if line.startswith(b"'''") and not single_quotes_flag:
                    single_quotes_flag = True
                # 注释 中间 和 ''' 结尾
                if single_quotes_flag is True:
                    if line.endswith(b"'''"):
                        single_quotes_flag = False
                # 注释 双引号 """ 开头
                if line.startswith(b'"""') and not double_quotes_flag:
                    double_quotes_flag = True
                # 注释 中间 和 """  结尾
                if double_quotes_flag is True:
                    if line.endswith(b'"""'):
                        double_quotes_flag = False
                else:
                    try:
                        temp_line = line.decode('utf-8')
                    except Exception:
                        temp_line = line.decode('gbk', 'ignore')
                    file_lines.append((nu + 1, temp_line))
    except FileNotFoundError as e:
        MyError().display(MyError().report(e, FileNotFoundError.__name__, "open", file_path))

    return file_lines, file_line_count


def get_file_name(file_path):
    """
    Gets the file name by the file path
    param file_path: -> string
        The absolute path of the file.
    return:
        Return real file name.
    """
    _, filename = os.path.split(file_path)
    return filename


def get_file_type(pck_path):
    """
    Gets the file type by the path
    param file_path: -> string
        The absolute path of the file.
    return
        Returns the format of the corresponding file.
    """
    suffix = pck_path.split('.')[-1]
    file_type = suffix_dict.get('.' + suffix, '')
    if file_type:
        return 0, file_type
    pck_path = pck_path.replace('$', '\$')
    check_command = 'file "{}"'.format(pck_path)
    res = execute_cmd(check_command)
    if res[0] == 0:
        file_type = find_file_type_by_colon(pck_path, res[1])
    else:
        try:
            file_type_str = magic.from_file(pck_path)
            file_type = file_type_str[: file_type_str.find(',')].strip()
        except Exception:
            file_type = 'NULL'

    return 1, file_type


def get_file_type_by_suffix(pck_path):
    suffix = pck_path.split('.')[-1]
    file_type = suffix_dict.get('.' + suffix, '')
    return file_type


def get_file_type_xarch(pck_path):
    """
    Gets the file type by the path
    param file_path: -> string
        The absolute path of the file.
    return
        Returns the format of the corresponding file.
    """
    type_dict = dict()
    suffix = pck_path.split('.')[-1]
    file_type = suffix_dict.get('.' + suffix, '')
    if file_type:
        type_dict['0'] = file_type
    check_command = 'file "{}"'.format(pck_path)
    res = execute_cmd(check_command)
    if res[0] == 0:
        file_name = os.path.split(pck_path)[1]
        type_str = res[1].split(file_name)[-1]
        file_type = type_str[1:][: type_str[1:].find(',')].strip()
        type_dict['1'] = file_type
    try:
        file_type_str = magic.from_file(pck_path)
        file_type = file_type_str[: file_type_str.find(',')].strip()
        type_dict['2'] = file_type
    except Exception:
        type_dict['2'] = 'Null'

    return type_dict


def compare_path(pkg_list, pkg_path_list):
    """
    Compare import path and py path whether consistent.
    param pkg_list: -> list
        List of import package.
    param pkg_path_list: -> list
        The absolute path list of package.
    Return: -> bool
        False: inconsistent
        True: consistent
    """
    same = False
    for pkg_path in pkg_path_list:
        pkg_path = pkg_path.split('/')
        if pkg_list == pkg_path[-1 * len(pkg_list):]:
            same = True
    return same


def compared_version(ver1, ver2):
    '''
    Compare version number
    param ver1: -> str 0.0.0
    param ver1: -> str 0.0.0.
    Return: -> int
        ver1>ver2  1
        ver1<ver2  -1
        ver1=ver20
    '''
    list1 = str(ver1).split(".")
    list2 = str(ver2).split(".")
    # 循环次数为短的列表的len
    try:
        for i in range(len(list1)) if len(list1) < len(list2) else range(len(list2)):
            if int(list1[i]) == int(list2[i]):
                pass
            elif int(list1[i]) < int(list2[i]):
                return -1
            else:
                return 1
        # 循环结束，哪个列表长哪个版本号高
        if len(list1) == len(list2):
            return 0
        elif len(list1) < len(list2):
            return -1
        else:
            return 1
    except Exception:
        return 1


def is_python_elf(file_name):
    re_str = '^python$|^python[2,3]$|^python[2,3].[1-9]$'
    python_elf = re.findall(re_str, file_name, re.S)
    if python_elf:
        return True
    return False


def create_issues(file_path, lineno, snippet, issue_type, check_type, advice=None, current_version=None):
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
                             "Need to be verified."],
        "file_broken": ["File decompression failed.",
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


def get_process_nu(migrated_count, thread_num):
    process_nu = 1
    if migrated_count >= 2:
        if thread_num >= migrated_count:
            process_nu = migrated_count
        else:
            process_nu = thread_num
    return process_nu
