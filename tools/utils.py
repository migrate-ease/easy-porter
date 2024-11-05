#!/usr/bin/env python3
# coding=utf-8
import copy
import hashlib
import os
import re
import subprocess
import time
from functools import partial
from pathlib import Path

import magic
import requests

from tools.constant import zip_arg, elf_suffix_list, version_key_list, sys_architecture_list, sys_list
from tools.error import MyError
from tools.filter_rules import suffix_dict, compatible_default_list, compatible_file, incompatible_default_list


def get_file_type_so(file_path):
    """
    Gets the file format type.
    param file_path: -> string
        The absolute path of the format file to be checked.
    return: -> string
        Returns the format of the corresponding file.
    """
    # Use the file command on files containing fifo special names to get the file type.
    if ("fifo" in file_path.split('/')[-1] or
            "blktype" in file_path.split('/')[-1] or
            "chrtype" in file_path.split('/')[-1]):
        file_type = get_file_real_type(file_path)

        return file_type

    try:
        file_type = get_file_real_type(file_path)

    except Exception:
        file_type = ''

    return file_type


def get_absolute_path_from_specified_path(specified_path, current_path, time_str):
    """
    If an intermediate temporary file save path is specified, get the absolute path of this path.
    param specified_path: -> string
        Path to save intermediate temporary files specified on the command line.
    param current_path: -> string
        The directory where the detection command is executed.
    param time_str: -> string
        Format the displayed timestamp.
    return: -> string
        The absolute path of the directory where the intermediate temporary files are saved.
    """
    if os.path.exists(specified_path):
        new_path = os.path.join(specified_path, "ep_tmp_{}".format(time_str))
    else:
        new_path = os.path.join(current_path, specified_path)
        mkdir_command = "mkdir -p {}".format(new_path)
        subprocess.call(mkdir_command, shell=True)

    return new_path


def get_so_project_name(so_path):
    """
    Sort so packages by package name.
    param so_path: -> dictionary
        All so filesets in the entire jar package.
    return: project -> str
        the project of so_path.
            name -> str
        Names available for queries.
    """
    project_path = os.path.split(so_path)[0]
    cpu_arch_list = ["-linux", "x86", "aarch", "-ppc",
                     "-amd", "-ia64", "-sparc", "-s390",
                     '_linux']

    so_name = so_path.split("/")[-1]
    for cpu_arch in cpu_arch_list:
        if cpu_arch in so_name:
            so_name = so_name.split(cpu_arch)[0]
    name = so_name

    name = name.rstrip('_').rstrip('-')
    if name.startswith("lib"):
        name = name[3:]
    for suffix in elf_suffix_list:
        if suffix in name:
            name = name.split(".{}".format(suffix))[0]
            break

    return project_path, name


def get_file_md5(file_path):
    """
    Get the MD5 code of the file.
    param file_path: -> string
        The absolute path of the file.
    return:
        Return md5 code of the file.
    """
    file_type = get_file_real_type(file_path)
    if 'block special' in file_type:
        return 'b0000000000000000000000000000001'
    if 'character special' in file_type:
        return 'c0000000000000000000000000000001'
    if 'socket' in file_type:
        return 's0000000000000000000000000000001'
    if 'symbolic' in file_type:
        return 'l0000000000000000000000000000001'
    if 'named pipe' in file_type:
        return 'p0000000000000000000000000000001'
    size = os.path.getsize(file_path)
    if size > 1024 * 1024:
        block_size = 1024 * 1024
    if 1024 * 100 < size < 1024 * 1024:
        block_size = 1024 * 100
    else:
        block_size = 1024

    with open(file_path, "rb") as f:
        f.seek(0)
        md5 = hashlib.md5()

        for line in chunked_file_reader(f, block_size=block_size):
            md5.update(line)

    f_md5 = md5.hexdigest()
    return f_md5


def chunked_file_reader(file, block_size=1024 * 16):
    # 首先使用 partial(fp.read, block_size) 构造一个新的无需参数的函数
    # 循环将不断返回 fp.read(block_size) 调用结果，直到其为 '' 时终止
    for chunk in iter(partial(file.read, block_size), b''):
        yield chunk


def check_aarch64_exist(file_path):
    """
    Check whether the file is similar to arm.
    param file_path:
        The absolute path of the file.
    return:
        0: Representations are all arm type files.
        1: Represents a file that is not of arm type.
    """
    arm_arg = 'aarch64'

    so_file_type = get_file_type_so(file_path)

    if arm_arg in so_file_type:
        return True

    return False


def check_x86_exist(file_path):
    """
    Check whether the file is similar to arm.
    param file_path:
        The absolute path of the file.
    return:
        0: Representations are all arm type files.
        1: Represents a file that is not of arm type.
    """
    so_file_type = get_file_type_so(file_path)

    if 'x86-64' in so_file_type:
        return True

    return False


def test_description(content):
    """
    Decorator for product testing and validation
    param content -> str
        Function Usage
    """

    def description(func):
        def exec_func():
            print('###### Function name: {} ######'.format(func.__name__))
            print('###### API description: {} ######'.format(content))
            func()

        return exec_func

    return description


def execute_cmd(cmd):
    """
    Exec linux command and get result.
    param cmd:
        Linux command.
    return:
        code and result.
    """
    p = subprocess.Popen(cmd, shell=True,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p.wait()
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        return p.returncode, stderr.decode('utf-8', 'ignore')

    return p.returncode, stdout.decode('utf-8', 'ignore')


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


def path_intersection(compatible_file, list2):
    tag = False
    for item2 in list2:
        if re.search(item2, compatible_file, re.I):
            tag = True
            break
    return tag


def ping_website(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException:
        return False


def so_name_to_search(search_so_name):
    source_name = search_so_name
    if 'lib' in search_so_name and not search_so_name.endswith('lib') and \
            not re.search('[a-zA-Z.]+lib', search_so_name, re.I):
        search_so_name = 'lib' + search_so_name.split('lib', 1)[-1]
    if '.jnilib' in search_so_name:
        search_so_name = search_so_name.split('.jnilib')[0]
    elif '.bin' in search_so_name:
        search_so_name = search_so_name.split('.bin')[0]
    elif 'dll' in search_so_name:
        search_so_name = search_so_name.split('.dll')[0]
    elif '.so' in search_so_name:
        search_so_name = search_so_name.split('.so')[0]
    elif '.a' in search_so_name:
        search_so_name = search_so_name.split('.a')[0]
    elif '.dylib' in search_so_name:
        search_so_name = search_so_name.split('.dylib')[0]
    elif '.framework' in search_so_name:
        search_so_name = search_so_name.split('.framework')[0]
    else:
        search_so_name = search_so_name.split('.', 1)[0]
    if not search_so_name:
        search_so_name = source_name
    search_so_name.rstrip('32').rstrip('64')
    re_str = "(.*?)[\=\-_\.][^a-zA-Z]\d*?\..*?"
    result = re.findall(re_str, search_so_name)
    if result and result[0]:
        search_so_name = result[0]
    return search_so_name


def get_so_tag(so_name):
    so_name = so_name.lower()
    tag = ""
    if '.lib' in so_name:
        tag = 'lib'
    elif '.jnilib' in so_name:
        tag = 'jnilib'
    elif '.bin' in so_name:
        tag = 'bin'
    elif 'dll' in so_name:
        tag = 'dll'
    elif '.so' in so_name:
        tag = 'so'
    elif '.a' in so_name:
        tag = 'a'
    elif '.dylib' in so_name:
        tag = 'dylib'
    elif '.framework' in so_name:
        tag = 'framework'
    else:
        tag = ''
    return tag


def find_file_type_by_colon(file_path, file_type_str):
    if ':' not in file_path:
        file_type = file_type_str[file_type_str.find(':') + 1: file_type_str.find(',')].strip()
    else:
        max_colon_index_path = file_path.rfind(':', 1)
        surplus_str = file_type_str[max_colon_index_path + 1:]
        file_type = surplus_str[surplus_str.find(':') + 1: surplus_str.find(',')]
    return file_type


def get_file_real_type(pck_path):
    pck_path = pck_path.replace('$', '\$')
    try:
        file_type = magic.from_file(pck_path)
    except Exception:
        check_command = 'file "{}"'.format(pck_path)
        res = execute_cmd(check_command)
        try:
            if res[0] == 0:
                file_type = find_file_type_by_colon(pck_path, res[1])
            else:
                file_type = 'NULL'
        except Exception:
            file_type = 'NULL'
    if not file_type:
        file_type = 'NULL'
    return file_type


def get_file_type_other(pck_path):
    """
    Gets the file type by the path
    param file_path: -> string
        The absolute path of the file.
    return
        Returns the format of the corresponding file.
    """
    ret = 1
    file_type = get_file_real_type(pck_path)
    if file_type == 'NULL' or file_type not in compatible_default_list:
        for suffix in suffix_dict:
            if pck_path.endswith(suffix):
                ret = 0
                file_type = suffix_dict.get(suffix)
                break
    return ret, file_type


def clear_log(log_dir_path):
    if not os.path.exists(log_dir_path):
        return
    log_path_list = os.listdir(log_dir_path)
    current_time_int = time.mktime(time.strptime(
        time.strftime('%Y%m%d%H%M%S',
                      time.localtime(int(round(time.time() * 1000)) / 1000)),
        '%Y%m%d%H%M%S'))
    time_3day3 = 3 * 24 * 3600
    time_3day3_ago = time.strftime('%Y%m%d%H%M%S', time.localtime(current_time_int - time_3day3))
    for log_path in log_path_list:
        if not re.match('ep_(output|java|python)_[0-9]{14}.log', log_path.lower()):
            continue
        time_stamp = int(log_path.split('_', -1)[-1].strip('.log'))
        if time_stamp < int(time_3day3_ago):
            real_path = os.path.join(log_dir_path, log_path)
            if os.path.exists(real_path):
                os.remove(real_path)


def read_link_src_path(file_path):
    if os.path.exists(file_path):
        file_type = get_file_real_type(file_path)
        if 'symbolic link to' in file_type.lower():
            link_path = file_type.split('symbolic link to')[-1].strip()
            file_type = read_link_src_path(link_path)
        return file_type
    else:
        return ''


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
    """
    Obtain file type based on file suffix
    :param pck_path:
    :return:
    """
    suffix = pck_path.split('.')[-1]
    file_type = suffix_dict.get("." + suffix, '')
    return file_type


def determine_unpack(file_path):
    """
    Determine whether the file belongs to a compressed package
    :param file_path:
    :return:
    """
    unpack = False
    try:
        file_path = file_path.replace('$', '\$')
        check_command = 'file "{}"'.format(file_path)
        res = execute_cmd(check_command)
        if res[0] == 0:
            file_type = find_file_type_by_colon(file_path, res[1])
        else:
            try:
                file_type_str = magic.from_file(file_path)
                file_type = file_type_str[: file_type_str.find(',')].strip()
            except Exception:
                file_type = 'NULL'
        pkg_type = file_type.split(',')[0]
        pkg_section_lower = pkg_type.lower().split(' ')
        if set(pkg_section_lower) & set(zip_arg) and get_file_type_by_suffix(file_path) not in compatible_default_list:
            unpack = True
    except Exception:
        unpack = False
    return unpack


def is_compatible(other_file, file_type_by_cmd, file_type_suffix):
    """
    Determine if the file is default compatible
    :param other_file: file path
    :param file_type_by_cmd: file xxx
    :param file_type_suffix: Obtain file types based on suffi
    :return:
    """
    file_type_suffix = file_type_suffix if file_type_suffix else ''
    result = True
    file_name = os.path.split(other_file)[-1]
    list_filter = list(filter(lambda x: x.lower() in file_type_by_cmd.lower() or x.lower() in file_type_suffix.lower()
                              and 'java' != file_type_suffix, compatible_default_list))
    # pyc 软链接文件默认兼容
    is_python_exec = re.search('python.*?byte-compiled|broken symbolic link.*?', file_type_by_cmd.lower())
    is_mf = file_name.lower() == compatible_file.lower()
    if not list_filter and not is_python_exec and not is_mf:
        result = False
    return result


def is_java_file(other_file, file_type_by_cmd, file_type_suffix):
    """
    Determine whether the file belongs to Java related files
    :param other_file: file path
    :param file_type_by_cmd: file xxx
    :param file_type_suffix: Obtain file types based on suffixes
    :return:
    """
    is_java = is_jar = is_jar_file = False
    if 'java' in file_type_by_cmd.lower():
        is_java = True
    if 'jar' in file_type_suffix.lower() or 'java' in file_type_suffix.lower():
        is_jar = True
    if other_file.endswith('.jar') or other_file.endswith('.java') or other_file.endswith('.class'):
        is_jar_file = True
    if is_java or is_jar or is_jar_file:
        return True
    return False


def check_file_incompatible(file_type_by_cmd):
    """
    Determine if the file is default incompatible
    :param file_type_by_cmd: file xxx
    :return:
    """
    get_flag = False
    for incompatible_flag in incompatible_default_list:
        if incompatible_flag in file_type_by_cmd.lower():
            get_flag = True
    return get_flag


def is_default_compatible_file(file_type_by_cmd, file_type_suffix):
    """
    Determine if the file is default compatible
    :param file_type_by_cmd: file xxx
    :param file_type_suffix: Obtain file types based on suffixes
    :return:
    """
    for compatible_type_str in compatible_default_list:
        if compatible_type_str.lower() in file_type_by_cmd or compatible_type_str in file_type_suffix:
            return True
    return False


def so_document_classification(so_dictionary):
    """
    Sort so packages by package name.
    param so_documents: -> dictionary
        All so filesets in the entire jar package.
    return: -> dictionary
        so_document_dic: A sorted set of so package files.
    """
    so_result = {}

    for project_name, so_group_dict in so_dictionary.items():
        so_result[project_name] = dict()
        for so_group, so_path_list in so_group_dict.items():
            if so_group not in so_result[project_name]:
                so_result[project_name][so_group] = list()
            for so_file in so_path_list:
                file_type = get_file_real_type(so_file)
                file_type = read_link_src_path(so_file) if 'symbolic link to' in file_type else file_type
                is_arch64, is_x86 = False, False
                if 'aarch64' in file_type:
                    is_arch64 = True
                if 'x86-64' in file_type:
                    is_x86 = True

                if is_x86 and is_arch64:
                    so_result[project_name][so_group].append('noarch')
                elif is_x86 and not is_arch64:
                    so_result[project_name][so_group].append('x86_64')
                elif not is_x86 and is_arch64:
                    so_result[project_name][so_group].append('aarch64')
                else:
                    so_result[project_name][so_group].append('uncertain')

    return so_result


def get_obj_version(obj, type):
    """
    Obtain obj version information.
    :param obj: zip/jar/so
    :param type: zip/so
    :return:
    """
    version = None
    if type == 'so':
        name_search = so_name_to_search(obj)
        other_str = obj.split(name_search)[-1]
        so_tag = get_so_tag(other_str)
        if not so_tag:
            return None
        # 获取so的版本好，正则匹配 1.0.0.so 或者*.so.1.2.3
        re_str_list = ["(\d.*?)?\.{}", "\.{}\.?(\d.*?)$"]
        for re_str in re_str_list:
            re_str = re_str.format(so_tag)
            result = re.findall(re_str, other_str, re.I)
            if result and result[0]:
                if result[0][0] and '.' in result[0][0]:
                    version = result[0][0]
    elif type == 'zip':
        if 'tar.gz' in obj:
            zip_name = obj.strip('tar.gz')
        else:
            zip_name = obj.rsplit('.', 1)[0]
        re_str = r'(\d+\.([\d\w]+\.?)+)[-_]?'
        result = re.findall(re_str, zip_name, re.I)
        if result:
            version = result[0][0]
    return version


def get_version_in_mf(mf_path):
    """
    Obtain jar version information from the MANIFEST file
    :param mf_path: MANIFEST file path
    :return: version
    """
    version = None
    try:
        with open(mf_path, 'r', encoding='utf-8') as mf:
            for line in mf:
                for version_key in version_key_list:
                    if version_key in line.lower():
                        version = line.split(':')[-1].strip()
                        break
                if version:
                    break
    except Exception as e:
        print(e)
    return version


def so_skip_by_architecture(find_str):
    """
    Determine if the current file needs to be skipped.
    :param find_str: so file name.
    :return:Bool
    """
    skip = False
    # 查找当前包含aarch64等关键信息的so是否为linux架构文件，不是则其他so不能忽略
    sys_name = re.findall('|'.join(sys_architecture_list), find_str, re.I)
    if sys_name:
        for _sys_name in sys_name:
            if re.findall('linux.{0,18}?/', _sys_name.strip('/').lower(), re.I):
                skip = True
                break
    return skip


def get_group_name(so_path):
    """
    Obtain the classification key words for the so file name
    :param so_path: the path of so file.
    :return: key words
    """
    temp_list = copy.deepcopy(sys_list)
    cpu_arch_list = []
    cpu_arch_list += temp_list
    # 32 64
    cpu_arch_list += [item + '32' for item in temp_list if item not in ['x86_64', "x86"]]
    cpu_arch_list += [item + '64' for item in temp_list if item not in ['x86_64', "x86"]]
    # -32 -64
    cpu_arch_list += ['-' + item for item in temp_list if item not in ['x86_64', "x86"]]
    cpu_arch_list += ['-' + item + '-32' for item in temp_list if item not in ['x86_64', "x86"]]
    cpu_arch_list += ['-' + item + '-64' for item in temp_list if item not in ['x86_64', "x86"]]
    # _32 _64
    cpu_arch_list += ['_' + item for item in temp_list if item not in ['x86_64', "x86"]]
    cpu_arch_list += ['_' + item + '_32' for item in temp_list if item not in ['x86_64', "x86"]]
    cpu_arch_list += ['_' + item + '_64' for item in temp_list if item not in ['x86_64', "x86"]]
    pattern = re.compile('[!@#$%^&*()+[\]{};:,/<>?\|=]')
    so_name = os.path.split(so_path)[-1]
    so_name = so_name_to_search(so_name)
    for cpu_arch in cpu_arch_list:
        if cpu_arch in so_name:
            so_name = so_name.split(cpu_arch)[0]
    name = so_name.strip()
    if name:
        name = name.rstrip('_').rstrip('-')
        if name.startswith('lib'):
            name = name[3:]
        name = name.rsplit(".", 1)[0]
        name = re.split(pattern, name)[0]
    else:
        name = os.path.split(so_path)[-1]
    return name


def tree_dir_files(path, real_path=None, initial=True):
    """
    Generate a directory tree structure for the specified directory
    :param path: the path of dir or zip.
    :param real_path: the real path of dir or zip.
    :param initial: Nesting levels of directories
    :return: Dict for tree structure
    """
    # 正则为去除路径中因同名jar解压后包含的数字后缀 _0_0等影响，某些包路径会以x86_64结尾,避免错误去除
    pattern = re.compile(r'(\.[^/.x86_64]*?)\d{1,2}_\d{1,2}(?=/)')
    real_path = pattern.sub(r'\1', real_path) if real_path else None
    if initial:
        root = path if isinstance(path, str) else str(path)
        if os.path.isdir(path):
            root_tree = tree_dir_files(root, initial=False)
            dirtree = {
                real_path if real_path else path: root_tree if root_tree else 'Y'
            }
        else:
            dirtree = {
                real_path if real_path else path: 'Y'
            }
        return dirtree

    dirtree = dict()
    p = Path(path if isinstance(path, str) else str(path))
    for ele_inner in p.iterdir():
        if ele_inner.is_dir():
            inner_tree = tree_dir_files(ele_inner, real_path, initial=False)
            dirtree[ele_inner.name] = inner_tree if inner_tree else 'Y'
        else:
            dirtree[ele_inner.name] = 'Y'

    return dirtree


def insert_children_into_node(root_node, target_path_list, zip_node, i=0):
    """
    Mount the directory tree after decompressing the zip file
    :param root_node: General directory tree structure.
    :param target_path_list: the path list of zip file.
    :param zip_node: the directory tree of zip file.
    :param i: Nesting levels of directories
    :return:Bool
    """
    if i < len(target_path_list[:-1]):
        if isinstance(root_node.get(target_path_list[i]), dict):
            return insert_children_into_node(root_node.get(target_path_list[i]), target_path_list, zip_node, i + 1)
        return False
    else:
        if '/'.join(target_path_list) in zip_node:
            root_node[target_path_list[-1]] = zip_node['/'.join(target_path_list)]
            return True
        return False


def mount_compatibility_into_node(migrated_path, issues, root_node):
    """
    Mount compatibility to dir tree.
    :param migrated_path: the path of dir which need to test.
    :param issues: incompatibile issues.
    :param root_node: General directory tree structure.
    :return:
    """
    for file_issue in issues:
        target_path_list = []
        file_path = file_issue.get('filename')
        other_path = file_path.replace(migrated_path, '')
        target_path_list = [migrated_path] + other_path.strip('/').split('/')
        snippet = file_issue.get('snippet', '').lower()
        cate_gory = 'N'
        # Error
        if 'error' in snippet or 'broken' in snippet:
            cate_gory = 'E'
        elif 'verified' in snippet:
            cate_gory = 'TBV'
        else:
            cate_gory = 'N'

        insert_compatibility_into_node(root_node, target_path_list, cate_gory)


def insert_compatibility_into_node(root_node, target_path_list, cate_gory, i=0):
    """
    Mount compatibility to dir tree.
    :param root_node: General directory tree structure.
    :param target_path_list: the path list of zip file.
    :param cate_gory: compatibility
    :param i: Nesting levels of directories
    :return:Bool
    """
    if i < len(target_path_list[:-1]):
        if isinstance(root_node.get(target_path_list[i]), dict):
            return insert_compatibility_into_node(root_node.get(target_path_list[i]), target_path_list, cate_gory, i + 1)
    else:
        if target_path_list[-1] in root_node:
            root_node[target_path_list[-1]] = cate_gory
            return True
    return False


def get_process_nu(migrated_count, thread_num):
    process_nu = 4
    if migrated_count >= 2:
        if thread_num >= migrated_count:
            process_nu = migrated_count
        else:
            process_nu = thread_num
    return process_nu


def remove_file_path_suffix(file_path):
    """
    Remove file path suffix.
    :param file_path: The specified file path
    :return: The file path after processing.
    """
    pattern = re.compile(r'(\.[^/.x86_64]*?)\d{1,2}_\d{1,2}$')
    file_path_list = file_path.split('/')
    file_path = '/'.join([pattern.sub(r'\1', item) for item in file_path_list])
    return file_path


def find_contained_elements(input_list):
    # 用于保存被包含的元素
    contained_elements = []

    # 遍历每个元素
    for current_ele in input_list:
        is_contained = False

        # 检查当前元素是否包含在其他元素中
        for compare_ele in input_list:
            if compare_ele != current_ele and current_ele in compare_ele:
                is_contained = True
                break

        # 如果当前元素是被包含的，则添加到结果列表中
        if is_contained:
            contained_elements.append(current_ele)
    if not contained_elements:
        contained_elements = input_list

    return contained_elements


def decompile_class(class_file):
    try:
        # 调用 javap 命令
        result = execute_cmd('javap -public {}|grep -oP "public .*?\..*?\s"'.format(class_file))
        # 检查是否成功
        if result[0] == 0:
            return 1, result[1]
        else:
            return 0, "Error: {}".format(result[1])
    except Exception as e:
        MyError().display(MyError().report(e, 'Javap Error',
                                           'Method: decompile_class',
                                           'Javap decompile error!'))
        return 0, str(e)


def class_result_resolution(content):
    line_list = content.split('\n')
    import_class_file_set = set()
    package = ''
    head_re = 'public.*?class'
    package_re = '(.*)\..*?'
    re_str = 'public[\w*?\s?]* (.*)\.'
    for line in line_list:
        if re.search(head_re, line):
            package_line = re.sub(head_re, '', line)
            package_line = package_line.strip().split(' ')[0]
            matching_result = re.findall(package_re, package_line)
            if matching_result:
                package = matching_result[0]
            continue
        if package and line.startswith(package) or line.startswith('static') or '<' in line:
            continue
        line = line.split('(')[0] if '(' in line else line
        line_result = re.findall(re_str, line)
        if line_result:
            import_class_file_set.add(line_result[0])
    # 去除包含的子串影响
    import_class_file_list = find_contained_elements(import_class_file_set)

    return import_class_file_list


def dir_tree_save_path_init(dir_tree_path, current_path, time_str):
    dir_tree_save_path = None
    if os.path.isfile(dir_tree_path):
        dir_path = os.path.split(dir_tree_path)[0]
        file_name = os.path.split(dir_tree_path)[1]
        dir_tree_save_path = os.path.join(dir_path, file_name.split('.json')[0] + '_{}'.format(time_str))
    else:
        if dir_tree_path:
            tree_dir_path = os.path.abspath(os.path.join(current_path, dir_tree_path))
            if tree_dir_path == '/' + dir_tree_path and '/' not in dir_tree_path:
                dir_path = current_path
                file_name = tree_dir_path.lstrip('/')
            else:
                dir_path = os.path.split(tree_dir_path)[0]
                file_name = os.path.split(tree_dir_path)[-1]

            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            temp_path = os.path.join(current_path, dir_path, 'tree_{}.json'.format(file_name))
            if os.path.exists(temp_path):
                dir_tree_save_path = os.path.join(current_path, dir_path,
                                                  'tree_{}_{}'.format(file_name, time_str))
            else:
                dir_tree_save_path = os.path.join(current_path, dir_path, 'tree_{}'.format(file_name))
        else:
            dir_tree_save_path = os.path.join(current_path, 'tree_{}'.format(time_str))
    return dir_tree_save_path
