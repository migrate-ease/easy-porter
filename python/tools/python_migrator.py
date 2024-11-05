#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2022/12/27 15:31
# file: python_migration.py
from __future__ import print_function

import _thread
import copy
import multiprocessing as mp
import os.path
import re
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from itertools import zip_longest

from python.tools.python_constant import Constant
from python.tools.python_summary import Summary
from python.utils.python_utils import get_file_name, get_py_linux_command_list, get_py_so_result, execute_cmd, \
    py_from_import_pkg_list, \
    file_lines_no_annotation, check_linux_command, check_linux_command_compatibility, compared_version, \
    get_file_type_by_suffix, is_python_elf, create_issues, get_process_nu
from tools.constant import constant, zip_arg
from tools.decompressor import DecompressFiles as df
from tools.error import MyError
from tools.filter_rules import python_flag, python_library_dict, specify_name, link_file, compatible_default_list, \
    compatible_file
from tools.normalized_output import NormalizedOutput
from tools.process_handle import ProcessHandle
from tools.recommendator import Recommend as rc
from tools.progress_handle import progress_bar, progress_bar_stop
from tools.sqlit_db import MySqlite
from tools.utils import get_so_project_name, get_absolute_path_from_specified_path, \
    so_name_to_search, read_link_src_path, get_file_real_type, check_aarch64_exist, get_file_md5, \
    is_compatible, check_file_incompatible, is_java_file, get_obj_version, get_version_in_mf, get_group_name, \
    tree_dir_files, insert_children_into_node, mount_compatibility_into_node, remove_file_path_suffix, \
    dir_tree_save_path_init

db_path = sys.argv[0]
current_path = os.getcwd()
logger = constant.logger


class CompatibilityCheck(object):
    """
    This is a code compatibility checking tool class.
    Mainly used to verify the specified detection object
    You can migrate directly or suggest incompatibilities
    """

    def __init__(self):
        self.root_node = {}
        self.loading = False  # 控制页面loading
        self.log_type = 'txt'
        self.engine = ''
        self.output = True
        self.recommend = True
        self.class_value = ''
        self.binary_check = False
        self.detection_command = None
        self.execution_detection_time = None
        self.warning_check = False
        self.tree_output = False
        self.dir_tree_path = None
        self.inner_log = False  # zip中检测文件的信息
        self.migrated_list = []
        self.zip_unzip_path = {}  # 存放解压后的临时文件与文件真实路径的对应关系
        self.classify_result = {}  # 存放所有压缩包解压后的分类结果
        self.not_compatibility = []  # 存放不兼容的so列表
        self.py_not_compatible_dict = dict()  # 存放不兼容的py文件
        self.py_noarch_dict = dict()
        self.py_arch64_dict = dict()
        self.py_uncertain_dict = dict()
        self.py_error_dict = dict()  # 存放存在error的py文件
        self.verify_zip_list = []  # 存放java引擎传递的待确认zip，python包需检测
        self.packages_list = []  # python内置模块与三方模块
        # --class xarch参数
        self.noarch_so_list = []
        self.arch64_so_list = []
        self.uncertain_so_list = []
        self.isolation = "\n" + '-' * 140
        self.file_num = 0
        self.total_queue = mp.Manager().Queue()
        self.tree_queue = mp.Manager().Queue()
        self.skip_list = ['jnilib', 'Windows lib', 'Windows dll', 'Mac lib']
        self.project_so_dict = dict()
        self.inner_queue = mp.Manager().Queue()

        self.time_str = time.strftime('%Y%m%d%H%M%S', time.localtime(int(round(time.time() * 1000)) / 1000 + 1))
        temp_files = os.path.expanduser('~/tmp/easyPorter')
        self.ep_temp_files = '{}/ep_tmp_{}'.format(temp_files, self.time_str)  # 存放压缩包解压后的文件

        self.db_path = "{}/data/my.db".format(db_path[:db_path.rfind(os.sep)])
        if hasattr(sys, '_MEIPASS'):
            # 如果是Pyinstaller打包后的程序，则获取临时目录路径
            self.db_path = os.path.join(sys._MEIPASS, 'my.db')

    def retrieve_all_file(self, detection_obj, zip_path='', real_zip=''):
        """
        Classify the parameter file list.
        param detection_obj: -> file/dir path
            It is the absolute path of file which need to be checked.
        return:
            so_file_path_list->(list): so file
            py_file_path_list->(list): py file
            other_file_path_list->(list): other file
        """
        file_path_list = []
        for root, dirs, files in os.walk(detection_obj):
            if self.class_value == 'cs':
                dirs[:] = [d for d in dirs if not self.skip_non_detection_dir(root, d, zip_path, real_zip)]
            for file in files:
                if not zip_path:
                    self.file_num += 1
                file_path = os.path.join(root, file)
                file_path_list.append(file_path)
        return file_path_list

    def skip_non_detection_dir(self, project, detection_dir, zip_path, real_zip):
        """
        Skip default directory detection for Mac, Windows, etc
        :param project: parent dir
        :param detection_dir: directory for detection
        :return:
        """
        if detection_dir.lower() in constant.ignored_list:
            dir_path = os.path.join(project, detection_dir)
            dir_real_path = self.get_real_path(dir_path, zip_path, real_zip)
            if zip_path:
                logger.info('Warning_ZIP4 {}.'.format(dir_real_path))
            else:
                logger.info('Warning4 {}.'.format(dir_real_path))
            return True
        return False

    def check_file_type(self, file_path, zip_path=''):
        """
        Get file types
        :param file_path: Detected file path.
        :param zip_path: Is it in the compressed package.
        :return:
            file_path -> Detected file path.
            type_nu -> Type number.
        """
        # 0 兼容，不需要检测 1 so文件 2 py文件 3 zip文件 4不兼容文件 5TBV
        type_nu = 0
        file_type = get_file_type_by_suffix(file_path)
        file_type_by_cmd = get_file_real_type(file_path)
        file_type_by_cmd = file_type_by_cmd.split(',')[0] if ',' in file_type_by_cmd else file_type_by_cmd
        file_type_lower = file_type_by_cmd.lower()
        file_name = get_file_name(file_path)
        file_suffix = '.' + file_name.split('.')[-1]

        if link_file in file_type_by_cmd:
            file_type = read_link_src_path(file_path)
        if file_name in constant.confirmed_list:
            if zip_path:
                type_nu = 0
            else:
                type_nu = 5
        elif file_suffix in constant.py_type_list or file_type == 'text':
            type_nu = 0
        elif file_type == "ELF" or file_type in constant.elf_type_list or 'elf' in file_type_lower:
            type_nu = 1
        elif file_type == 'py' and ('python script' in file_type_by_cmd.lower() or 'python2 script' in
                                    file_type_by_cmd.lower() or 'python3 script' in
                                    file_type_by_cmd.lower() or ('python' in file_type_by_cmd.lower() and
                                    'script' in file_type_by_cmd.lower())):
            type_nu = 2
        elif file_type == 'py' and 'Objective-C source' in file_type_by_cmd:
            type_nu = 2
        elif file_suffix == '.jar' and '.xml' in file_type_lower:
            type_nu = 0
        elif set(file_type_by_cmd.lower().split(' ')) & set(zip_arg) and file_type not in compatible_default_list:
            if self.class_value == 'udf':
                type_nu = 5
                if zip_path:
                    if ('jar' != file_type or 'jar' not in file_type_lower or 'java' not in file_type_lower) or \
                            self.classify_py_zip(file_name)[0]:
                        type_nu = 3
                else:
                    if os.path.abspath(file_path) in self.verify_zip_list or \
                            ('jar' != file_type or 'jar' not in file_type_lower or 'java' not in file_type_lower) or \
                            self.classify_py_zip(file_name)[0]:
                        type_nu = 3
            else:
                type_nu = 3
        elif check_file_incompatible(file_type_by_cmd):
            type_nu = 4
        elif self.python_compatible_file(file_path, file_type_by_cmd, file_type, zip_path):
            type_nu = 0
        else:
            type_nu = 5
        return file_path, type_nu

    def check_file_type_udf(self, file_path, zip_path=''):
        """
        Get file types
        :param file_path: Detected file path.
        :param zip_path: Is it in the compressed package.
        :return:
            file_path -> Detected file path.
            type_nu -> Type number.
        """
        # 0 兼容，不需要检测 1 so文件 2 py文件 3 zip文件 4不兼容文件 5TBV 6 udf不需要检测
        file_type = get_file_type_by_suffix(file_path)
        file_type_by_cmd = get_file_real_type(file_path)
        file_type_by_cmd = file_type_by_cmd.split(',')[0] if ',' in file_type_by_cmd else file_type_by_cmd
        file_type_lower = file_type_by_cmd.lower()
        file_name = get_file_name(file_path)

        if set(file_type_by_cmd.lower().split(' ')) & set(zip_arg) and file_type not in compatible_default_list:
            if zip_path:
                if ('jar' != file_type and 'jar' not in file_type_lower and 'java' not in file_type_lower) or \
                        self.classify_py_zip(file_name)[0]:
                    type_nu = 3
                else:
                    type_nu = 5
            else:
                if os.path.abspath(file_path) in self.verify_zip_list or \
                        ('jar' != file_type and 'jar' not in file_type_lower and 'java' not in file_type_lower and
                            self.classify_py_zip(file_name)[0]):
                    type_nu = 3
                else:
                    type_nu = 6
        elif is_java_file(file_path, file_type_by_cmd, file_type):
            type_nu = 6
        else:
            file_path, type_nu = self.check_file_type(file_path, zip_path)
        return file_path, type_nu

    def python_compatible_file(self, file_path, file_type_by_cmd, file_type, zip_path=''):
        """
        Determine if it is a file that is compatible with the Python engine by default.
        :param file_path: Specify file.
        :param file_type_by_cmd: file_type.
        :param file_type: Obtain file types based on file suffixes.
        :param zip_path: Is it in the compressed package.
        :return: Bool
        """
        if (self.class_value == 'udf' and self.binary_check and
                ('java' in file_type_by_cmd.lower() or 'jar' in file_type.lower() or 'java' == file_type)):
            return True
        elif file_type == 'java' or 'java class data' in file_type_by_cmd.lower() or 'java source' in file_type_by_cmd.lower():
            return False
        elif is_compatible(file_path, file_type_by_cmd, file_type):
            return True
        if zip_path.endswith('.jar') and 'c source' in file_type_by_cmd.lower() and file_type == 'text':
            return True
        return False

    def classify_files(self, detection_obj, file_path_list, class_t, zip_path=''):
        """
        Classify the parameter file list.
        param detection_obj(str): -> It is the absolute path of file which need to be checked.
              file_path_list(list): -> List of files in the specified folder/file.
              class_t(ThreadPoolExecutor): -> The specified thread pool.
              zip_path(str): -> Is it in the compressed package.
        return:
            compatible_list->(list): default compatible files
            so_list->(list): so files
            py_list->(list): py files
            compress_list->(list): zip files
            incompatible_list->(list): incompatible files
            tbv_list->(list): default to be verified files
        """
        mf_path = ""
        compatible_list = []
        so_list = []
        py_list = []
        compress_list = []
        incompatible_list = []
        tbv_list = []
        skip_list = []
        file_num = len(file_path_list)
        if file_num:
            if self.class_value == 'udf':
                tasks = [class_t.submit(self.check_file_type_udf, file_path, zip_path) for file_path in file_path_list]
            else:
                tasks = [class_t.submit(self.check_file_type, file_path, zip_path) for file_path in file_path_list]
            for task in as_completed(tasks):
                file_path, type_nu = task.result()
                relative_path = file_path
                if os.path.isdir(detection_obj):
                    relative_path = file_path.replace(detection_obj, '').lstrip('/')
                if type_nu == 0:
                    compatible_list.append(relative_path)
                elif type_nu == 1:
                    so_list.append(file_path)
                elif type_nu == 2:
                    py_list.append(file_path)
                elif type_nu == 3:
                    compress_list.append(file_path)
                elif type_nu == 4:
                    incompatible_list.append(relative_path)
                elif type_nu == 6:
                    skip_list.append(file_path)
                else:
                    tbv_list.append(relative_path)
                if compatible_file in file_path:
                    mf_path = file_path

        return [compatible_list, so_list, py_list, compress_list, incompatible_list, tbv_list, skip_list, mf_path]

    def so_directory_pretreatment(self, so_list, zip_file=None, real_zip=None):
        """
        So files Preprocessing
        :param so_list: So file list
        :param zip_file: Is it in the compressed package.
        :param real_zip: The real path of zip.
        :return: new_so_list->(list) Processed file list.
        """
        new_so_list = []
        parent_project_so = self.so_project_classification(so_list)
        for parent_project, so_group_dict in parent_project_so.items():
            for so_group, so_path_list in so_group_dict.items():
                find_so = False
                # 根据优先级顺序查找
                temp_so_list = []
                for architecture in constant.architecture_priority:
                    for so_path in so_path_list:
                        find_str = so_path
                        if zip_file:
                            find_str = so_path.replace(zip_file, '')
                        if re.findall(architecture, find_str, re.I):
                            skip = self.so_skip_by_architecture(find_str)
                            if skip:
                                continue
                            so_path_list.remove(so_path)
                            self.skip_warning2_so(so_path_list, zip_file, real_zip)
                            temp_so_list.append(so_path)
                            find_so = True
                            break
                    if find_so:
                        break
                if not temp_so_list:
                    temp_so_list = so_path_list
                new_so_list += temp_so_list
        new_so_list = self.skip_warning3_so(new_so_list, zip_file, real_zip)
        return new_so_list

    def so_project_classification(self, so_list):
        """
        Sort so files according to directory.
        :param so_list:So file list
        :return:parent_project_so->(dict) Classified dictionary.
        """
        parent_project_so = dict()
        for so_path in so_list:
            so_name_group = get_group_name(so_path)
            parent_project = os.path.split(so_path)[0]
            # 查找路径中包含 系统架构的路径
            sys_name = re.findall('|'.join(constant.sys_architecture_list), so_path, re.I)
            if sys_name:
                parent_project = so_path.split(sys_name[0])[0].rstrip('/')
            if parent_project not in parent_project_so:
                parent_project_so[parent_project] = dict()
            if so_name_group not in parent_project_so[parent_project]:
                parent_project_so[parent_project][so_name_group] = []
            parent_project_so[parent_project][so_name_group].append(so_path)
        return parent_project_so

    def so_skip_by_architecture(self, find_str):
        """
        Determine if the current file needs to be skipped.
        :param find_str: so file name.
        :return:Bool
        """
        skip = False
        # 查找当前包含aarch64等关键信息的so是否为linux架构文件，不是则其他so不能忽略
        sys_name = re.findall('|'.join(constant.sys_architecture_list), find_str, re.I)
        if sys_name:
            for _sys_name in sys_name:
                if re.findall('linux.{0,18}?/', _sys_name.strip('/').lower(), re.I):
                    skip = True
                    break
        return skip

    def skip_warning2_so(self, so_path_list, zip_file, real_zip):
        """
        Output warning2 information.
        :param so_path_list: List of files to be processed
        :param zip_file:Is it in the compressed package.
        :param real_zip:The real path of zip.
        """
        for so_path in so_path_list:
            so_path = self.get_real_path(so_path, zip_file, real_zip)
            if zip_file:
                logger.info('Warning_ZIP2 {}'.format(so_path))
            else:
                logger.info('Warning2 {}'.format(so_path))
                self.total_queue.put(1)

    def skip_warning3_so(self, so_path_list, zip_file, real_zip):
        """
        Output warning3 information.
        :param so_path_list: List of files to be processed
        :param zip_file:Is it in the compressed package.
        :param real_zip:The real path of zip.
        :return: temp_list->(list) Processed file list.
        """
        # -w下过滤与arm架构无关的文件
        temp_list = copy.deepcopy(so_path_list)
        for so_path in so_path_list:
            file_type = get_file_type_by_suffix(so_path)
            if file_type in self.skip_list:
                real_path = so_path
                if zip_file:
                    real_path = self.get_real_path(so_path, zip_file, real_zip)
                    logger.info('Warning_ZIP3 {}'.format(real_path))
                else:
                    logger.info('Warning3 {}'.format(real_path))
                    self.total_queue.put(1)
                temp_list.remove(so_path)
        return temp_list

    def recommend_by_so(self, so_file_path, mysql):
        """
        Use the incompatible so to search the corresponding version in the database.
        param mysql: -> function
            The created mysql object.
        param so_file_path: -> string
            Absolute path to incompatible so.
        return search_result: -> dictionary
            The result of searching the database through incompatible so.
        """
        type_src = ""
        version = ""
        upgrade = ""
        package = ""
        repo_url = ""
        pip_install_name = ''
        minversion = ""
        table_name = 'python3'
        py2_flag = ['py2', 'cp27', 'python2', 'lib-dynload']
        so_file_name = os.path.split(so_file_path)[-1]
        so_file_path = so_file_path.replace(self.ep_temp_files, '')
        res, flag = self.classify_py_zip(so_file_path)
        if res:
            # 处理路径，删除其他影响判断的字符
            if 'site-packages' in so_file_path:
                so_file_path = so_file_path.split('site-packages')[-1]
            # 识别python2、3
            for flag in py2_flag:
                if flag in so_file_path.lower():
                    table_name = 'python2'
                    break
            elf_so_name = ""
            sql_so_s = "SELECT minversion, version, snippet, name, repo_url FROM {} WHERE elf LIKE {} OR elf LIKE {};"
            if table_name == 'python3':
                if 'cpython' in so_file_name and 'x86_64' in so_file_name:
                    start = so_file_name.rfind('cpython')
                    end = so_file_name.rfind('x86_64')
                    replace_str = so_file_name[start: end]
                    elf_so_name = so_file_name.replace(replace_str, 'cpython-36m-')

            so_name_like = '"%%;{}%%"'.format(elf_so_name if elf_so_name else so_file_name)
            so_name_like2 = '"%%{};%%"'.format(elf_so_name if elf_so_name else so_file_name)
            sql_so = sql_so_s.format(table_name, so_name_like, so_name_like2)
            result = mysql.search_one(sql_so)
            if not result and table_name == 'python3':
                sql_so = sql_so_s.format('python2', so_name_like, so_name_like2)
                result = mysql.search_one(sql_so)
            if result:
                version = result[1]
                minversion = result[0]
                repo_url = result[4]
                version = self.get_version(version, minversion, repo_url)
                upgrade = so_file_name
                pip_install_name = result[3]
                package = pip_install_name
                type_src = 'Yum'

        if not version and not upgrade:
            sql_so7 = "SELECT version, repo_url, snippet, minversion, lib FROM so_el7 WHERE name like ?;"
            sql_so8 = "SELECT version, repo_url, snippet, minversion, lib FROM so_el8 WHERE name like ?;"
            # udf使用el7
            so_name_deal = so_name_to_search(so_file_name)
            search_so_name = "{}%%".format(so_name_deal)
            if self.class_value:
                result = rc().recommend_by_so(sql_so7, mysql, search_so_name)
            else:
                result = rc().recommend_by_so(sql_so8, mysql, search_so_name)
            if result:
                version = result[0]
                minversion = result[3]
                repo_url = result[1]
                version = self.get_version(version, minversion, repo_url)
                version_source = int(result[2]) if result[2] else None
                package = result[4]
                type_src = rc().check_type_src(version_source)
        advice_str = NormalizedOutput().get_advice_str(minversion, version, repo_url)
        advice = advice_str[1] if advice_str else ''
        advice_level = advice_str[0] if advice_str else 0
        action = NormalizedOutput().get_action_str(advice_level, minversion, version, pip_install_name, 'python')
        search_result = {
            "version": '{}\t'.format(version),
            "advice": advice,
            "action": action,
            "repo_url": repo_url if repo_url else '',
            "package": package if package else '',
            "type_src": type_src,
        }
        return search_result

    def get_version(self, version, minversion, repo_url):
        """
        Get version string
        :param version: Recommended version
        :param minversion: Recommended min version
        :param repo_url: Recommended download url.
        :return: version string
        """
        version_str = ''
        if version:
            version_str = version
        elif minversion:
            version_str = minversion
        elif repo_url:
            version_str = repo_url
        return version_str

    def get_real_path(self, file_path, zip_file, real_zip):
        """
        Obtain the real path of the file
        :param file_path: Extract the file path to the temporary directory.
        :param zip_file:Is it in the compressed package.
        :param real_zip:The real path of zip.
        :return:
        """
        real_path = file_path
        if zip_file and not real_zip:
            real_path = file_path.replace(self.ep_temp_files, os.path.split(zip_file)[0])
        if real_zip:
            real_path = file_path.replace(self.ep_temp_files, os.path.split(real_zip)[0])
        real_path = self.remove_file_path_suffix(real_path)
        return real_path

    def remove_file_path_suffix(self, file_path):
        """
        Remove file path suffix.
        :param file_path: The specified file path
        :return: The file path after processing.
        """
        pattern = re.compile(r'(\.[^/.x86_64]*?)\d{1,2}_\d{1,2}$')
        file_path_list = file_path.split('/')
        file_path = '/'.join([pattern.sub(r'\1', item) for item in file_path_list])
        return file_path

    def check_so_file(self, so_file, zip_file=None, real_zip=None, zip_version=None):
        """
        Detect so files
        param so_file: -> str
            The absolute path of the so file.
        param zip_file: -> str
            The absolute path of the zip file which contains the so file.
        return:
            Returns the information dictionary of so files
        """
        result = dict()
        try:
            so_file.encode('utf-8')
            if not zip_file:
                logger.info('Began {}'.format(so_file))
        except Exception:
            so_file = so_file.encode('utf-8', 'ignore').decode('utf-8', 'ignore') + '?'
            if not zip_file:
                result['md5'] = constant.broken_file_md5
                self.total_queue.put(1)
                logger.info('Began {}'.format(so_file))
                logger.info('Ended {}'.format(so_file))
            return {}

        real_path = self.get_real_path(so_file, zip_file, real_zip)
        python_elf = False
        if 'python' in so_file:
            python_elf = is_python_elf(so_file)
        if python_elf:
            logger.warning('Skipped {}:Python executable file.'.format(real_path))
        else:
            file_name = get_file_name(so_file)
            current_version = get_obj_version(file_name, 'so')
            if not current_version and zip_version:
                current_version = zip_version
            result['current_version'] = current_version
            result['file_path'] = so_file
            file_type = get_file_real_type(so_file)
            file_type = read_link_src_path(so_file) if 'symbolic link to' in file_type else file_type
            if not zip_file:
                result['md5'] = get_file_md5(so_file)
            project_path, so_name = get_so_project_name(so_file)
            if project_path not in self.project_so_dict:
                self.project_so_dict[project_path] = dict()
            if so_name not in self.project_so_dict[project_path]:
                self.project_so_dict[project_path][so_name] = []
            result['type'] = file_type.split(',')[0] if ',' in file_type else file_type
            result['file_path'] = so_file
            result['real_path'] = real_path
            check_result = check_aarch64_exist(so_file)
            if check_result or 'ascii text' in file_type.lower():
                self.project_so_dict[project_path][so_name].append(1)
                result['is_compatibility'] = 'YES'
                result['sort'] = 3
            else:
                self.project_so_dict[project_path][so_name].append(0)
                self.not_compatibility.append(so_file)
                result['is_compatibility'] = 'NO'
                result['sort'] = 2

        if not zip_file:
            self.total_queue.put(1)
            logger.info('Ended {}'.format(so_file))
        else:
            self.inner_path_print(real_path)

        return result

    def check_so_file_xarch(self, so_file, zip_file=None, real_zip=None):
        """
        Detect so files xarch
        param so_file: -> str
            The absolute path of the so file.
        return:
            Returns the information dictionary of so files
        """
        result = dict()
        try:
            so_file.encode('utf-8')
            if not zip_file:
                logger.info('Began {}'.format(so_file))
        except Exception:
            so_file = so_file.encode('utf-8', 'ignore').decode('utf-8', 'ignore') + '?'
            if not zip_file:
                result['md5'] = constant.broken_file_md5
                self.total_queue.put(1)
                logger.info('Began {}'.format(so_file))
                logger.info('Ended {}'.format(so_file))
            else:
                real_path = self.get_real_path(so_file, zip_file, real_zip)
                self.inner_path_print(real_path)
            return {}

        real_path = self.get_real_path(so_file, zip_file, real_zip)
        python_elf = False
        if 'python' in so_file:
            python_elf = is_python_elf(so_file)
        if python_elf:
            logger.warning('Skipped {}:Python executable file.'.format(real_path))
        else:
            result['file_path'] = so_file
            file_type = get_file_real_type(so_file)
            file_type = read_link_src_path(so_file) if 'symbolic link to' in file_type else file_type
            if not zip_file:
                result['md5'] = get_file_md5(so_file)
            project_path, so_name = get_so_project_name(so_file)
            if project_path not in self.project_so_dict:
                self.project_so_dict[project_path] = dict()
            if so_name not in self.project_so_dict[project_path]:
                self.project_so_dict[project_path][so_name] = []
            result['type'] = file_type.split(',')[0] if ',' in file_type else file_type
            result['file_path'] = so_file
            result['real_path'] = real_path
            result['so_name'] = so_name
            is_arch64, is_x86 = False, False
            if 'aarch64' in file_type:
                is_arch64 = True
            if 'x86-64' in file_type:
                is_x86 = True

            if is_x86 and is_arch64:
                self.noarch_so_list.append(so_file)
                self.project_so_dict[project_path][so_name].append('noarch')
                result['category'] = 'noarch'  # 既支持aarch64也支持x86
                result['sort'] = 4
            elif is_x86 and not is_arch64:
                self.not_compatibility.append(so_file)
                self.project_so_dict[project_path][so_name].append('x86_64')
                result['category'] = 'x86_64'  # 仅支持x86_64
                result['sort'] = 2
            elif not is_x86 and is_arch64:
                self.arch64_so_list.append(so_file)
                self.project_so_dict[project_path][so_name].append('aarch64')
                result['category'] = 'aarch64'  # 仅支持aarch64
                result['sort'] = 3
            else:
                self.uncertain_so_list.append(so_file)
                self.project_so_dict[project_path][so_name].append('uncertain')
                result['category'] = 'uncertain'  # 无法判断
                result['sort'] = 1

        if not zip_file:
            logger.info('Ended {}'.format(so_file))
            self.total_queue.put(1)
        else:
            self.inner_path_print(real_path)
        return result

    def recommand_by_zip_flag(self, zip_flag, table_name, mysql):
        """
        Recommend based on the compressed file name
        :param zip_flag: Recognized Python keywords
        :param table_name: python2/python3
        :param mysql: Database Connection
        :return:
        """
        sql_so_s = "SELECT minversion, version, snippet, name, repo_url FROM {} WHERE name = ?;".format(table_name)
        result = mysql.search_one(sql_so_s, (zip_flag,))
        if result:
            return True, result
        return False, tuple()

    def check_py_file(self, py_file, zip_file=None, real_zip=None):
        """
        Detect py files
        param py_file: -> str
            The absolute path of the py file.
        return:
            Returns the information dictionary of py files
        """
        result = dict()
        try:
            py_file.encode('utf-8')
            if not zip_file:
                logger.info('Began {}'.format(py_file))
        except Exception:
            py_file = py_file.encode('utf-8', 'ignore').decode('utf-8', 'ignore') + '?'
            if not zip_file:
                result['md5'] = constant.broken_file_md5
                self.log_print(result)
                self.total_queue.put(1)
                logger.info('Began {}'.format(py_file))
                logger.info('Ended {}'.format(py_file))
            return {}
        result['file_path'] = py_file
        if not zip_file:
            result['md5'] = get_file_md5(py_file)
        file_type = get_file_real_type(py_file)
        real_path = self.get_real_path(py_file, zip_file, real_zip)
        result['type'] = file_type.split(',')[0] if ',' in file_type else file_type
        result['real_path'] = real_path
        file_lines, file_line_count = file_lines_no_annotation(py_file)
        result['file_line_count'] = file_line_count
        fi_result = py_from_import_pkg_list(py_file, file_lines)
        so_file_result, incompatible, error = self.py_so_file_path_list(real_path, file_lines)
        linux_command_dict = get_py_linux_command_list(file_lines)
        del file_lines
        result['fi_result'] = fi_result
        check_so_result = self.py_so_error_issues(real_path, so_file_result)
        check_linux_result = self.py_so_other_issues(real_path, linux_command_dict)
        result['advice'] = check_so_result[0] + check_linux_result[0]
        if self.log_type == 'json':
            result['issues'] = check_so_result[1] + check_linux_result[1]
        file_name = get_file_name(py_file)
        if error:
            if file_name not in self.py_error_dict:
                self.py_error_dict[file_name] = list()
            self.py_error_dict[file_name].append(py_file)
            result['is_compatibility'] = 'ERROR'
            result['sort'] = 0
        elif incompatible or check_linux_result[0]:
            if file_name not in self.py_not_compatible_dict:
                self.py_not_compatible_dict[file_name] = list()
            self.py_not_compatible_dict[file_name].append(py_file)
            result['is_compatibility'] = 'NO'
            result['sort'] = 2
        else:
            result['is_compatibility'] = 'YES'
            result['sort'] = 3
        del check_so_result, check_linux_result
        return result

    def check_py_file_xarch(self, py_file, zip_file=None, real_zip=None):
        """
        Detect py files xarch
        param py_file: -> str
            The absolute path of the py file.
        return:
            Returns the information dictionary of py files
        """
        result = dict()
        try:
            py_file.encode('utf-8')
            if not zip_file:
                logger.info('Began {}'.format(py_file))
        except Exception:
            py_file = py_file.encode('utf-8', 'ignore').decode('utf-8', 'ignore') + '?'
            if not zip_file:
                result['md5'] = constant.broken_file_md5
                self.log_print(result)
                self.total_queue.put(1)
                logger.info('Began {}'.format(py_file))
                logger.info('Ended {}'.format(py_file))
            else:
                real_path = self.get_real_path(py_file, zip_file, real_zip)
                self.inner_path_print(real_path)
            return {}
        result['file_path'] = py_file
        if not zip_file:
            result['md5'] = get_file_md5(py_file)

        file_type = get_file_real_type(py_file)
        # 获取每个文件中包含的 from import 包
        file_lines, file_line_count = file_lines_no_annotation(py_file)
        result['py_line_count'] = file_line_count
        fi_result = py_from_import_pkg_list(py_file, file_lines)
        result['type'] = file_type.split(',')[0] if ',' in file_type else file_type
        result['fi_result'] = fi_result
        real_path = self.get_real_path(py_file, zip_file, real_zip)
        result['real_path'] = real_path
        # 判断py中的so
        category_list = self.py_so_file_path_list_xarch(py_file, file_lines)

        # 判断 linux命令 是否兼容 uname -m
        temp_list = []
        linux_command_dict = get_py_linux_command_list(file_lines)
        del file_lines
        for nu, item in linux_command_dict.items():
            command_list = item['check_command']
            ret = check_linux_command(command_list)
            linux_command_dict[nu]['category'] = ret
            temp_list.append(ret)

        if all(temp_list):
            category_list.append('noarch')
        else:
            category_list.append('uncertain')
        result['category_list'] = category_list
        file_name = get_file_name(py_file)
        if 'failed' in category_list:
            if file_name not in self.py_error_dict:
                self.py_error_dict[file_name] = list()
            self.py_error_dict[file_name].append(py_file)
        elif list(set(category_list)) == ['x86_64']:
            if file_name not in self.py_not_compatible_dict:
                self.py_not_compatible_dict[file_name] = list()
            self.py_not_compatible_dict[file_name].append(py_file)
        elif list(set(category_list)) == ['aarch64']:
            if file_name not in self.py_arch64_dict:
                self.py_arch64_dict[file_name] = list()
            self.py_arch64_dict[file_name].append(py_file)
        elif list(set(category_list)) == ['noarch']:
            if file_name not in self.py_noarch_dict:
                self.py_noarch_dict[file_name] = list()
            self.py_noarch_dict[file_name].append(py_file)
        else:
            if file_name not in self.py_uncertain_dict:
                self.py_uncertain_dict[file_name] = list()
            self.py_uncertain_dict[file_name].append(py_file)
        return result

    def check_py_pkg_import(self, py_result, zip_file=None):
        """
        Detect package which was from imported in py file
        param py_result: -> dict
            The result of detected py files.
        return:
             Returns the result of py file which was error or incompatible, and issues info.
        """
        # 3. 检测py中from import 是否引用error/incompatible的py
        issues = []
        advices = []
        fi_result = py_result.get('fi_result', {})
        real_path = py_result.get('real_path', {})
        is_compatibility = py_result.get('is_compatibility')
        if is_compatibility != 'YES':
            issues += py_result.get('issues', [])
        if fi_result:
            for nu in fi_result:
                pkg_path = fi_result[nu].get('pkg_path', '')
                pkg_list = fi_result[nu].get('pkg_list', '')
                if not pkg_path:
                    continue
                pkg_name = fi_result[nu].get('pkg_name', '') + '.py'
                line = fi_result[nu].get('line', '')

                if pkg_name in self.py_not_compatible_dict:
                    pkg_path_list = self.py_not_compatible_dict[pkg_name]
                    incompatible = self.compare_path(pkg_list, pkg_path, pkg_path_list)
                    if incompatible:
                        py_result['is_compatibility'] = 'NO'
                        reason = '[Import Package Incompatible] @ line {}: {};'.format(nu, line)
                        advices.append(reason)
                        issues.append(Summary().create_issues(real_path, nu, reason, 'PythonImportIssue',
                                                              'py_fi_compatible'))

                elif pkg_name in self.py_error_dict:
                    pkg_path_list = self.py_error_dict[pkg_name]
                    error = self.compare_path_error(pkg_list, pkg_path, pkg_path_list)
                    if error:
                        py_result['is_compatibility'] = 'ERROR'
                        reason = '[Import Package Error] @ line {}: {};'.format(nu, line)
                        advices.append(reason)
                        issues.append(Summary().create_issues(real_path, nu, reason, 'PythonImportIssue',
                                                              'py_fi_compatible'))
        del py_result["fi_result"]
        py_result['issues'] = issues
        advices += py_result.get('advice', [])
        py_result['advice'] = ''.join(advices) if advices else ''
        if not zip_file:
            self.log_print(py_result)
            self.total_queue.put(1)
            logger.info('Ended {}'.format(real_path))
        else:
            self.inner_path_print(real_path)

        return py_result

    def check_py_pkg_import_xarch(self, py_result, zip_file=None):
        """
        Detect package which was from imported in py file xarch
        param py_result: -> dict
            The result of detected py files.
        return:
             Returns the result of py file which was error or incompatible, and issues info.
        """
        # 3. 检测py中from import 是否引用error/incompatible的py
        fi_result = py_result.get('fi_result', {})
        category_list = py_result.get('category_list', [])
        real_path = py_result.get('real_path', {})

        if fi_result:
            for nu in fi_result:
                pkg_list = fi_result[nu].get('pkg_list', '')
                pkg_path = fi_result[nu].get('pkg_path', '')
                if not pkg_path:
                    continue
                pkg_name = fi_result[nu].get('pkg_name', '') + '.py'

                temp_category = 'noarch'
                if pkg_name in self.py_not_compatible_dict:  # x86
                    pkg_path_list = self.py_not_compatible_dict[pkg_name]
                    is_x86 = self.compare_path(pkg_list, pkg_path, pkg_path_list)
                    if is_x86:
                        temp_category = 'x86_64'
                elif pkg_name in self.py_arch64_dict:  # aarch64
                    pkg_path_list = self.py_arch64_dict[pkg_name]
                    is_arch64 = self.compare_path(pkg_list, pkg_path, pkg_path_list)
                    if is_arch64:
                        temp_category = 'aarch64'
                elif pkg_name in self.py_noarch_dict:  # aarch64
                    pkg_path_list = self.py_noarch_dict[pkg_name]
                    is_noarch = self.compare_path(pkg_list, pkg_path, pkg_path_list)
                    if is_noarch:
                        temp_category = 'noarch'
                elif pkg_name in self.py_uncertain_dict:  # aarch64
                    pkg_path_list = self.py_uncertain_dict[pkg_name]
                    is_uncertain = self.compare_path(pkg_list, pkg_path, pkg_path_list)
                    if is_uncertain:
                        temp_category = 'uncertain'
                elif pkg_name in self.py_error_dict:  # failed
                    pkg_path_list = self.py_error_dict[pkg_name]
                    error = self.compare_path_error(pkg_list, pkg_path, pkg_path_list)
                    if error:
                        temp_category = 'failed'
                else:
                    temp_category = 'noarch'
                category_list.append(temp_category)

        if category_list:
            if 'failed' in category_list:
                category = 'failed'
                sort = 0
            elif list(set(category_list)) == ['x86_64']:
                category = 'x86_64'
                sort = 2
            elif list(set(category_list)) == ['aarch64']:
                category = 'aarch64'
                sort = 3
            elif list(set(category_list)) == ['noarch']:
                category = 'noarch'
                sort = 4
            else:
                category = 'uncertain'
                sort = 1
        else:
            category = 'noarch'
            sort = 4
        py_result['category'] = category
        py_result['sort'] = sort
        if not zip_file:
            self.total_queue.put(1)
            self.log_print_xarch(py_result)
            logger.info('Ended {}'.format(real_path))
        else:
            self.inner_path_print(real_path)
        return py_result

    def check_other_file(self, other_file, is_compatible, zip_file=None, real_zip=None):
        """
        Detect py files
        param py_file_path_list: -> list
            The absolute path list of the py file.
        return:
             Returns the information dictionary of other files
        """
        result = dict()
        try:
            other_file.encode('utf-8')
            if not zip_file:
                result['md5'] = get_file_md5(other_file)
                logger.info('Began {}'.format(other_file))
        except Exception:
            other_file = other_file.encode('utf-8', 'ignore').decode('utf-8', 'ignore') + '?'
            if not zip_file:
                result['md5'] = constant.broken_file_md5
                self.log_print(result)
                logger.info('Began {}'.format(other_file))
                logger.info('Ended {}'.format(other_file))
                self.total_queue.put(1)
            else:
                self.inner_path_print(other_file)
            return {}

        file_type_by_cmd = get_file_real_type(other_file)
        real_path = self.get_real_path(other_file, zip_file, real_zip)
        file_name = get_file_name(other_file)
        result['type'] = file_type_by_cmd.split(',')[0] if ',' in file_type_by_cmd else file_type_by_cmd
        result['sort'] = 3
        result['real_path'] = real_path
        result['file_path'] = other_file
        if is_compatible == 1:
            result['is_compatibility'] = 'YES'
        elif is_compatible == 2:
            result['is_compatibility'] = 'NO'
            result['sort'] = 2
            if self.warning_check:
                result['is_compatibility'] = 'WARNING'
                logger.warning('Warning3 {}'.format(real_path))
            if self.log_type == 'json':
                issue = Summary().create_issues(real_path, None, 'incompatible', 'OtherIssue',
                                                'other_compatible',
                                                'Need to recompile on aarch64 with the source.')
                result['issue'] = issue
        elif is_compatible == 3:
            result['is_compatibility'] = 'TBV'
            result['sort'] = 1
            if self.warning_check and file_name in constant.confirmed_list:
                result['is_compatibility'] = 'WARNING'
                logger.warning('Warning3 {}'.format(real_path))
            else:
                logger.warning('Skipped {}'.format(real_path))
                if self.log_type == 'json':
                    issue = Summary().create_issues(real_path, None, 'Need to be verified.', 'OtherIssue',
                                                    'other_compatible',
                                                    'Need to be verified by other engines, '
                                                    'or if compatible, it can be ignored.')
                    result['issue'] = issue
        else:
            # 只有udf下才有
            logger.warning('Skipped {}'.format(real_path))
        if not zip_file:
            self.log_print(result)
            self.total_queue.put(1)
            logger.info('Ended {}'.format(other_file))
        else:
            self.inner_path_print(real_path)
        return result

    def check_other_file_xarch(self, other_file, is_compatible, zip_file=None, real_zip=None):
        """
        Detect py files xarch.
        param py_file_path_list: -> list
            The absolute path list of the py file.
        return:
             Returns the information dictionary of other files
        """
        result = dict()
        try:
            other_file.encode('utf-8')
            if not zip_file:
                result['md5'] = get_file_md5(other_file)
                logger.info('Began {}'.format(other_file))
        except Exception:
            other_file = other_file.encode('utf-8', 'ignore').decode('utf-8', 'ignore') + '?'
            if not zip_file:
                result['md5'] = constant.broken_file_md5
                self.log_print_xarch(result)
                logger.info('Began {}'.format(other_file))
                logger.info('Ended {}'.format(other_file))
                self.total_queue.put(1)
            else:
                self.inner_path_print(other_file)
            return {}

        file_name = get_file_name(other_file)
        file_type_by_cmd = get_file_real_type(other_file)
        real_path = self.get_real_path(other_file, zip_file, real_zip)
        result['type'] = file_type_by_cmd.split(',')[0] if ',' in file_type_by_cmd else file_type_by_cmd
        result['sort'] = 3
        result['real_path'] = real_path
        result['file_path'] = other_file

        if is_compatible == 1:
            result['category'] = 'noarch'
        elif is_compatible == 2:
            result['category'] = 'x86_64'
            result['sort'] = 2
            if self.warning_check:
                result['category'] = 'warning'
                logger.warning('Warning3 {}'.format(real_path))
        else:
            result['category'] = 'uncertain'
            result['sort'] = 1
            if self.warning_check and file_name in constant.confirmed_list:
                result['category'] = 'warning'
                logger.warning('Warning3 {}'.format(real_path))
        if not zip_file:
            self.log_print_xarch(result)
            logger.info('Ended {}'.format(other_file))
            self.total_queue.put(1)
        else:
            self.inner_path_print(other_file)
        return result

    def deal_zip(self, zip_file):
        """
        Detecting compressed packets
        :param zip_file: Compressed package path
        :return: detection result
        """
        with ThreadPoolExecutor(2) as thread_pool:
            unzip_result = self.extract_and_collect_files(zip_file, thread_pool)
            if self.class_value == 'xarch':
                zip_result = self.get_result_check_in_zip_xarch(zip_file, unzip_result, thread_pool)
            else:
                zip_result = self.get_result_check_in_zip(zip_file, unzip_result, thread_pool)
            del unzip_result
        return zip_result

    def extract_and_collect_files(self, zip_file, thread_pool, is_inner=False, real_zip=None):
        """
        Unzip all compressed packages and obtain all file paths in the compressed packages.
        param compressed_files: -> list
            Checks all tarballs contained by the object.
        param is_inner: -> bool
            Nesting in compressed packages
        return: -> None
        """
        zip_result = {zip_file: dict()}
        if is_inner is False:
            logger.info('Began {}'.format(zip_file))
        decompression_result = df().decompress_package(zip_file, {}, self.ep_temp_files)
        decompress_path = decompression_result[1]['decompress_path']
        real_path = real_zip if real_zip else zip_file
        if decompression_result[0] in [1, 2]:
            if decompression_result[1].get('record_info', ''):
                logger.info(decompression_result[1].get('record_info', ''))
        elif decompression_result[0] in [3, 5]:
            # 无命令等warning
            logger.info(decompression_result[1].get('record_info', ''))
            return {
                zip_file: {
                    "error": True,
                    "file_path": real_path
                }
            }
        else:
            # 解压失败error
            logger.info(decompression_result[1].get('record_info', ''))
            return {
                zip_file: {
                    "error": True,
                    "file_path": real_path
                }
            }
        if self.class_value == 'cs' and self.tree_output:
            # 解析目录树
            zip_node = tree_dir_files(decompress_path, real_path, True)
            self.tree_queue.put(zip_node)
        file_path_list = self.retrieve_all_file(decompress_path, zip_file, real_zip)
        temp_list = self.classify_files(decompress_path, file_path_list, thread_pool, zip_file)
        file_name = get_file_name(zip_file)
        zip_version = get_obj_version(file_name, 'zip')
        if zip_version is None and file_name.endswith('jar') and temp_list[-1]:
            zip_version = get_version_in_mf(temp_list[-1])
        del file_path_list
        so_list = temp_list[1]
        if self.warning_check and so_list:
            so_list = self.so_directory_pretreatment(temp_list[1], zip_file, real_zip)
        zip_result[zip_file]["compatible_list"] = temp_list[0]
        zip_result[zip_file]["so_list"] = so_list
        zip_result[zip_file]["py_list"] = temp_list[2]
        zip_result[zip_file]["incompatible_list"] = temp_list[4]
        zip_result[zip_file]["tbv_list"] = temp_list[5]
        zip_result[zip_file]['parent_path'] = real_path
        zip_result[zip_file]['zip_version'] = zip_version
        zip_list = temp_list[3]
        del temp_list
        if zip_list:
            for zip_file_inner in zip_list:
                inner_real_zip = self.get_real_path(zip_file_inner, zip_file, real_zip)
                result = self.extract_and_collect_files(zip_file_inner, thread_pool, is_inner=True,
                                                        real_zip=inner_real_zip)
                zip_result.update(result)
                del result
        return zip_result

    def get_result_check_in_zip(self, zip_file, zip_result, thread_pool):
        """
        Obtain detection results for all files in the compressed package
        :param zip_file:Compressed package path
        :param zip_result:Dictionary of file structure in compressed packages
        :param thread_pool: ThreadPoolExecutor obj.
        :return: Summary result of zip.
        """
        result = {
            'file_path': zip_file,
            'error_count': 0,
            'incompatible': 0,
            'tbv': 0,
            'tbv_list': [],
            'incompatible_list': [],
            'issues': [],
            'py_line_count': 0,
            'file_result': {}
        }
        inner_dict = {
            'project': zip_file,
            'current': 0,
            'total': 0
        }
        for inner_zip, inner_result in zip_result.items():
            i = 1
            error = inner_result.get("error", False)
            real_path = inner_result.get("file_path", False)
            if error:
                result['error_count'] += 1
                result['tbv_list'] = []
                result['tbv_list'].append(real_path.split(get_file_name(zip_file) + '/')[-1])
                continue
            if result['error_count']:
                continue
            so_list = inner_result.get("so_list", [])
            py_list = inner_result.get("py_list", [])
            incompatible_list = inner_result.get("incompatible_list", [])
            tbv_list = inner_result.get("tbv_list", [])
            real_zip = inner_result.get("parent_path", '')
            zip_version = inner_result.get("zip_version")
            so_result, py_result = {}, {}
            inner_file_nu = len(so_list) + len(py_list) + len(incompatible_list) + len(tbv_list)
            inner_dict['total'] += inner_file_nu
            result['incompatible'] += 0 if self.warning_check else len(incompatible_list)
            result['tbv'] += len(tbv_list)
            result['tbv_list'] += tbv_list
            result['incompatible_list'] += incompatible_list if not self.warning_check else []
            # zip 中兼容的不用管
            for incom_file in incompatible_list:
                real_path = os.path.join(real_zip, incom_file)
                if self.warning_check:
                    logger.warning('Warning_ZIP3 {}'.format(real_path))
                    continue
                if self.log_type == 'json':
                    issue = Summary().create_issues(real_path, None, 'incompatible', 'OtherIssue',
                                                    'other_compatible',
                                                    'Need to recompile on aarch64 with the source.',
                                                    current_version=zip_version)
                    result['issues'].append(issue)
                self.inner_path_print(real_path)
            if not self.output and len(zip_result) == 1:
                inner_dict['current'] += len(incompatible_list)
                self.inner_queue.put(inner_dict)
            for tbv_file in tbv_list:
                real_path = os.path.join(real_zip, tbv_file)
                if self.log_type == 'json':
                    issue = Summary().create_issues(real_path, None, 'Need to be verified.', 'OtherIssue',
                                                    'other_compatible',
                                                    'Need to be verified by other engines, '
                                                    'or if compatible, it can be ignored.')
                    result['issues'].append(issue)
                self.inner_path_print(real_path)
            if not self.output and len(zip_result) == 1:
                inner_dict['current'] += len(tbv_list)
                self.inner_queue.put(inner_dict)
            if so_list:
                so_result = self.check_so_thread(so_list, thread_pool, inner_zip, real_zip, zip_version)
                if not self.output and len(zip_result) == 1:
                    inner_dict['current'] += len(so_list)
                    self.inner_queue.put(inner_dict)
            if py_list:
                py_result = self.check_py_thread(py_list, thread_pool, inner_zip, real_zip)
                if not self.output and len(zip_result) == 1:
                    inner_dict['current'] += len(py_list)
                    self.inner_queue.put(inner_dict)
            result["issues"] += (so_result.get('count_issues', []) + py_result.get('count_issues', []))
            result["py_line_count"] = py_result.get('py_line_count', 0)
            result['file_result'].update(so_result.get('count_result', {}))
            result['file_result'].update(py_result.get('count_result', {}))
            del so_result, py_result
            if not self.output and len(zip_result) > 1:
                inner_dict['current'] = i
                inner_dict['total'] = len(zip_result)
                self.inner_queue.put(inner_dict)
            i += 1
        if not self.output:
            inner_dict['current'] = 1
            inner_dict['total'] = 1
            self.inner_queue.put(inner_dict)
        logger.info('Ended {}'.format(zip_file))
        self.inner_path_print(zip_file)
        self.total_queue.put(1)
        return result

    def count_result_zip(self, threads_zip):
        """
        Summarize the multi process results of detecting zip packages
        """
        statistics_zip_dict = {
            'count_result': dict(),
            'compatible': 0,
            'incompatible': 0,
            'tbv': 0,
            'error': 0,
            'error_zip': 0,  # json统计 error文件时会重复计算，新增字段计算json中error
            'egg': 0,
            'zip': 0,
            'whl': 0,
            'py_line_count': 0,
            'count_issues': []
        }
        for task in as_completed(threads_zip):
            try:
                zip_result = task.result()
                zip_path = zip_result.get('file_path')
                if zip_result.get('error_count', 0):
                    statistics_zip_dict['error'] += 1
                    statistics_zip_dict['error_zip'] += 1
                    file_type = get_file_real_type(zip_path)
                    statistics_zip_dict['count_result'][zip_path] = {
                        'category': -1,
                        'md5': get_file_md5(zip_path),
                        'unverified_list': zip_result.get('tbv_list', []),
                        'type': file_type.split(',')[0] if ',' in file_type else file_type,
                        'sort': 0,
                        'is_zip': True
                    }
                    issue = create_issues(zip_path, None, "Files were broken.", 'Error', "file_broken",
                                          'Need to be rechecked manually, or if compatible, it can be ignored.')
                    statistics_zip_dict['count_issues'].append(issue)
                    continue

                statistics_zip_dict['count_issues'] += zip_result.get('issues', [])
                statistics_zip_dict['py_line_count'] += zip_result.get('py_line_count', 0)
                result_all = self.collect_zip_result(zip_path, zip_result)
                del zip_result
                result_all['md5'] = get_file_md5(zip_path)
                if result_all.get('category', 1) in [2, 3, 5]:
                    statistics_zip_dict['incompatible'] += 1
                    result_all['is_compatibility'] = 'NO'
                elif result_all.get('category', 1) == 1:
                    statistics_zip_dict['compatible'] += 1
                    result_all['is_compatibility'] = 'YES'
                elif result_all.get('category', 1) == -1:
                    statistics_zip_dict['error'] += 1
                    result_all['is_compatibility'] = 'ERROR'
                else:
                    result_all['is_compatibility'] = 'TBV'
                    logger.warning('Skipped {}'.format(zip_path))
                    statistics_zip_dict['tbv'] += 1
                if zip_path.endswith('egg'):
                    statistics_zip_dict['egg'] += 1
                elif zip_path.endswith('whl'):
                    statistics_zip_dict['whl'] += 1
                else:
                    statistics_zip_dict['zip'] += 1
                statistics_zip_dict['count_result'][zip_path] = result_all
                result_all['file_path'] = zip_path
                self.log_print(result_all, True)
                del result_all
            except Exception:
                traceback.print_exc()

        return statistics_zip_dict

    def collect_zip_result(self, zip_path, zip_result):
        """
        Summarize the check results of all files in the compressed package
        :param zip_path: Compressed package path
        :param zip_result: the check results of all files in the compressed package.
        :return: Summary result of zip.
        """
        no_count, tbv_count, error_count, version_count = 0, 0, 0, 0
        tbv_count = zip_result.get('tbv', 0)
        no_count += zip_result.get('incompatible', 0)
        statistics_result = {
            "category": 1,
            "name_list": [],
            "advice_list": [],
            "package_list": [],
            "version_list": [],
            "from_list": [],
            "download_list": [],
            "action_list": [],
            "unverified_list": [],
        }
        category = 1
        statistics_result['sort'] = 3
        zip_name = os.path.split(zip_path)[-1]
        for file_path, result in zip_result.get('file_result', {}).items():
            is_compatibility = result.get('is_compatibility', 'YES')
            relative_path = result.get('real_path', '').split(zip_name)[-1]
            relative_path = self.remove_file_path_suffix(relative_path).strip('/')
            advice, package, version, type_src, repo_url, action = '', '', '', '', '', ''
            if is_compatibility not in ['NO', 'ERROR']:
                continue
            if is_compatibility == 'NO':
                no_count += 1
                version = result.get('version', '')
                version_count += 1 if version and version != '\t' else 0
                advice = result.get('advice', '')
                package = result.get('package', '')
                type_src = result.get('type_src', '')
                repo_url = result.get('repo_url', '')
                action = result.get('action', '')
            elif is_compatibility == 'ERROR':
                error_count += 1
                advice = result.get('advice', '')
            statistics_result['name_list'].append(relative_path)
            statistics_result['advice_list'].append(advice if advice else '')
            statistics_result['package_list'].append(package if package else '')
            statistics_result['version_list'].append(version)
            statistics_result['from_list'].append(type_src if type_src else '')
            statistics_result['download_list'].append(repo_url if repo_url else '')
            statistics_result['action_list'].append(action if action else '')
        statistics_result['name_list'] += zip_result.get('incompatible_list', [])
        if error_count:
            category = -1
            statistics_result['sort'] = 0
            statistics_result['unverified_list'] = zip_result.get('tbv_list', []) if tbv_count else []
        else:
            if no_count:
                if version_count == no_count:
                    category = 2
                elif 0 < version_count < no_count:
                    category = 3
                elif version_count == 0:
                    category = 5
                statistics_result['sort'] = 2
                if self.binary_check:
                    statistics_result['unverified_list'] = [tbv_file for tbv_file in zip_result.get('tbv_list', [])
                                                            if not tbv_file.endswith('.class') and not
                                                            tbv_file.endswith('.java')]
                else:
                    statistics_result['unverified_list'] = zip_result.get('tbv_list', []) if tbv_count else []
            else:
                category = 0 if tbv_count else 1
                statistics_result['sort'] = 1
                statistics_result['unverified_list'] = zip_result.get('tbv_list', []) if tbv_count else []
        del zip_result
        statistics_result['category'] = category
        statistics_result['is_zip'] = True
        file_type = get_file_real_type(zip_path)
        statistics_result['type'] = file_type.split(',')[0] if ',' in file_type else file_type
        return statistics_result

    def get_result_check_in_zip_xarch(self, zip_file, zip_result, thread_pool):
        """
        Obtain detection results for all files in the compressed package by xarch.
        :param zip_file:Compressed package path
        :param zip_result:Dictionary of file structure in compressed packages
        :param thread_pool: ThreadPoolExecutor obj.
        :return: Summary result of zip.
        """
        result = {
            'file_path': zip_file,
            'incompatible_list': [],
            'noarch_count': 0,
            'x86_64_count': 0,
            'aarch64_count': 0,
            'uncertain_count': 0,
            'fail_count': 0,
            'file_result': {},
            'tbv_list': [],
        }
        inner_dict = {
            'project': zip_file,
            'current': 0,
            'total': 0
        }
        for inner_zip, inner_result in zip_result.items():
            i = 1
            error = inner_result.get("error", False)
            real_path = inner_result.get("file_path", False)
            if error:
                result['fail_count'] += 1
                result['tbv_list'].append(real_path.split(get_file_name(zip_file) + '/')[-1])
                continue
            so_list = inner_result.get("so_list", [])
            py_list = inner_result.get("py_list", [])
            incompatible_list = inner_result.get("incompatible_list", [])
            tbv_list = inner_result.get("tbv_list", [])
            real_zip = inner_result.get("parent_path", '')  # 需要重新处理
            inner_file_nu = len(so_list) + len(py_list) + len(incompatible_list) + len(tbv_list)
            inner_dict['total'] += inner_file_nu
            so_result, py_result = {}, {}
            result['x86_64_count'] += 0 if self.warning_check else len(incompatible_list)
            result['uncertain_count'] += len(tbv_list)
            result['incompatible_list'] += incompatible_list if not self.warning_check else []
            # zip 中兼容的不用管
            for incom_file in incompatible_list:
                real_path = os.path.join(real_zip, incom_file)
                if self.warning_check:
                    logger.warning('Warning_ZIP3 {}'.format(real_path))
                    continue
                self.inner_path_print(real_path)
            if not self.output and len(zip_result) == 1:
                inner_dict['current'] += len(incompatible_list)
                self.inner_queue.put(inner_dict)
            for tbv_file in tbv_list:
                real_path = os.path.join(real_zip, tbv_file)
                self.inner_path_print(real_path)
            if so_list:
                so_result = self.check_so_thread_xarch(so_list, thread_pool, inner_zip, real_zip)
                inner_dict['current'] += len(so_list)
                if not self.output and len(zip_result) == 1:
                    self.inner_queue.put(inner_dict)
            if py_list:
                py_result = self.check_py_thread_xarch(py_list, thread_pool, inner_zip, real_zip)
                inner_dict['current'] += len(py_list)
                if not self.output and len(zip_result) == 1:
                    self.inner_queue.put(inner_dict)
            result['file_result'].update(so_result.get('count_result', {}))
            result['file_result'].update(py_result.get('count_result', {}))
            del so_result, py_result
            if not self.output and len(zip_result) > 1:
                inner_dict['current'] = i
                inner_dict['total'] = len(zip_result)
                self.inner_queue.put(inner_dict)
            i += 1
        if not self.output:
            inner_dict['current'] = 1
            inner_dict['total'] = 1
            self.inner_queue.put(inner_dict)
        logger.info('Ended {}'.format(zip_file))
        self.inner_path_print(zip_file)
        self.total_queue.put(1)
        return result

    def count_result_zip_xarch(self, threads_zip):
        """
        Summarize the multi process results of detecting zip packages by xarch.
        """
        statistics_zip_dict = {
            'count_result': dict(),
            'noarch': 0,
            'x86_64': 0,
            'aarch64': 0,
            'uncertain': 0,
            'warning': 0,
            'failed': 0,
        }
        for task in as_completed(threads_zip):
            try:
                zip_result = task.result()
                zip_path = zip_result.get('file_path')
                if zip_result.get('error_count', 0):
                    statistics_zip_dict['failed'] += 1
                    file_type = get_file_real_type(zip_path)
                    statistics_zip_dict['count_result'][zip_path] = {
                        'category': 'failed',
                        'md5': get_file_md5(zip_path),
                        'type': file_type.split(',')[0] if ',' in file_type else file_type,
                        'unverified_list': zip_result.get('tbv_list', []),
                        'sort': 0,
                        'is_zip': True
                    }
                    continue

                result_all = self.collect_zip_result_xarch(zip_path, zip_result)
                del zip_result
                result_all['md5'] = get_file_md5(zip_path)
                if result_all.get('category', 'uncertain') == 'failed':
                    statistics_zip_dict['failed'] += 1
                elif result_all.get('category', 'uncertain') == 'noarch':
                    statistics_zip_dict['noarch'] += 1
                elif result_all.get('category', 'uncertain') == 'x86_64':
                    statistics_zip_dict['x86_64'] += 1
                elif result_all.get('category', 'uncertain') == 'aarch64':
                    statistics_zip_dict['aarch64'] += 1
                elif result_all.get('category', 'uncertain') == 'warning':
                    statistics_zip_dict['warning'] += 1
                else:
                    statistics_zip_dict['uncertain'] += 1
                statistics_zip_dict['count_result'][zip_path] = result_all
                result_all['file_path'] = zip_path
                self.log_print_xarch(result_all, True)
                del result_all
            except Exception:
                traceback.print_exc()

        return statistics_zip_dict

    def collect_zip_result_xarch(self, zip_path, zip_result):
        """
        Summarize the check results of all files in the compressed package by xarch.
        :param zip_path: Compressed package path
        :param zip_result: the check results of all files in the compressed package.
        :return: Summary result of zip.
        """
        noarch_count = zip_result.get('noarch_count', 0)
        x86_64_count = zip_result.get('x86_64_count', 0)
        aarch64_count = zip_result.get('aarch64_count', 0)
        uncertain_count = zip_result.get('uncertain_count', 0)
        fail_count = zip_result.get('fail_count', 0)
        statistics_result = {
            "category": 'uncertain',
            "name_list": [],
            "advice_list": [],
            "package_list": [],
            "version_list": [],
            "from_list": [],
            "download_list": [],
            "action_list": [],
            'sort': 0,
            "unverified_list": zip_result.get('tbv_list', []) if fail_count else [],
        }
        zip_name = os.path.split(zip_path)[-1]
        for file_path, result in zip_result.get('file_result', {}).items():
            file_category = result.get('category', 'uncertain')
            relative_path = result.get('real_path', '').split(zip_name)[-1]
            relative_path = self.remove_file_path_suffix(relative_path).strip('/')
            if file_category == 'x86_64':
                x86_64_count += 1
                version = result.get('version', '')
                advice = result.get('advice', '')
                package = result.get('package', '')
                type_src = result.get('type_src', '')
                repo_url = result.get('repo_url', '')
                action = result.get('action', '')
                statistics_result['name_list'].append(relative_path)
                statistics_result['advice_list'].append(advice if advice else '')
                statistics_result['package_list'].append(package if package else '')
                statistics_result['version_list'].append(version)
                statistics_result['from_list'].append(type_src if type_src else '')
                statistics_result['download_list'].append(repo_url if repo_url else '')
                statistics_result['action_list'].append(action if action else '')
            elif file_category == 'error':
                fail_count += 1
            elif file_category == 'noarch':
                noarch_count += 1
            elif file_category == 'aarch64':
                aarch64_count += 1
            else:
                uncertain_count += 1
        statistics_result['name_list'] += zip_result.get('incompatible_list', [])
        del zip_result
        if fail_count:
            category = 'failed'
            statistics_result['sort'] = 0
        elif uncertain_count:
            category = 'uncertain'
            statistics_result['sort'] = 1
        elif x86_64_count:
            category = 'x86_64'
            statistics_result['sort'] = 2
        elif aarch64_count:
            category = 'aarch64'
            statistics_result['sort'] = 3
        elif noarch_count:
            category = 'noarch'
            statistics_result['sort'] = 4
        else:
            category = 'uncertain'
            statistics_result['sort'] = 0
        statistics_result['category'] = category
        statistics_result['is_zip'] = True
        file_type = get_file_real_type(zip_path)
        statistics_result['type'] = file_type.split(',')[0] if ',' in file_type else file_type
        return statistics_result

    def teardown_operation(self):
        """
        Delete temporary files after detection is complete.
        return: -> None
        """
        try:
            rtcode, output = execute_cmd("rm -rf {}".format(self.ep_temp_files))
            if rtcode != 0:
                logger.info(output)
        except Exception:
            traceback.print_exc()
        return

    def compare_path(self, pkg_list, pkg_path, pkg_path_list):
        """
        Compare import path and py path whether consistent.
        param pkg_path: -> str
            Path of import package.
        param pkg_path_list: -> list
            The absolute path list of package.
        Return: -> bool
            False: inconsistent
            True: consistent
        """
        # 获取在python内置模块与三方模块
        if not self.packages_list:
            ret, result = execute_cmd('''python -c "help('modules')"''')
            if ret == 0:
                for line in result.split('\n'):
                    if not line or line.startswith('Please wait a moment') or line.startswith('Enter any module') or \
                            line.startswith("for modules whose"):
                        continue
                    self.packages_list += [package for package in line.split(' ') if package]
        if len(pkg_list) == 1:
            if os.path.exists(pkg_path):
                # 判断是否是私有不兼容模块
                if os.path.abspath(pkg_path) in [os.path.abspath(tempath) for tempath in pkg_path_list]:
                    return True
                return False
        else:
            same = False
            for pkg_path in pkg_path_list:
                pkg_path = pkg_path.lstrip('.').split('/')
                if pkg_list == pkg_path[-1 * len(pkg_list):]:
                    same = True
                    break
            return same

        if os.path.split(pkg_path)[-1].strip('.py') in self.packages_list:
            return False
        return True

    def compare_path_error(self, pkg_list, pkg_path, pkg_path_list):
        """
        Compare import path and py path whether consistent.
        param pkg_path: -> str
            Path of import package.
        param pkg_path_list: -> list
            The absolute path list of package.
        Return: -> bool
            False: inconsistent
            True: consistent
        """
        if len(pkg_list) == 1:
            if os.path.exists(pkg_path):
                # 判断是否是私有不兼容模块
                if os.path.abspath(pkg_path) in [os.path.abspath(tempath) for tempath in pkg_path_list]:
                    return True
                return False
        else:
            for pkg_path in pkg_path_list:
                pkg_path = pkg_path.lstrip('.').split('/')
                if pkg_list == pkg_path[-1 * len(pkg_list):]:
                    return True
            return False

    def merge_check_result(self, py_result, py_fi_result, py_statistics_data):
        """
        Merge test results
        param py_result: -> dict
            The result of detected py files.
        param py_fi_result: -> dict
            The result dict of py file which was error or incompatible
        param py_fi_result: -> py_statistics_data
            Summary data of detection
        """
        for py_file in py_fi_result:
            if py_file in py_result:
                if 'is_compatibility' not in py_fi_result[py_file]:
                    continue

                if py_result[py_file]['is_compatibility'] == 'ERROR' or \
                        py_fi_result[py_file]['is_compatibility'] == 'ERROR':

                    if py_result[py_file]['is_compatibility'] == 'NO':
                        py_statistics_data[1] -= 1
                        py_statistics_data[2] += 1
                    elif py_result[py_file]['is_compatibility'] == 'YES':
                        py_statistics_data[0] -= 1
                        py_statistics_data[2] += 1
                    py_result[py_file]['is_compatibility'] = 'ERROR'
                    py_result[py_file]['reason'] = py_fi_result[py_file]['reason']
                    py_result[py_file]['sort'] = 0

                elif py_result[py_file]['is_compatibility'] == 'NO' or \
                        py_fi_result[py_file]['is_compatibility'] == 'NO':
                    py_result[py_file]['is_compatibility'] = 'NO'
                    py_result[py_file]['reason'] = py_result[py_file]['reason'] + py_fi_result[py_file]['reason']

                py_result[py_file]['reason'] = [reason_info for reason_info in py_result[py_file]['reason']
                                                if 'line' in reason_info]

        return py_result, py_statistics_data

    def py_so_error_issues(self, py_file, so_result):
        """
        Get the error of the so list in py and output error list and json info.
        param py_file: -> path
            The absolute path of the py file.
        param so_result: -> dict
            The so detection result in the py file
        return:
            error_reason_list: error info list.
            issues: json info.
        """
        reason_list = []
        issues = []

        for so_path in so_result:
            for nu in so_result[so_path]['nu']:
                reason = ''
                # error
                if so_result[so_path].get('not_exist', True):
                    reason = '[So Path Not Found] @ line {}: {};'.format(nu, so_path)
                    issues.append(Summary().create_issues(py_file, nu, reason, 'AppReferenceIssue', 'py_so_exists'))
                # incompatible
                elif so_result[so_path].get('incompatible', True):
                    reason = '[So Incompatible] @ line {}: {};'.format(nu, so_path)
                    issues.append(Summary().create_issues(py_file, nu, reason, 'ArchSpecificLibraryIssue',
                                                          'py_so_compatible'))

                reason_list.append(reason)
        return reason_list, issues

    def py_so_other_issues(self, py_file, linux_command_dict):
        """
        Get the incompatible of the so list in py and output error list and json info.
        param py_file: -> path
            The absolute path of the py file.
        param linux_command_dict: -> dict
            The so detection result in the py file
        return:
            error_reason_list: error info list.
            issues: json info.
        """
        check_result = []
        issues = []
        for nu in linux_command_dict:
            check_command_list = linux_command_dict[nu]['check_command']
            result_c = [command for command in check_command_list if
                        not check_linux_command_compatibility(command)]
            if result_c:
                reason = '[Command NOT Found] @ line {}: {};'.format(nu, linux_command_dict[nu]['source_command'])
                check_result.append(reason)
                issues.append(Summary().create_issues(py_file, nu, reason, 'LinuxCommandIssue', 'py_linux_compatible'))
        return check_result, issues

    def py_so_file_path_list(self, file_path, file_lines):
        """
        Get the absolute path list of the so file which referenced in the py file
        param file_path: -> str
            Py file absolute path
        return:
            absolute path dict of so.
        """
        incompatible, error = False, False
        # 获取py中包含的so文件路径dict  result[so_path]['nu'].append(nu + 1)
        py_so_result = get_py_so_result(file_path, file_lines)

        for so_path in py_so_result:
            # 判断当前so文件是否存在
            if os.path.exists(so_path):
                if so_path in self.not_compatibility:
                    py_so_result[so_path]['incompatible'] = True
                    incompatible = True
                else:
                    check_result = check_aarch64_exist(so_path)
                    if not check_result:
                        py_so_result[so_path]['incompatible'] = True
                        incompatible = True
            else:
                py_so_result[so_path]['not_exist'] = True
                error = True

        return py_so_result, incompatible, error

    def py_so_file_path_list_xarch(self, file_path, file_lines):
        """
        Determine the compatibility of so files in py
        :param file_path: File path
        :param file_lines: File contents.
        :return:Compatibility List
        """
        # 获取py中包含的so文件路径dict  result[so_path]['nu'].append(nu + 1)
        py_so_result = get_py_so_result(file_path, file_lines)
        temp_list = []
        for so_path in py_so_result:
            # 判断当前so文件是否存在
            if os.path.exists(so_path):
                file_name = get_file_name(so_path)
                if file_name in self.not_compatibility:
                    temp_list.append('x86_64')
                elif file_name in self.arch64_so_list:
                    temp_list.append('aarch64')
                elif file_name in self.noarch_so_list:
                    temp_list.append('noarch')
                elif file_name in self.uncertain_so_list:
                    temp_list.append('uncertain')
                else:
                    so_result = self.check_so_file_xarch(so_path, True)
                    temp_list.append(so_result.get('category', 'uncertain'))
            else:
                temp_list.append('error')
        return temp_list

    def classify_py_zip(self, file_name):
        """
        Determine whether the file belongs to python
        param file_name: -> string
            The name of the file.
        return: --> bool
        """
        for flag in python_flag:
            if flag.lower() in file_name.lower():
                if flag == 'py' and list(filter(lambda x: x in file_name, specify_name)):
                    continue
                return True, flag
        return False, ''

    def log_print(self, result, zip_flag=False):
        """
        Log printing during detection
        param result: -> dict.
        """
        if self.output:
            is_compatibility = result.get('is_compatibility', '')
            if is_compatibility == 'YES':
                return
            file_path = result.get('real_path', '') if 'real_path' in result else result.get('file_path', '')
            file_name = os.path.split(file_path)[-1]
            file_md5 = result.get('md5', '')
            file_type = result.get('type', '')
            advice = result.get('advice', '')
            upgrade = result.get('upgrade', '')
            version = result.get('version', '')
            type_src = result.get('type_src', '')
            package = result.get('package', '')
            output_terms = ["NAME", "MD5", "COMPATIBILITY", "TYPE", "INCOMPATIBILITY", "ADVICE",
                            "UPGRADE", "NAME", "TYPE-SRC", "PACKAGE", "VERSION"]

            content = ("{0:<15}: {1:<20} \n"
                       "{2:<15}: {3:<20} \n"
                       "{4:<15}: {5:<20} \n"
                       "{6:<15}: {7:<20} \n"
                       "{8:<15}: {9:<20} \n"
                       ).format(output_terms[0], file_name,
                                output_terms[1], file_md5,
                                output_terms[2], is_compatibility,
                                output_terms[3], file_type,
                                output_terms[4], file_name)
            if not zip_flag:
                if upgrade:
                    content += "{0:<15}: {1:<20} \n".format(output_terms[6], upgrade)
                if advice:
                    content += "{0:<15}: {1:<20} \n".format(output_terms[5], '\n{:17}'.format(advice))

                if version:
                    name_so = so_name_to_search(file_name)
                    content += "    |{0:<30} |{1:<10} |{2:<15} |{3:<50} \n" \
                               "    |{4:<30} |{6:<10} |{6:<15} |{7:<50} \n" \
                        .format(output_terms[7], output_terms[8],
                                output_terms[9], output_terms[10],
                                name_so, type_src, package, version)
            else:
                name_list = result.get('name_list', '')
                if name_list:
                    type_src_list = result.get('from_list', '')
                    package_list = result.get('package_list', '')
                    version_list = result.get('version_list', '')
                    advice_list = result.get('advice_list', '')
                    content += "    |{0:<30} |{1:<10} |{2:<30} |{3:<20} |{4:<50} \n".format(
                        output_terms[7], output_terms[8],
                        output_terms[9], output_terms[10], 'ADVICE')
                    for name_so, type_src, package, version, advice in zip_longest(name_list, type_src_list,
                                                                                   package_list, version_list,
                                                                                   advice_list):
                        name_so = so_name_to_search(os.path.split(name_so)[-1])
                        version = version.strip('\t') if version else ''
                        type_src = type_src.strip('\t') if type_src else ''
                        package = package.strip('\t') if package else ''
                        advice = advice.strip('\t') if advice else ''
                        content += "    |{0:<30} |{1:<10} |{2:<30} |{3:<20} |{4:<50} \n" \
                            .format(name_so, type_src, package, version, advice)

            print(content)

    def log_print_xarch(self, file_dict, zip_flag=False):
        """
        Log printing during detection by xarch.
        param result: -> dict.
        """
        if self.output:
            category = file_dict.get('category', '')
            if category == 'noarch':
                return
            file_path = file_dict.get('real_path', '') if 'real_path' in file_dict else file_dict.get('file_path', '')
            file_name = file_dict.get('file_name', '') if 'file_name' in file_dict else os.path.split(file_path)[-1]
            file_md5 = file_dict.get('md5', '')
            file_type = file_dict.get('type', '')
            output_terms = ["NAME", "MD5", "CATEGORY", "TYPE", "INCOMPATIBILITY", "ADVICE",
                            "UPGRADE", "NAME", "TYPE-SRC", "PACKAGE", "VERSION"]
            content = ("{0:<15}: {1:<20} \n"
                       "{2:<15}: {3:<20} \n"
                       "{4:<15}: {5:<20} \n"
                       "{6:<15}: {7:<20} \n"
                       ).format(output_terms[0], file_name,
                                output_terms[1], file_md5,
                                output_terms[2], category,
                                output_terms[3], file_type)

            if category == 'X86_64':
                advice = file_dict.get('advice', '')
                upgrade = file_dict.get('upgrade', '')
                version = file_dict.get('version', '')
                type_src = file_dict.get('type_src', '')
                package = file_dict.get('package', '')
                if upgrade:
                    content += "{0:<15}: {1:<20} \n".format(output_terms[6], upgrade)
                if advice:
                    content += "{0:<15}: {1:<20} \n".format(output_terms[5], '\n{:17}'.format(advice))

                if version:
                    name_so = so_name_to_search(file_name)
                    content += "    |{0:<60} |{1:<10} |{2:<30} |{3:<50} \n" \
                               "    |{4:<60} |{6:<5} |{6:<30} |{7:<50}" \
                        .format(output_terms[7], output_terms[8],
                                output_terms[9], output_terms[10],
                                name_so, type_src, package, version)
            if zip_flag:
                name_list = file_dict.get('name_list', '')
                if name_list:
                    type_src_list = file_dict.get('from_list', '')
                    package_list = file_dict.get('package_list', '')
                    version_list = file_dict.get('version_list', '')
                    content += "    |{0:<60} |{1:<10} |{2:<30} |{3:<50} \n".format(
                        output_terms[7], output_terms[8],
                        output_terms[9], output_terms[10])
                    for name_so, type_src, package, version in zip_longest(name_list, type_src_list, package_list,
                                                                           version_list):
                        name_so = so_name_to_search(os.path.split(name_so)[-1])
                        version = version.strip('\t') if version else ''
                        type_src = type_src.strip('\t') if type_src else ''
                        package = package.strip('\t') if package else ''
                        content += "    |{0:<30} |{1:<10} |{2:<30} |{3:<20} \n" \
                            .format(name_so, type_src, package, version)

            print(content)

    def inner_path_print(self, real_path):
        if self.inner_log:
            real_path = remove_file_path_suffix(real_path)
            print('{} done.'.format(real_path))

    def program_loading(self):
        """
        Dynamic display during waiting.
        return: -> None
        """
        while self.loading:
            time.sleep(5)
            print("\rSearching", end="")
            for i in range(6):
                print(".", end='', flush=True)
                time.sleep(1)

    def summary_print_xarch(self, execution_results, start_time):
        """
        Summary Output
        param start_time: -> time
            Detection Start Time.
        """

        end_time = time.time()

        summary_output = "Python " + constant.summary_output_xarch.format(execution_results[4], execution_results[3],
                                                                          execution_results[2], execution_results[1],
                                                                          execution_results[0], execution_results[5],
                                                                          execution_results[6])
        average = (end_time - start_time) / execution_results[6] if execution_results[6] else 0
        run_time = constant.summary_run_time.format(end_time - start_time, average)
        summary_output_log = constant.summary_output_xarch.format(execution_results[4], execution_results[3],
                                                                  execution_results[2], execution_results[1],
                                                                  execution_results[0], execution_results[5],
                                                                  execution_results[6])
        logger.info(summary_output_log)
        if self.output:
            print(self.isolation)
            print(summary_output)
            print(self.isolation)
            print(run_time)

    def summary_print(self, execution_results, start_time):
        """
        Summary Output
        param start_time: -> time
            Detection Start Time.
        """
        all_files_count = execution_results[5]
        end_time = time.time()
        summary_output = "Python " + constant.summary_output.format(execution_results[0], execution_results[1],
                                                                    execution_results[2], execution_results[3],
                                                                    execution_results[4], execution_results[5])
        average = (end_time - start_time) / all_files_count if all_files_count else 0
        run_time = constant.summary_run_time.format(end_time - start_time, average)
        if self.output:
            print(self.isolation)
            print(summary_output)
            print(self.isolation)
            print(run_time)
        summary_output_log = constant.summary_output.format(execution_results[0], execution_results[1],
                                                            execution_results[2], execution_results[4],
                                                            execution_results[3], execution_results[5])
        logger.info(summary_output_log)

    def get_json_source_info(self, migrated_path):
        source_files = []
        source_dirs = []
        if os.path.isdir(migrated_path):
            for file_path in os.listdir(migrated_path):
                temp_path = os.path.join(migrated_path, file_path)
                if os.path.isfile(temp_path):
                    source_files.append(temp_path)
                else:
                    source_dirs.append(temp_path)
        else:
            source_files.append(migrated_path)
        return source_files, source_dirs

    def json_report_productization(self, migrated_path, so_result, py_result, other_result, warning, zip_result):
        """
        Output detection results to JSON file when class cs.
        """
        temp_dict = dict()
        summary_dict = dict()
        summary_dict.update(so_result.get('count_result', {}))
        summary_dict.update(py_result.get('count_result', {}))
        summary_dict.update(other_result.get('count_result', {}))
        summary_dict.update(zip_result.get('count_result', {}))
        temp_dict["file_path"] = migrated_path
        temp_dict["issues"] = (so_result.get('count_issues', []) + py_result.get('count_issues', [])
                               + zip_result.get('count_issues', []) + other_result.get('count_issues', []))
        temp_dict["py_file_count"] = (len(py_result.get('count_result', {})) + other_result.get('py', 0))
        temp_dict["so_file_count"] = len(so_result.get('count_result', {})) - so_result.get('warning', 0)
        temp_dict["egg_file_count"] = zip_result.get('egg', 0)
        temp_dict["whl_file_count"] = zip_result.get('whl', 0)
        temp_dict["zip_file_count"] = zip_result.get('zip', 0) + zip_result.get('error_zip', 0)
        temp_dict["other_file_count"] = other_result.get('other', 0) - other_result.get('warning', 0)
        temp_dict["pyc_file_count"] = other_result.get('pyc', 0)
        temp_dict["warning_count"] = warning
        temp_dict["py_line_count"] = (py_result.get('py_line_count', 0) + zip_result.get('py_line_count', 0))
        temp_dict["root_directory"] = migrated_path
        source_files, source_dirs = self.get_json_source_info(migrated_path)
        temp_dict["source_dirs"] = source_dirs
        temp_dict["source_files"] = source_files
        summary_dict['json_info'] = temp_dict
        del so_result, py_result, other_result, zip_result
        if self.tree_output:
            mount_compatibility_into_node(migrated_path, temp_dict["issues"], self.root_node)
        Summary().summary_content(summary_dict, self.log_type, self.class_value)

    def custom_output_file_name(self, log_name, engine):
        """
        Determine standardized log generation path based on parameters.
        """
        if log_name:
            log_path = os.path.abspath(os.path.join(Constant.current_path, log_name))
            temp_log_path = 'log' if self.log_type == 'txt' else self.log_type

            if log_path == '/' + log_name and '/' not in log_name:
                dir_path = Constant.current_path
                file_name = log_name.lstrip('/')
            else:
                dir_path = os.path.split(log_path)[0]
                file_name = os.path.split(log_path)[-1]
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)

            if file_name:
                Constant.log_path = os.path.join(dir_path, file_name)
                if os.path.exists(log_path + '.' + temp_log_path):
                    Constant.log_path = os.path.join(dir_path, file_name + '_' + Constant.time_str)
                Constant.log_path = Constant.log_path if engine else Constant.log_path + '_python'
            else:
                Constant.log_path = os.path.join(dir_path, 'result_' + Constant.time_str + '_python')
        if self.class_value != 'udf':
            open(Constant.log_path + Constant.suffix_dict[self.log_type], 'a').close()

    def check_so_thread(self, so_file_list, thread_pool, zip_file=None, real_zip=None, zip_version=None):
        """
        Detecting threads for so files
        :param so_file_list: so file list
        :param thread_pool: ThreadPoolExecutor
        :param zip_file: zip path.
        :param real_zip: zip real path.
        :return:
        """
        statistics_so_dict = {
            'count_result': dict(),
            'compatible': 0,
            'incompatible': 0,
            'warning': 0,
            'count_issues': []
        }
        table_name, zip_flag = '', ''
        if self.class_value and zip_file:
            file_name = get_file_name(zip_file)
            res, zip_flag = self.classify_py_zip(file_name)
            table_name = 'python3'
            py2_flag = ['py2', 'cp2', 'python2', 'lib-dynload']
            # 识别python2、3
            for flag in py2_flag:
                if flag in file_name.lower():
                    table_name = 'python2'
                    break
        threads = []
        for so_file in so_file_list:
            threads.append(thread_pool.submit(self.check_so_file, so_file, zip_file, real_zip, zip_version))
        mysql = MySqlite(self.db_path)
        for task in as_completed(threads):
            result = task.result()
            if not result:
                continue
            file_path = result.get('file_path')
            statistics_so_dict['count_result'][file_path] = result
        for so_file, result in statistics_so_dict.get('count_result', {}).items():
            real_path = result.get('real_path', '')
            project_path, so_name = get_so_project_name(so_file)
            is_compatibility = result.get('is_compatibility', 'YES')
            recommand_field_list = ["version", "advice", "action", "package", "repo_url", "type_src"]
            if is_compatibility == 'NO':
                if any(self.project_so_dict[project_path][so_name]):
                    if zip_file:
                        logger.info('Warning_ZIP1 {}'.format(real_path))
                    else:
                        logger.info('Warning1 {}'.format(real_path))
                    result["is_compatibility"] = 'YES'
                    result["sort"] = 3
                    for field in recommand_field_list:
                        result.pop(field, None)
                    statistics_so_dict['compatible'] += 1
                else:
                    statistics_so_dict['incompatible'] += 1
                    db_search_result = dict()
                    if self.class_value and zip_file:
                        # 不兼容
                        recommand_data = self.recommand_by_zip_flag(zip_flag, table_name, mysql)
                        if recommand_data[0]:
                            pip_name = ''
                            version = recommand_data[1][1] if recommand_data[1][1] else ''
                            repo_url = recommand_data[1][4] if recommand_data[1][4] else ''
                            minversion = recommand_data[1][0] if recommand_data[1][0] else ''
                            version = self.get_version(version, minversion, repo_url)
                            if zip_flag == 'scikit_learn':
                                if compared_version(version, '0.23.1') == 1:
                                    pip_name = "scikit_learn.libs"
                                else:
                                    pip_name = "sklearn"
                            elif zip_flag == 'Pillow':
                                if compared_version(version, '7.0.0') == 1 or compared_version(version, '8.4.0') != 0:
                                    pip_name = "Pillow.libs"
                                else:
                                    pip_name = "PIL"
                            elif zip_flag in python_library_dict:
                                pip_name = python_library_dict.get(zip_flag)
                            else:
                                pip_name = recommand_data[1][3]
                            advice_r = NormalizedOutput().get_advice_str(minversion, version, repo_url)
                            advice = advice_r[1]
                            action = NormalizedOutput().get_action_str(advice_r[0], minversion, version, pip_name,
                                                                       'python')
                            db_search_result = {
                                "version": '{}\t'.format(version),
                                "advice": advice,
                                "action": action,
                                "repo_url": repo_url if repo_url else '',
                                "package": pip_name if pip_name else '',
                                "type_src": 'Yum',
                            }
                    if not db_search_result:
                        db_search_result = self.recommend_by_so(so_file, mysql)
                    statistics_so_dict['count_result'][so_file].update(db_search_result)
                    advice = {
                        "NAME": os.path.split(so_file)[-1] if not zip_flag else zip_flag,
                        "TYPE-SRC": db_search_result.get('type_src', ''),
                        "PACKAGE": db_search_result.get('package', ''),
                        "VERSION": db_search_result.get('version', '').strip('\t'),
                        "DOWDNLOAD": db_search_result.get('repo_url', '')
                    }
                    current_version = result.get('current_version')
                    issue = create_issues(real_path, None, 'incompatible', 'ArchSpecificLibraryIssue',
                                          'so_compatible', advice, current_version)
                    statistics_so_dict['count_issues'].append(issue)
            elif is_compatibility == 'WARNING':
                statistics_so_dict['warning'] += 1
            else:
                statistics_so_dict['compatible'] += 1
            if not zip_file:
                self.log_print(statistics_so_dict['count_result'][so_file])
        return statistics_so_dict

    def check_so_thread_xarch(self, so_file_list, thread_pool, zip_file=None, real_zip=None):
        """
       Detecting threads for so files by xarch.
       :param so_file_list: so file list
       :param thread_pool: ThreadPoolExecutor
       :param zip_file: zip path.
       :param real_zip: zip real path.
       :return:
       """
        statistics_so_dict = {
            'count_result': dict(),
            'noarch': 0,
            'aarch64': 0,
            'x86_64': 0,
            'uncertain': 0
        }
        threads = []
        for so_file in so_file_list:
            threads.append(thread_pool.submit(self.check_so_file_xarch, so_file, zip_file, real_zip))
        result_summary = dict()
        for task in as_completed(threads):
            result = task.result()
            if not result:
                continue
            file_path = result.get('file_path')
            del result['file_path']
            result_summary[file_path] = result
            del result
        mysql = MySqlite(self.db_path)
        for so_file, result in result_summary.items():
            project_path, so_name = get_so_project_name(so_file)
            category_list = self.project_so_dict.get(project_path, {}).get(so_name, [])
            if 'x86_64' in category_list and 'aarch64' in category_list or 'noarch' in category_list:
                result['category'] = 'noarch'
                statistics_so_dict['noarch'] += 1
            elif 'aarch64' in category_list:
                result['category'] = 'aarch64'
                statistics_so_dict['aarch64'] += 1
            elif 'x86_64' in category_list:
                result['category'] = 'x86_64'
                statistics_so_dict['x86_64'] += 1
                db_search_result = self.recommend_by_so(so_file, mysql)
                result.update(db_search_result)
            else:
                result['category'] = 'uncertain'
                statistics_so_dict['uncertain'] += 1
            statistics_so_dict['count_result'][so_file] = result
            if not zip_file:
                self.log_print_xarch(result)
            del result

        return statistics_so_dict

    def check_py_thread(self, py_file_list, thread_pool, zip_file=None, real_zip=None):
        """
        Detecting threads for py files
        :param so_file_list: py file list
        :param thread_pool: ThreadPoolExecutor
        :param zip_file: zip path.
        :param real_zip: zip real path.
        :return:
        """
        statistics_py_dict = {
            'count_result': dict(),
            'compatible': 0,
            'incompatible': 0,
            'error': 0,
            'py_line_count': 0,
            'count_issues': []
        }
        threads = [thread_pool.submit(self.check_py_file, py_file, zip_file, real_zip) for py_file in py_file_list]
        for task in as_completed(threads):
            py_result = task.result()
            if not py_result:
                continue
            file_path = py_result.get('file_path')
            del py_result['file_path']
            statistics_py_dict['count_result'][file_path] = py_result

        for py_file, py_result in statistics_py_dict.get('count_result', {}).items():
            result = self.check_py_pkg_import(py_result, zip_file)
            issues = result.get('issues', [])
            file_line_count = result.get('file_line_count')
            statistics_py_dict['count_result'][py_file] = result
            statistics_py_dict['py_line_count'] += file_line_count
            is_compatibility = result.get('is_compatibility')
            if is_compatibility == 'ERROR':
                statistics_py_dict['error'] += 1
            elif is_compatibility == 'NO':
                statistics_py_dict['incompatible'] += 1
            else:
                statistics_py_dict['compatible'] += 1
            statistics_py_dict['count_issues'] += issues
            del result
        return statistics_py_dict

    def check_py_thread_xarch(self, py_file_list, thread_pool, zip_file=None, real_zip=None):
        """
        Detecting threads for py files by xarch
        :param so_file_list: py file list
        :param thread_pool: ThreadPoolExecutor
        :param zip_file: zip path.
        :param real_zip: zip real path.
        :return:
        """
        statistics_py_dict = {
            'count_result': dict(),
            'noarch': 0,
            'aarch64': 0,
            'x86_64': 0,
            'uncertain': 0,
            'failed': 0
        }
        threads = [thread_pool.submit(self.check_py_file_xarch, py_file, zip_file, real_zip) for py_file in py_file_list]
        for task in as_completed(threads):
            try:
                py_result = task.result()
                if not py_result:
                    continue
                py_file = py_result.get('file_path', '')
                result = self.check_py_pkg_import_xarch(py_result, zip_file)
                del result['file_path']
                statistics_py_dict['count_result'][py_file] = result
                category = result.get('category', 'uncertain')
                if category == 'noarch':
                    statistics_py_dict['noarch'] += 1
                elif category == 'aarch64':
                    statistics_py_dict['aarch64'] += 1
                elif category == 'x86_64':
                    statistics_py_dict['x86_64'] += 1
                elif category == 'uncertain':
                    statistics_py_dict['uncertain'] += 1
                elif category == 'failed':
                    statistics_py_dict['failed'] += 1
                else:
                    statistics_py_dict['uncertain'] += 1
                del result
            except Exception:
                traceback.print_exc()
        return statistics_py_dict

    def check_other_process(self, other_file_list, migrated_path, is_compatible, t_other):
        """
        The thread of analyzing the detection of other files.
        """
        statistics_other_dict = {
            'count_result': dict(),
            'compatible': 0,
            'incompatible': 0,
            'warning': 0,
            'tbv': 0,
            'py': 0,
            'pyc': 0,
            'other': 0,
            'count_issues': [],
        }
        threads = []
        for other_file in other_file_list:
            if os.path.isdir(migrated_path):
                other_file = os.path.join(migrated_path, other_file)
            threads.append(t_other.submit(self.check_other_file, other_file, is_compatible))
        for task in as_completed(threads):
            try:
                result = task.result()
                if not result:
                    continue
                other_file = result.get('file_path', '')
                del result['file_path']
                statistics_other_dict['count_result'][other_file] = result
                is_compatibility = result.get('is_compatibility', 'YES')
                if is_compatibility == 'TBV':
                    statistics_other_dict['tbv'] += 1
                    if self.log_type == 'json':
                        statistics_other_dict['count_issues'].append(result.get('issue', {}))
                elif is_compatibility == 'NO':
                    statistics_other_dict['incompatible'] += 1
                    if self.log_type == 'json':
                        statistics_other_dict['count_issues'].append(result.get('issue', {}))
                elif is_compatibility == 'WARNING':
                    statistics_other_dict['warning'] += 1
                else:
                    statistics_other_dict['compatible'] += 1
                del result
                suffix = other_file.split('.')[-1]
                if suffix in ['pyd', 'pyi', 'pyz', 'pyw', 'pyo', 'ipynb']:
                    statistics_other_dict['py'] += 1
                elif other_file.endswith('.pyc'):
                    statistics_other_dict['pyc'] += 1
                else:
                    statistics_other_dict['other'] += 1
            except Exception:
                traceback.print_exc()
        return statistics_other_dict

    def check_other_process_xarch(self, other_file_list, migrated_path, is_compatible, t_other):
        """
        The thread of analyzing the detection of other files.
        """
        statistics_other_dict = {
            'count_result': dict(),
            'noarch': 0,
            'aarch64': 0,
            'x86_64': 0,
            'uncertain': 0,
            'warning': 0
        }
        threads = []
        for other_file in other_file_list:
            if os.path.isdir(migrated_path):
                other_file = os.path.join(migrated_path, other_file)
            threads.append(t_other.submit(self.check_other_file_xarch, other_file, is_compatible))
        for task in as_completed(threads):
            try:
                result = task.result()
                if not result:
                    continue
                other_file = result.get('file_path', '')
                del result['file_path']
                statistics_other_dict['count_result'][other_file] = result
                category = result.get('category', 'uncertain')
                if category == 'noarch':
                    statistics_other_dict['noarch'] += 1
                elif category == 'aarch64':
                    statistics_other_dict['aarch64'] += 1
                elif category == 'x86_64':
                    statistics_other_dict['x86_64'] += 1
                elif category == 'warning':
                    statistics_other_dict['warning'] += 1
                else:
                    statistics_other_dict['uncertain'] += 1
                del result
            except Exception:
                traceback.print_exc()
        return statistics_other_dict

    def analysis_scaned_result(self, summary_list, total_count, start_time):
        """
        Analyze test results
        """
        if self.class_value == 'xarch':
            summary_result = summary_list[6]
            execution_results = [summary_list[0], summary_list[1], summary_list[2], summary_list[3], summary_list[4],
                                 summary_list[5], total_count]
            self.summary_print_xarch(execution_results, start_time)
        else:
            execution_results = [summary_list[1], summary_list[0], summary_list[4], summary_list[3], summary_list[2],
                                 total_count]
            self.summary_print(execution_results, start_time)
            if self.class_value == 'cs':
                return
            else:
                summary_result = summary_list[5]
        del summary_list
        self.create_report(execution_results, summary_result)

    def create_report(self, execution_results, summary_result):
        """
        Generate a report based on the specified format.
        """
        if self.log_type == 'csv':
            if self.class_value != 'udf':
                Summary().init_csv(self.class_value, self.log_type, self.migrated_list, execution_results,
                                   self.detection_command, self.execution_detection_time)

        elif self.log_type == 'txt':
            NormalizedOutput().log_normalized_output(self.log_type, Constant.log_path + '.log',
                                                     self.migrated_list,
                                                     execution_results, self.detection_command,
                                                     self.execution_detection_time, 'python')
        else:
            Constant.summary_dict = NormalizedOutput().log_normalized_output(self.log_type,
                                                                             Constant.log_path + '.json',
                                                                             self.migrated_list,
                                                                             execution_results,
                                                                             self.detection_command,
                                                                             self.execution_detection_time,
                                                                             'python')
        Summary().summary_content(summary_result, self.log_type, self.class_value)

    def exec_check(self, temp_list, migrated_path, warning_count, assigned_nu):
        if self.tree_output and self.class_value == 'cs':
            # 收集目录树信息
            _thread.start_new_thread(self.collect_dir_tree_info, (migrated_path, ))
        so_result, py_result = {}, {}
        compatible_list = temp_list[0]
        incompatible_list = temp_list[4]
        tbv_list = temp_list[5]
        skip_list = temp_list[6]
        other_result = {
            'count_result': dict(),
            'compatible': 0,
            'incompatible': 0,
            'warning': 0,
            'tbv': 0,
            'py': 0,
            'pyc': 0,
            'other': 0,
            'count_issues': [],
        }
        with ThreadPoolExecutor(2) as thread_pool:
            if temp_list[1]:
                so_result = self.check_so_thread(temp_list[1], thread_pool)
            if temp_list[2]:
                py_result = self.check_py_thread(temp_list[2], thread_pool)
            if compatible_list:
                other_result1 = self.check_other_process(compatible_list, migrated_path, 1, thread_pool)
                other_result = other_result1
            if incompatible_list:
                other_result['other'] += len(incompatible_list)
                other_result2 = self.check_other_process(incompatible_list, migrated_path, 2, thread_pool)
                other_result['count_result'].update(other_result2.get('count_result', {}))
                other_result['count_issues'] += other_result2.get('count_issues', [])
                other_result['incompatible'] += other_result2.get('incompatible', 0)
                other_result['warning'] += other_result2.get('warning', 0)
            if tbv_list:
                other_result['other'] += len(tbv_list)
                other_result3 = self.check_other_process(tbv_list, migrated_path, 3, thread_pool)
                other_result['count_result'].update(other_result3.get('count_result', {}))
                other_result['count_issues'] += other_result3.get('count_issues', [])
                other_result['tbv'] += other_result3.get('tbv', 0)
                other_result['warning'] += other_result3.get('warning', 0)
            if skip_list:
                self.check_other_process(skip_list, migrated_path, 4, thread_pool)
                other_result['tbv'] += len(skip_list)
        zip_result = {}
        if temp_list[3]:
            threads_zip = []
            process_nu = get_process_nu(len(temp_list[3]), assigned_nu)
            with ProcessPoolExecutor(process_nu) as process_pool:
                for zip_file in temp_list[3]:
                    threads_zip.append(process_pool.submit(self.deal_zip, zip_file))
                zip_result = self.count_result_zip(threads_zip)
        if self.tree_output:
            # 每一个进程单独 stop
            self.tree_queue.put('stop')
        # 汇总数据
        compatible = 0
        incompatible = 0
        warning = 0
        to_be_verified = 0
        other_file_count = 0  # so,py中error,解压失败视为other分类
        py_line_count = 0
        issues = []
        summary_dict = dict()

        compatible += (so_result.get('compatible', 0) + py_result.get('compatible', 0) +
                       zip_result.get('compatible', 0) + other_result.get('compatible', 0))
        incompatible += (so_result.get('incompatible', 0) + py_result.get('incompatible', 0) +
                         zip_result.get('incompatible', 0) + other_result.get('incompatible', 0))
        to_be_verified += (other_result.get('tbv', 0) + zip_result.get('tbv', 0))
        other_file_count += (py_result.get('error', 0) + zip_result.get('error', 0))
        warning += (so_result.get('warning', 0) + other_result.get('warning', 0) + warning_count)
        # 标准化输出 json每个检测目录为一个单元
        if self.log_type == 'json' and self.class_value == 'cs':
            self.json_report_productization(migrated_path, so_result, py_result, other_result, warning, zip_result)
            if self.tree_output:
                # 输出目录树
                Summary().write_json_log(self.dir_tree_path, self.root_node)
        else:
            summary_dict.update(so_result.get('count_result', {}))
            summary_dict.update(py_result.get('count_result', {}))
            summary_dict.update(zip_result.get('count_result', {}))
            summary_dict.update(other_result.get('count_result', {}))
            py_line_count += (py_result.get('py_line_count', 0) + zip_result.get('py_line_count', 0))
            issues += (so_result.get('count_issues', []) + py_result.get('count_issues', []) +
                       zip_result.get('count_issues', []) + other_result.get('count_issues', []))
        del so_result, py_result, zip_result, other_result
        return incompatible, compatible, warning, other_file_count, to_be_verified, summary_dict

    def exec_check_xarch(self, temp_list, migrated_path, warning_count, assigned_nu):
        so_result, py_result = {}, {}
        compatible_list = temp_list[0]
        incompatible_list = temp_list[4]
        tbv_list = temp_list[5]
        other_result = {
            'count_result': dict(),
            'x86_64': 0,
            'aarch64': 0,
            'noarch': 0,
            'uncertain': 0,
            'warning': 0
        }
        with ThreadPoolExecutor(2) as thread_pool:
            if temp_list[1]:
                so_result = self.check_so_thread_xarch(temp_list[1], thread_pool)
            if temp_list[2]:
                py_result = self.check_py_thread_xarch(temp_list[2], thread_pool)
            if compatible_list:
                other_result1 = self.check_other_process_xarch(compatible_list, migrated_path, 1, thread_pool)
                other_result['count_result'].update(other_result1.get('count_result', {}))
                other_result['noarch'] += len(compatible_list)
            if incompatible_list:
                other_result2 = self.check_other_process_xarch(incompatible_list, migrated_path, 2, thread_pool)
                other_result['count_result'].update(other_result2.get('count_result', {}))
                other_result['x86_64'] += other_result2.get('x86_64', 0)
                other_result['aarch64'] += other_result2.get('aarch64', 0)
                other_result['noarch'] += other_result2.get('noarch', 0)
                other_result['uncertain'] += other_result2.get('uncertain', 0)
                other_result['warning'] += other_result2.get('warning', 0)
            if tbv_list:
                other_result3 = self.check_other_process_xarch(tbv_list, migrated_path, 3, thread_pool)
                other_result['count_result'].update(other_result3.get('count_result', []))
                other_result['uncertain'] += other_result3.get('uncertain', 0)
                other_result['warning'] += other_result3.get('warning', 0)
        zip_result = {}
        if temp_list[3]:
            threads_zip = []
            process_nu = get_process_nu(len(temp_list[3]), assigned_nu)
            with ProcessPoolExecutor(process_nu) as process_pool:
                for zip_file in temp_list[3]:
                    threads_zip.append(process_pool.submit(self.deal_zip, zip_file))
                zip_result = self.count_result_zip_xarch(threads_zip)
        # 汇总数据
        summary_dict = dict()
        summary_dict.update(so_result.get('count_result', {}))
        summary_dict.update(py_result.get('count_result', {}))
        summary_dict.update(other_result.get('count_result', {}))
        summary_dict.update(zip_result.get('count_result', {}))
        noarch_count = (so_result.get('noarch', 0) + py_result.get('noarch', 0) +
                        other_result.get('noarch', 0) + zip_result.get('noarch', 0))
        aarch64_count = (so_result.get('aarch64', 0) + py_result.get('aarch64', 0) +
                         other_result.get('aarch64', 0) + zip_result.get('aarch64', 0))
        x86_64_count = (so_result.get('x86_64', 0) + py_result.get('x86_64', 0) +
                        other_result.get('x86_64', 0) + zip_result.get('x86_64', 0))
        uncertain_count = (so_result.get('uncertain', 0) + py_result.get('uncertain', 0) +
                           other_result.get('uncertain', 0) + zip_result.get('uncertain', 0))
        fail_count = py_result.get('failed', 0) + zip_result.get('failed', 0)
        warning_count = other_result.get('warning', 0) + warning_count
        del so_result, py_result, zip_result, other_result
        return noarch_count, aarch64_count, x86_64_count, uncertain_count, fail_count, \
            warning_count, summary_dict

    def collect_dir_tree_info(self, migrated_path):
        """
        Collect all file directory trees of the directory to be tested
        :param migrated_path: the directory path to be tested
        :return
        """
        migrated_path = migrated_path.rstrip('/')
        self.root_node = tree_dir_files(migrated_path, initial=True)
        while True:
            # 循环从消息队列中取出 zip文件解压后的 tree, 并添加至tree_node
            try:
                if self.tree_queue.empty():
                    continue
                zip_tree_node = self.tree_queue.get(timeout=10)
                if zip_tree_node == 'stop':
                    break
                if zip_tree_node:
                    # 挂载至树上
                    zip_path = list(zip_tree_node.keys())[0]
                    if self.ep_temp_files in zip_path:
                        zip_real_path = zip_path.split(self.ep_temp_files)[1].strip('/')
                    else:
                        zip_real_path = zip_path.split(migrated_path)[1].strip('/')
                    path_list = zip_real_path.split('/') if zip_real_path else []
                    path_list.insert(0, list(self.root_node.keys())[0].rstrip('/'))
                    pattern = re.compile(r'(\.[^/.x86_64]*?)\d{1,2}_\d{1,2}$')
                    path_list = [pattern.sub(r'\1', item) for item in path_list]
                    insert_flag = insert_children_into_node(self.root_node, path_list, zip_tree_node)
                    if not insert_flag:
                        real_path = '/'.join(path_list)
                        print('{} mount node failed! please check.'.format(real_path))
            except Exception:
                traceback.print_exc()
                break

    def exec_check_multithreading(self, paras_list, csv_log_path, verify_zip_list):
        """
        Detection process using multithreading
        """
        try:
            if verify_zip_list:
                self.verify_zip_list = [os.path.abspath(path) for path in verify_zip_list]
            self.execution_detection_time = df().get_command_result('date')

            self.migrated_list = paras_list[0]
            self.engine = paras_list[1]
            self.log_type = paras_list[2]
            self.output = paras_list[3]

            self.recommend = paras_list[4]
            self.class_value = paras_list[6]
            self.binary_check = paras_list[7]
            if not self.output and paras_list[10]:
                self.inner_log = True
            self.warning_check = paras_list[13]
            self.tree_output = paras_list[15]
            if self.class_value == 'cs' and self.tree_output:
                self.dir_tree_path = dir_tree_save_path_init(paras_list[16], Constant.current_path, self.time_str)
            self.detection_command = ' '.join(paras_list[8])
            if self.recommend and self.output:
                self.loading = True
                _thread.start_new_thread(self.program_loading, ())
            constant.schedule_tag = True
            if paras_list[9]:
                self.ep_temp_files = get_absolute_path_from_specified_path(paras_list[9], current_path, self.time_str)

            # 自定义输出文件名
            self.custom_output_file_name(paras_list[5], paras_list[1])

            start_time = time.time()
            # incompatible, compatible, warning, other_file_count, to_be_verified
            summary_list = [0, 0, 0, 0, 0, dict()]
            migrated_count = len(self.migrated_list)
            migrated_check_list = []
            with ThreadPoolExecutor(2) as thread_pool:
                for migrated_path in self.migrated_list:
                    warning_count = 0
                    migrated_path = os.path.abspath(migrated_path)
                    if os.path.isdir(migrated_path):
                        logger.info('Began collecting all files to be scanned.')
                        file_path_list = self.retrieve_all_file(migrated_path)
                        temp_list = self.classify_files(migrated_path, file_path_list, thread_pool)
                        logger.info('Ended collecting all files to be scanned.')
                    else:
                        self.file_num += 1
                        logger.info('Began collecting all files to be scanned.')
                        temp_list = self.classify_files(migrated_path, [migrated_path], thread_pool)
                        logger.info('Ended collecting all files to be scanned.')
                    if self.warning_check:
                        new_so_list = self.so_directory_pretreatment(temp_list[1])
                        warning_count += len(temp_list[1]) - len(new_so_list)
                        temp_list[1] = new_so_list
                    migrated_check_list.append((temp_list, migrated_path, warning_count))
            constant.schedule_tag = True
            constant.progress_engine = 'python'
            if not self.output:
                _thread.start_new_thread(progress_bar, (self.file_num, self.total_queue, self.inner_queue, 'python'))
            ph = ProcessHandle()
            ph.get_process_nu(paras_list[11])
            assigned_nu = ph.process_nu  # 根据指定参数判断进程池大小
            process_nu = get_process_nu(migrated_count, assigned_nu)
            if migrated_count == 1:
                temp_list = migrated_check_list[0][0]
                migrated_path = migrated_check_list[0][1]
                warning_count = migrated_check_list[0][2]
                if self.class_value == 'xarch':
                    summary_list = self.exec_check_xarch(temp_list, migrated_path, warning_count, assigned_nu)
                else:
                    summary_list = self.exec_check(temp_list, migrated_path, warning_count, assigned_nu)
            else:
                tasks = []
                with ProcessPoolExecutor(process_nu) as summary_pool:
                    for temp_list, migrated_path, warning_count in migrated_check_list:
                        if self.class_value == 'xarch':
                            task = summary_pool.submit(self.exec_check_xarch, temp_list, migrated_path, warning_count, assigned_nu)
                        else:
                            task = summary_pool.submit(self.exec_check, temp_list, migrated_path, warning_count, assigned_nu)
                        tasks.append(task)
                    for task in as_completed(tasks):
                        try:
                            result = task.result()
                            summary_list[0] += result[0]
                            summary_list[1] += result[1]
                            summary_list[2] += result[2]
                            summary_list[3] += result[3]
                            summary_list[4] += result[4]
                            summary_list[5].update(result[5])
                        except Exception as e:
                            traceback.print_exc()
                            print(e)
            if self.log_type == 'csv' and csv_log_path:
                Constant.log_path = csv_log_path

            # 写入日志
            self.analysis_scaned_result(summary_list, self.file_num, start_time)
            self.loading = False

            return 0
        except Exception as e:
            traceback.print_exc()
            print(e)
            MyError().display(MyError().report(e, Exception.__name__, "exec_check_multithreading", 'Exec Error'))
        finally:
            self.teardown_operation()
            if not self.output:
                constant.schedule_tag = False
                time.sleep(1)
                progress_bar_stop(self.file_num)
