#!/usr/bin/env python3
# coding=utf-8
import _thread
import copy
import csv
import json
import math
import multiprocessing as mp
import os.path
import pathlib
import re
import subprocess
import sys
import time

from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from concurrent.futures import as_completed
from itertools import zip_longest
from traceback import print_exc

from java.tools.java_searcher import RepositorySearch
from java.tools.java_recommendator import RecommendedTools as rt
from java.tools.java_scanner import PomFileProcessing as pp
from java.utils.java_utils import DocumentProcessing as dp, get_import_data, check_file
from java.utils.java_utils import DynamicLoading as dl
from java.utils.java_utils import LinuxCommandExecute as lc
from java.utils.java_utils import StandardLog as sl
from java.utils.java_utils import StringProcessing as sp
from tools.constant import zip_arg
from tools.constant import path_keyword, constant, arm_architecture, architecture_priority
from tools.decompressor import DecompressFiles as df
from tools.error import MyError
from tools.filter_rules import compatible_default_list, python_flag, link_file, compatible_file
from tools.normalized_output import NormalizedOutput as no
from tools.recommendator import Recommend as rc
from tools.progress_handle import progress_bar, progress_bar_stop
from tools.sqlit_db import MySqlite
from tools.utils import get_absolute_path_from_specified_path, get_file_md5, path_intersection, \
    ping_website, so_name_to_search, get_file_name, get_file_type, get_file_type_by_suffix, is_default_compatible_file, \
    execute_cmd, check_file_incompatible, so_document_classification, get_version_in_mf, \
    get_obj_version, so_skip_by_architecture, tree_dir_files, insert_children_into_node, mount_compatibility_into_node, \
    remove_file_path_suffix, dir_tree_save_path_init
from tools.utils import get_file_type_other as gft, get_file_real_type, read_link_src_path, determine_unpack

java_db_path = sys.argv[0]

logger = constant.logger
java_current_path = os.getcwd()


class MigrationCheck(object):
    """
    This is a migration check tool class.
    It is mainly used to verify whether the specified detection object
    can be migrated directly, and it can also recommend incompatible
    so packages contained in the object.
    Currently, the recommended sources are maven warehouse and github warehouse.
    """

    def __init__(self):
        self.isolation = "\n----------------------------------------------------------------------" \
                         "----------------------------------------------------------------------"
        self.failed_files = {}
        self.jar_pom_files = {}
        self.zip_unzip_path = {}
        self.zip_package_pom_path_results = {}
        self.mf_path_dict = {}

        self.queue_paths = mp.Manager().Queue()
        self.queue_counts = mp.Manager().Queue()
        self.connect_taobao = None
        self.detection_command = None
        self.detected_object = None
        self.execution_detection_time = None
        self.root_node = None
        self.dir_tree_path = None
        self.collect_tree = None
        self.zip_node_list = []
        self.incompatible_results = []
        self.compatible_results = []
        self.failed_results = []
        self.jars = []
        self.java_import_file = []
        self.decompress_file_paths = []
        self.non_test_file = []
        self.non_test_file_results = []
        self.compressed_to_python = []
        self.table_names = ["jar", "so_el7", "so_el8"]
        self.compatible_list = mp.Manager().Queue()
        self.detected_file_path = ''
        self.number = 0
        self.processes_number = 1
        self.so_warning_count = 0
        self.other_warning_count = 0
        self.so_file_count = 0
        self.jar_file_count = 0
        self.other_file_count = 0
        self.java_file_count = 0
        self.class_file_count = 0
        self.zip_file_count = 0
        self.pom_file_count = 0
        self.file_num = 0
        self.file_type = 'dir'
        self.log_type = 'txt'
        self.json_log_filename = ''
        self.csv_log_path = ''
        self.progress_tag = True
        self.log_file = None
        self.engine = None
        self.class_value = None
        self.quiet_mark = False
        self.binary_check = False
        self.recommend_mark = False
        self.codescan_json = False
        self.warning_check = False
        self.warning_tag = False
        self.tree_output = False
        self.inner_log = False
        self.broken_link = "broken symbolic link"
        self.skip_list = ['jnilib', 'Windows lib', 'Windows dll', 'Mac lib']

        self.total_queue = mp.Manager().Queue()
        self.inner_queue = mp.Manager().Queue()

        # --class xarch
        self.summary_data = []

        self.mvnsearch = RepositorySearch()

        self.time_str = time.strftime('%Y%m%d%H%M%S', time.localtime(int(round(time.time() * 1000)) / 1000))

        temp_files = os.path.expanduser('~/tmp/easyPorter')
        self.ep_temp_files = '{}/ep_tmp_{}'.format(temp_files, self.time_str)
        self.db_path = "{}/data/my.db".format(java_db_path[:java_db_path.rfind('/')])
        self.cfr_jar_path = None
        self.path_file = "{}/".format(self.ep_temp_files)
        self.result_log_file = "{}/result".format(java_current_path)
        self.not_arm_file = "{}/incompat_arm".format(self.ep_temp_files)
        self.arm_file = "{}/compat_arm".format(self.ep_temp_files)
        self.fail_log = "{}/failure".format(self.ep_temp_files)
        if hasattr(sys, '_MEIPASS'):
            # 如果是Pyinstaller打包后的程序，则获取临时目录路径
            self.db_path = os.path.join(sys._MEIPASS, 'my.db')

    def path_exist(self, file_path, real_path=None):
        """
        Determine whether the input package or source code path exists.
        If it exists, get the path of the given file in the directory.
        param file_path: -> string
            The absolute path to the file.
        return -> function or None
            Method to traverse folders or None.
        """
        for file in file_path:
            path = pathlib.Path(file)
            if path.exists():
                file_save_path = "{}{}".format(self.path_file, file.strip('./').replace('/', '_'))
                return dp().traverse_folder(file, file_save_path, self.class_value, real_path, self.ep_temp_files)

            else:
                print('{}: This file path does not exist, '
                      'please check and re execute!'.format(path))

        return

    def check_aarch64_exist(self, file_path):
        """
        Check whether the file is similar to arm.
        param file_path:
            The absolute path of the file.
        return:
            0: Representations are all arm type files.
            1: Represents a file that is not of arm type.
            file_path: The absolute path of the file.
        """
        arm_arg = 'aarch64'
        mark_arg = 'mark'
        result_arg = 'result'

        check_result = {}

        file_type = df().get_file_type(file_path)

        if arm_arg in file_type:
            check_result[mark_arg] = 0
            check_result[result_arg] = 0
            return check_result

        check_result[mark_arg] = 1
        check_result[result_arg] = file_path

        return check_result

    def get_path(self, file_path, package_name):
        for index, i in enumerate(arm_architecture):
            if index == 4:
                file_path_list = file_path.split(package_name)[-1].split("/")
                key_tag = None
                for item in file_path_list:
                    if "arm" in item:
                        key_tag = item
                        break
                if key_tag:
                    return file_path.split(key_tag)[0].rstrip("/")
            if re.search(i, file_path):
                return re.split(i, file_path)[0]
        return file_path

    def skip_warning2_so(self, so_path_list, dir_tag):
        """
        Output warning2 information.
        :param so_path_list: List of files to be processed
        :param zip_file:Is it in the compressed package.
        :param real_zip:The real path of zip.
        """
        for so_path in so_path_list:
            real_path = os.path.abspath(self.get_zip_path(so_path))
            if dir_tag:
                self.so_warning_count += 1
                logger.warning("Warning2 {}".format(real_path), 'java')
            else:
                logger.warning("Warning_ZIP2 {}".format(real_path), 'java')
            self.inner_path_print(real_path)

    def architecture_screen(self, so_dictionary, package_path=None, dir_tag=True):
        """
        param so_dictionary: -> dictionary
            So file set in the entire jar package.
        return: -> dictionary
        """
        new_so_dictionary = {}
        for project_name, so_group_dict in so_dictionary.items():
            new_so_dictionary[project_name] = {}
            for so_group, so_path_list in so_group_dict.items():
                find_so = False
                # 根据优先级顺序查找
                temp_so_list = []
                for architecture in architecture_priority:
                    for so_path in so_path_list:
                        find_str = so_path
                        if package_path:
                            zip_name = os.path.split(package_path)[-1]
                            find_str = so_path.split(zip_name)[-1]
                        if re.findall(architecture, find_str, re.I):
                            skip = so_skip_by_architecture(find_str)
                            if skip:
                                continue
                            so_path_list.remove(so_path)
                            self.skip_warning2_so(so_path_list, dir_tag)  # warning2 分组中剩余的so
                            temp_so_list.append(so_path)
                            find_so = True
                            break
                    if find_so:
                        break
                if not temp_so_list:
                    temp_so_list = so_path_list
                new_so_dictionary[project_name][so_group] = temp_so_list
        return new_so_dictionary

    def parse_so_document(self, so_dictionary, dir_tag=True):
        """
        The set of so files that have been classified according to the so file name.
        param so_dictionary: -> dictionary
            So file set in the entire jar package.
        return: -> dictionary
            so_mark: The verification result identifier of the so file.
        """
        mark_arg = 'mark'
        result_arg = 'result'
        so_mark = {}

        for project_name, so_group_dict in so_dictionary.items():
            so_mark[project_name] = {}
            for so_group, so_path_list in so_group_dict.items():
                marks = []
                inconformity = []

                for so_file in so_path_list:
                    if dir_tag:
                        logger.info('Began {}'.format(os.path.abspath(so_file)), 'java')
                    check_result = self.check_aarch64_exist(so_file)
                    if self.class_value != 'xarch':
                        marks.append(check_result.get(mark_arg))  # 包含0或者1
                        inconformity.append(check_result.get(result_arg))  # 包含0或者路径
                    if dir_tag:
                        logger.info('Ended {}'.format(os.path.abspath(so_file)), 'java')
                    self.inner_path_print(os.path.abspath(self.get_zip_path(so_file)))
                so_mark[project_name][so_group] = [marks, inconformity]

        return so_mark

    def skip_warning3_so(self, so_dictionary, package_path=None):
        """
        Output warning3 information.
        :param so_dictionary: Dict of files to be processed
        :return: so_dictionary->(Dict) Processed file dict.
        """
        # -w下过滤与arm架构无关的文件
        temp_dict = {}
        so_file_list = []
        for project_name, so_group_dict in so_dictionary.items():
            temp_dict[project_name] = {}
            for so_group, so_path_list in so_group_dict.items():
                temp_list = copy.deepcopy(so_path_list)
                for so_path in so_path_list:
                    file_type = get_file_type_by_suffix(so_path)
                    if file_type in self.skip_list:
                        real_path = os.path.abspath(self.get_zip_path(so_path))
                        if package_path:
                            logger.info('Warning_ZIP3 {}'.format(real_path), 'java')
                        else:
                            self.so_warning_count += 1

                            logger.warning("Warning3 {}".format(real_path), 'java')
                        self.inner_path_print(real_path)
                        temp_list.remove(so_path)
                if temp_list:
                    temp_dict[project_name][so_group] = temp_list
                    so_file_list += temp_list
        return temp_dict, so_file_list

    def auto_recommendation(self, so_name, version, log_type):
        """
        Call the auto recommendation tool to obtain the compatible version corresponding
        to the incompatible package.
        param so_name: -> string
            The absolute path of the file to be extracted.
        param version: -> string
            Version corresponding to so package.
        param log_type: -> string
            Set the format type of the saved result file. For example: csv, json, txt.
        return: -> None
        """
        file_name = self.get_recommended_keyword(so_name)

        return rt().self_recommended(10, 'json', 0, [file_name], log_type, version)

    def final_recommendation_result(self, package_so_res, so_dictionary):
        """
        Search the so files that cannot be migrated to obtain the final execution results.
        param package_so_res: -> dictionary
            The so package is filtered by arm.
        return: -> dictionary
            The result of so search in maven or github warehouse.
        """
        so_search_result = {}

        for project_name, so_group_dict in package_so_res.items():
            for so_group, mark_incom_list in so_group_dict.items():
                marks = mark_incom_list[0]
                for so_path in so_dictionary[project_name][so_group]:
                    if 0 not in marks:
                        so_search_result[so_path] = {"mark": '', "version": ''}
                    else:
                        so_search_result[so_path] = 0
        return so_search_result

    def final_recommendation_result_xarch(self, so_dictionary, so_category_dict, dir_tag=True):
        """
        Search the so files that cannot be migrated to obtain the final execution results.
        param package_so_res: -> dictionary
            The so package is filtered by arm.
        return: -> dictionary
            The result of so search in maven or github warehouse.
        """
        x86_64_count = 0
        noarch_count = 0
        uncertain_count = 0
        aarch64_count = 0
        failed_count = 0
        so_search_result = {}

        for project_name, so_group_dict in so_category_dict.items():
            for so_group, category_list in so_group_dict.items():
                so_list = so_dictionary.get(project_name, {}).get(so_group, [])
                if 'x86_64' in category_list and 'aarch64' in category_list or 'noarch' in category_list:
                    category = 'noarch'
                    noarch_count += len(so_list)
                elif 'aarch64' in category_list:
                    category = 'aarch64'
                    aarch64_count += len(so_list)
                elif 'x86_64' in category_list:
                    category = 'x86_64'
                    x86_64_count += len(so_list)
                elif 'failed' in category_list:
                    category = 'failed'
                    failed_count += len(so_list)
                else:
                    category = 'uncertain'
                    uncertain_count += len(so_list)
                for so_path in so_list:
                    real_path = os.path.abspath(self.get_zip_path(so_path))
                    if not dir_tag:
                        logger.info('Began {}'.format(real_path), 'java')
                    so_search_result[so_path] = category
                    if not dir_tag:
                        logger.info('Ended {}'.format(real_path), 'java')
                    self.inner_path_print(real_path)

        staticdata = [x86_64_count, aarch64_count, noarch_count, uncertain_count, failed_count]

        return so_search_result, staticdata

    def compression_filter(self, file_path, collect_jar_mark=False, collect_so_mark=False):
        """
        Filter compressed files, so that some special compression types
        do not perform decompression operations.
        param file_path: -> string
            The file path to check.
        param collect_jar_mark: -> boolean
            Whether to add to the list that only collects jar packages.
        return: -> string
            After filtering, the path of the compressed package that meets the requirements.
        """
        if os.path.exists(file_path.rstrip('/')) and os.path.isfile(file_path):
            type_str, file_path, file_type = self.class_file_type(file_path)
            return type_str

    def multi_threaded_decompression_get_path(self, jar_package_list, number, log_type,
                                              quiet_mark, json_log_filename):
        """
        Perform multi-threaded processing on multiple compressed packages,
        and obtain all file paths under each compressed package.
        param jar_package_list: -> list
        param number: -> int
            Specifies the number of threads to be started.
        param log_type: -> string
            Log save format.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        return: -> dictionary
            Paths of all files in the package corresponding to each compressed package.
        """
        all_paths = []

        if jar_package_list:
            all_jar_decompression_result = self.threading_executes(self.check_package_compatible,
                                                                   file_list=jar_package_list,
                                                                   number=number,
                                                                   log_type=log_type,
                                                                   mark=None,
                                                                   quiet_mark=quiet_mark,
                                                                   json_log_filename=json_log_filename,
                                                                   parent_path=None)

            for jar_decompression_result in all_jar_decompression_result:
                jar_file_dic = {}
                jar_path = jar_decompression_result.get("package_path")
                decompress_file_path = jar_decompression_result.get("decompress_file_path")
                file_path_list = jar_decompression_result.get("file_path_list")

                if type(decompress_file_path) is list:
                    self.decompress_file_paths.append(decompress_file_path[0])

                if type(file_path_list) is list:
                    jar_file_dic[jar_path] = file_path_list
                    all_paths.append(jar_file_dic)

        return all_paths

    def filter_pom_java_file(self, jar_path_dic, jar_names):
        """
        Filter all files in the compressed package to find pom files and java files.
        param jar_path_dic: -> dictionary
            All file paths in the compressed package.
        param jar_names: -> string
            The compressed package path to be filtered.
        return: -> dictionary
            A list of all jar files in the package.
            And Parsing results of all pom files in the package.
            And A list of all java files in the package.
        """
        jar_pom_parse_result = {}

        java_file_list = []
        jar_list = []

        for key in jar_names:
            pom_file_results = {}
            pom_path_results = {}

            jar_file_result = jar_path_dic[key]

            self.compression_filter(key, collect_jar_mark=True)

            for file_path in jar_file_result:
                compression_path = self.compression_filter(file_path, collect_jar_mark=True)
                if compression_path and compression_path != "other":
                    jar_list.append(file_path)

                pom_file = pp().pom_file_filter(file_path)

                if pom_file:
                    pom_parse_result = pp().summarize_final_pom_parse_results(key, pom_file)
                    pom_path_results[pom_file] = pom_parse_result
                    pom_parse_result_copy = copy.copy(pom_parse_result)
                    pom_file_results = pp().pom_parsed_result_processing(pom_file_results,
                                                                         pom_parse_result_copy)
                    pom_file_results_copy = copy.copy(pom_file_results)
                    jar_pom_parse_result = pp().pom_parsed_result_processing(jar_pom_parse_result,
                                                                             pom_file_results_copy)

                java_file = pp().class_file_filter(file_path)
                if java_file:
                    java_file_list.append(file_path)

            if pom_path_results:
                self.zip_package_pom_path_results = {
                    key: pom_path_results
                }

        filter_result = {
            "jar_list": list(set(jar_list)),
            "jar_pom_parse_result": jar_pom_parse_result,
            "java_file_list": list(set(java_file_list))
        }

        return filter_result

    def filter_pom_using_java_import(self, java_imports, pom_parse_result):
        """
        Use the import in the java file to filter the pom parsing results.
        param java_imports: -> list
            The import of the java file import.
        param pom_parse_result: -> dictionary
            pom file parsing result.
        return: -> dictionary
            Filter results.
        """
        java_pom_share_jar_dict = {}

        jar_key_list = list(pom_parse_result.keys())

        java_import_copy = copy.copy(java_imports)
        pom_parse_result_copy = copy.copy(pom_parse_result)

        for jar_key in jar_key_list:
            stop_mark = True
            index_arg = 0

            while stop_mark:
                java_imports_count = len(java_imports) - 1

                if java_imports[index_arg] == jar_key.split('/')[0]:
                    java_import_copy.remove(java_imports[index_arg])

                    del pom_parse_result_copy[jar_key]
                    java_pom_share_jar_dict[jar_key] = pom_parse_result[jar_key]

                    stop_mark = False

                if index_arg < java_imports_count:
                    index_arg += 1

                else:
                    stop_mark = False

        filter_result = {
            "java_and_pom_share": java_pom_share_jar_dict,
            "java_unique": java_import_copy,
            "pom_unique": pom_parse_result_copy
        }

        return filter_result

    def decompression_result_processing(self, all_path, number, log_type,
                                        quiet_mark, json_log_filename):
        """
        Process all file paths obtained after decompressing the jar package.
        Depending on the situation, decide whether to filter the java file,
        and whether to filter the pom analysis result through the import in the java file.
        param all_path: -> dictionary
            All file paths obtained after decompressing the jar package.
        param number: -> int
            Specifies the number of threads to be started.
        param log_type: -> string
            Log save format.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        return: -> None
        """
        if all_path:
            for jar_path_dic in all_path:
                java_file_check_import_result = []
                java_file_check_result = []
                jar_pom_parse_res = []

                jar_keys = list(jar_path_dic.keys())

                filter_pom_java_result = self.filter_pom_java_file(jar_path_dic, jar_keys)
                jar_list = filter_pom_java_result["jar_list"]
                java_file_list = filter_pom_java_result["java_file_list"]
                jar_pom_parse_result = filter_pom_java_result["jar_pom_parse_result"]

                # If the large jar package contains multiple small jar packages or does not contain small jar packages,
                # then directly parse the pom file; if only one small jar package is included,
                # first filter the import in the java file,
                # and then use the import information to filter the pom Parsing results.
                if len(jar_list) == 1:
                    java_files = []

                    sub_jar_all_path = self.multi_threaded_decompression_get_path(jar_list, number, log_type,
                                                                                  quiet_mark, json_log_filename)

                    if sub_jar_all_path:
                        for path_dic in sub_jar_all_path:
                            key_args = list(path_dic.keys())

                            filter_result = self.filter_pom_java_file(path_dic, key_args)

                            jar_pom_parse_res = filter_result["jar_pom_parse_result"]
                            java_files = filter_result["java_file_list"]

                    if java_files:
                        java_file_check_import_result = self.threading_executes_java_pom(pp().java_file_import_filter,
                                                                                         number=4,
                                                                                         log_type=log_type,
                                                                                         file_list=java_files,
                                                                                         mark=java_files,
                                                                                         quiet_mark=self.cfr_jar_path,
                                                                                         json_log_filename=json_log_filename)

                if jar_pom_parse_result:
                    self.jar_pom_files = pp().pom_parsed_result_processing(jar_pom_parse_result, self.jar_pom_files)

                if java_file_list:
                    java_file_check_result = self.threading_executes_java_pom(pp().java_file_import_filter,
                                                                              number=4,
                                                                              log_type=log_type,
                                                                              file_list=java_file_list,
                                                                              mark=java_file_list,
                                                                              quiet_mark=self.cfr_jar_path,
                                                                              json_log_filename=json_log_filename)

                java_file_check_import_result += java_file_check_result

                # Filter pom using java import filter result.
                if java_file_check_import_result and jar_pom_parse_res:
                    java_filter_pom_result = self.filter_pom_using_java_import(java_file_check_import_result,
                                                                               jar_pom_parse_res)

                    self.jar_pom_files = pp().pom_parsed_result_processing(java_filter_pom_result["pom_unique"],
                                                                           self.jar_pom_files)

                    self.java_import_file += java_filter_pom_result["java_unique"]

        return

    def filter_pom_file_get_parsed_result(self, jar_file_path, pom_list, java_list):
        """
        Filter the pom file contained in the detection object,
        and parse to obtain the result.
        param jar_file_path: -> string
            The absolute path of the packet to be detected.
        param path_list: -> list
            Absolute paths to all files contained in the detection object.
        return: -> dictionary or None
            Pom file parsing result.
        """
        pom_path_results = {}
        pom_file_results = {}
        java_file_parse_result = []

        if pom_list or java_list:
            if pom_list:
                for pom_file in pom_list:
                    # pom文件进行解析
                    pom_parse_result = pp().summarize_final_pom_parse_results(jar_file_path, pom_file)
                    pom_path_results[pom_file] = pom_parse_result
                    pom_parse_result_copy = copy.copy(pom_parse_result)
                    pom_file_results = pp().pom_parsed_result_processing(pom_file_results, pom_parse_result_copy)
            if java_list:
                for java_file in java_list:
                    # java文件进行解析
                    java_file_parse_res = pp().java_file_import_filter(java_file, number=None,
                                                                       log_type=None, file_list=None,
                                                                       quiet_mark=self.cfr_jar_path,
                                                                       java_files=[java_file],
                                                                       json_log_filename=None)

                    java_file_parse_result += java_file_parse_res

        else:
            pom_file = pp().pom_file_filter(jar_file_path)  # 过滤pom文件
            java_file = pp().class_file_filter(jar_file_path)  # 过滤java文件
            if pom_file:
                pom_parse_result = pp().summarize_final_pom_parse_results(jar_file_path, pom_file)
                pom_path_results[pom_file] = pom_parse_result
                pom_parse_result_copy = copy.copy(pom_parse_result)
                pom_file_results = pp().pom_parsed_result_processing(pom_file_results, pom_parse_result_copy)
            elif java_file:
                java_file_parse_res = pp().java_file_import_filter(jar_file_path, number=None,
                                                                   log_type=None, file_list=None,
                                                                   quiet_mark=self.cfr_jar_path,
                                                                   java_files=[jar_file_path],
                                                                   json_log_filename=None)

                java_file_parse_result += java_file_parse_res
            else:
                return

        if pom_path_results:
            self.zip_package_pom_path_results = {
                jar_file_path: pom_path_results
            }

        filter_result = {
            "pom_file_results": pom_file_results,
            "java_file_parse_result": list(set(java_file_parse_result))
        }

        return filter_result

    def check_package_compatible(self, package_path, number, log_type, mark,
                                 quiet_mark, json_log_filename, parent_path=None):
        """
        Check whether the compressed package meets the migration requirements.
        param package_path: -> string
            The absolute path of the file to be extracted.
        param log_type: -> string
            Log save format.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        return:
            The file path after decompression, which can be shared, can not be shared,
        and can not be shared file list.
            decompress_file_path: -> list
                The extracted folder path list of the detection object.
            file_path_list: -> list
                The absolute path list of all sub files in the folder.
            1: -> int
                Indicates that the decompression requirements are not met,
                and no sub-files are generated
        """
        so_arg = "elf"
        file_type = ""
        ep_tmp_mark = "/ep_tmp_2"
        decompress_path = None

        java_file_types = ["java class data", "java source"]
        pkg_section_lower = []

        return_result = {}

        if os.path.isfile(package_path):
            file_type = df().get_file_type(package_path).split(',')[0]
            pkg_section_lower = file_type.lower().split(' ')

        if (not os.path.isdir(package_path)
                and (so_arg not in pkg_section_lower and
                     java_file_types[0] not in file_type.lower() and
                     java_file_types[1] not in file_type.lower())):
            # 过滤特殊压缩类型，使其不进行解压操作
            document_process_result = df().special_archive_filtering('java', package_path)

            if document_process_result:
                # 对文件进行解压操作
                decompress_mark, decompress_result = df().decompress_package(package_path,
                                                                             zip_unzip_path=self.zip_unzip_path,
                                                                             temporary_file_path=self.ep_temp_files)
                record_info = decompress_result.get('record_info')
                # 如果文件解压结果标识为1和2，则说明解压成功
                if decompress_mark == 1 or decompress_mark == 2:
                    if record_info:
                        logger.info(record_info, 'java')

                    decompress_path = decompress_result.get('decompress_path')
                    decompress_temp_path = decompress_result.get('zip_unzip_path')
                    self.zip_unzip_path[decompress_path] = decompress_temp_path
                    if self.class_value == 'cs' and self.tree_output:
                        # 生成解压后的临时路径目录树
                        zip_node = tree_dir_files(decompress_path, decompress_temp_path, True)
                        return_result["zip_node"] = zip_node
                    # 补充思路
                    if ep_tmp_mark in package_path:
                        self.zip_unzip_path[package_path] = decompress_temp_path

                elif decompress_mark == 3 or decompress_mark == 4:
                    if "Need to be verified" in record_info:
                        content = "Skipped {}".format(package_path)
                        logger.warning(content, 'java')
                    else:
                        logger.info(record_info, 'java')
                    return_result["package_path"] = package_path
                    return_result["decompress_file_path"] = 1
                    return_result["file_path_list"] = 1
                    if decompress_mark == 3:
                        return_result["decompress_failed"] = True
                    return return_result
                else:
                    # 文件解压标记为5的情况下说明没有该解压命令
                    logger.info(record_info, 'java')
                    return_result["package_path"] = package_path
                    return_result["decompress_file_path"] = 5
                    return_result["file_path_list"] = 1
                    if decompress_mark == 5:
                        return_result["miss_command"] = True
                    return return_result

            else:
                return_result["package_path"] = package_path
                return_result["decompress_file_path"] = 1
                return_result["file_path_list"] = 1

                return return_result

        elif (os.path.isfile(package_path) and
              (so_arg in pkg_section_lower or
               java_file_types[0] in file_type.lower() or
               java_file_types[1] in file_type.lower())):

            return_result["package_path"] = package_path
            return_result["decompress_file_path"] = [package_path]
            return_result["file_path_list"] = [package_path]

            return return_result

        # 对解压成功的文件，读取临时文件中记录的此压缩包包含的所有文件绝对路径
        if decompress_path:
            try:
                return_result["package_path"] = package_path
                return_result["decompress_file_path"] = [decompress_path]
                return_result["file_path_list"] = []
                return return_result
            except Exception as e:
                print(e)
                # 收集解压后路径中文件列表失败，失败全局变量添加csvdata
                self.inspection_result_output(package_path, 0, -1, log_type,
                                              quiet_mark, json_log_filename)
        else:
            # 解压失败，输出csvdata
            self.inspection_result_output(package_path, 0, -1, log_type,
                                          quiet_mark, json_log_filename)

        return_result["package_path"] = package_path
        return_result["decompress_file_path"] = package_path
        return_result["file_path_list"] = 1
        return return_result

    def multi_process_execution(self, custom_function1, custom_function2,
                                processes_number, file_path_list):
        """
        Multiprocess files.
        param custom_function1: -> function
            A custom function to be multiprocessed.
        param custom_function2: -> function
            A custom function to be multiprocessed.
        param processes_number: -> int
            The specified number of processes.
        param file_path_list: -> list
            The object to be processed by the custom function.
        return: -> list
            The result after processing by the custom function.
        """
        stop_arg = 'stop'
        pool_count = None
        check_result = []

        if custom_function2:
            pool_count = mp.Pool(processes=int(processes_number))
        pool_unzip = mp.Pool(processes=int(processes_number))

        pool_unzip.imap(custom_function1, file_path_list)
        pool_unzip.close()
        pool_unzip.join()

        self.queue_paths.put(stop_arg)

        while True:  # 从消息队列中获取检测结果，并保存到list中
            try:
                if custom_function2:
                    pool_count.apply_async(custom_function2, args=())
                    res = self.queue_counts.get(timeout=0.1)
                else:
                    res = self.queue_paths.get(timeout=0.1)

                if res == stop_arg:
                    break
                if res:
                    check_result.append(res)
            except Exception as e:
                print(e)
                break

        return check_result

    def get_jar_so_files(self, package_path, number, log_type, mark,
                         quiet_mark, json_log_filename, parent_path=None,
                         filter_non_text_file_result=False, decompress_failed_mark=False):
        """
        Get all so files in the jia package.
        param package_path: -> str
            The absolute path of the packet to be detected.
        param number: -> int
            Specifies the number of threads.
        param log_type: -> str
            Specify the result record format.
        param mark: -> boolean
            Indicates whether to evaluate only.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        param filter_non_text_file_result: -> boolean
            Whether to contain the identification of the py type file.
        return: -> boolean or dictionary
            filter_non_text_file_result:
                Whether to contain the identification of the py type file.
            jar_so_files:
                The corresponding so file in the jar package.
        """
        try:
            mark_arg = 0
            jar_so_files = {
                'failed_zip_list': [],
                'zip_node_list': [],
            }
            jar_list = []
            so_list = []
            other_list = []
            java_list = []
            pom_list = []
            check_result = self.check_package_compatible(package_path,
                                                         number,
                                                         log_type,
                                                         mark_arg,
                                                         quiet_mark,
                                                         json_log_filename)

            decompress_file_path = check_result.get("decompress_file_path")
            zip_node = check_result.get("zip_node", {})
            jar_so_files['zip_node_list'].append(zip_node)

            if check_result.get('decompress_failed', ''):
                parent_zip_name = get_file_name(parent_path)
                jar_so_files['failed_zip_list'].append(package_path.split(parent_zip_name)[-1].strip('/'))
                decompress_failed_mark = True
            if isinstance(decompress_file_path, list) and os.path.isdir(decompress_file_path[0]):
                # 根据解压路径，获取文件列表
                real_path = os.path.abspath(self.get_zip_path(package_path))
                if self.binary_check and self.warning_tag:
                    # 只检测so与内部zip
                    jar_list, so_list, other_list, inner_file_nu, com_file_nu = \
                        self.get_dir_files(decompress_file_path[0], real_path)
                else:
                    if self.processes_number:
                        # 外部指定-n时，避免线程切换开销，默认使用单进程
                        jar_list, so_list, other_list, java_list, pom_list, com_file_nu, inner_file_nu = \
                            self.get_dir_files_single(decompress_file_path[0], real_path, package_path)
                    else:
                        # 外部不指定-n时，内部使用4线程进行检测，提升单包检测效率
                        jar_list, so_list, other_list, java_list, pom_list, com_file_nu, inner_file_nu = \
                            self.get_dir_files_pool(decompress_file_path[0], real_path, package_path)

            if other_list:
                filter_non_text_file_result = self.filter_non_text_file(other_list)
                if filter_non_text_file_result:
                    filter_non_text_file_result = True

            if check_result.get('miss_command'):
                parent_zip_name = get_file_name(parent_path)
                jar_so_files['failed_zip_list'].append(package_path.split(parent_zip_name)[-1].strip('/'))
                filter_non_text_file_result = True

            if type(decompress_file_path) is list:
                mark_arg = 1
                for file_path in jar_list:
                    res, other_list_ = self.get_jar_so_files(file_path, number, log_type, mark,
                                                             quiet_mark, json_log_filename,
                                                             package_path, filter_non_text_file_result)

                    if res:
                        jar_so_files[list(res.keys())[0]] = list(res.values())[0]
                        jar_so_files['filter_non_text_file_result'] = filter_non_text_file_result
                        if res.get('failed_zip_list', []):
                            jar_so_files['failed_zip_list'] += res.get('failed_zip_list')
                        jar_so_files['zip_node_list'] += res.get('zip_node_list', [])

                    if other_list_:
                        other_list.extend(other_list_)

                if not so_list and mark_arg == 0:
                    jar_so_files['filter_non_text_file_result'] = filter_non_text_file_result

                else:
                    jar_so_files[package_path] = so_list
                    jar_so_files['filter_non_text_file_result'] = filter_non_text_file_result

            elif type(decompress_file_path) is int:
                jar_so_files['filter_non_text_file_result'] = filter_non_text_file_result
                jar_so_files['decompress_failed_mark'] = decompress_failed_mark

            self.inner_path_print(self.get_zip_path(package_path))
            return jar_so_files, other_list
        except Exception:
            print_exc()
            return {}, []

    def filter_jar_file(self, java_file_parse_result, all_jars, number, log_type,
                        quiet_mark, json_log_filename):
        """
        Use the pom file parsing results and jave import file to
        filter all jar packages in the detection object.
        param java_file_parse_result: -> list
            Java file parsing result.
        param all_jars: -> list
            Detects all jar files contained in the object.
        param number: -> int
            Specifies the number of threads.
        param log_type: -> str
            Specify the result record format.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        return: -> dictionary
            The detection results include the common parts of jar and pom,
            the common parts of jar and java import, and the non-common parts.
        """
        all_jar_path_dict = self.multi_threaded_decompression_get_path(all_jars, number, log_type,
                                                                       quiet_mark, json_log_filename)

        if all_jar_path_dict:
            self.decompression_result_processing(all_jar_path_dict, number, log_type,
                                                 quiet_mark, json_log_filename)
        elif java_file_parse_result:
            pass
        else:
            return

        jar_pom_share_data_dict = {}
        jar_java_share_data_list = []

        if self.jars:
            jar_list = copy.copy(self.jars)

            if self.jar_pom_files:
                jar_pom_share_data_dict = self.filter_jar_using_pom_file(jar_list)

            self.java_import_file += java_file_parse_result
            if self.java_import_file:
                self.java_import_file = list(set(self.java_import_file))
                jar_java_share_data_list = self.filter_jar_using_java_import_file(jar_list)
        else:
            self.java_import_file += java_file_parse_result
            self.java_import_file = list(set(self.java_import_file))

        filter_jar_result = {
            "jar_pom_share_data_dict": jar_pom_share_data_dict,
            "jar_java_share_data_list": jar_java_share_data_list,
            "unique_jar": list(set(self.jars)),
            "unique_pom": self.jar_pom_files,
            "unique_java_import": self.java_import_file
        }

        return filter_jar_result

    def filter_jar_using_pom_file(self, jar_list):
        """
        Use the parsing results of pom files to filter all collected jar files.
        param jar_list: -> list
            Detects all jar files contained in the object.
        return: -> dictionary
            Common parts filtered by pom parsing results.
        """
        jar_pom_share_data = {}

        jar_pom_parse_result = copy.copy(self.jar_pom_files)
        jar_pom_keys = list(jar_pom_parse_result.keys())

        for pom_key in jar_pom_keys:
            pom_value = jar_pom_parse_result[pom_key]
            jar_version = pom_value["version"]

            if jar_version:
                for ver in jar_version:
                    if ver:
                        jar_name_splicing = "{}-{}.".format(pom_key.replace('.', '/'), ver)
                    else:
                        jar_name_splicing = "{}.".format(pom_key.replace('.', '/'))

                    stop_mark = True
                    index_arg = 0
                    while stop_mark:
                        jar_list_count = len(jar_list) - 1

                        if jar_name_splicing in jar_list[index_arg]:
                            try:
                                self.jars.remove(jar_list[index_arg])
                                del self.jar_pom_files[pom_key]
                                jar_pom_share_data[pom_key] = pom_value
                                stop_mark = False
                            except Exception:
                                pass

                        if index_arg < jar_list_count:
                            index_arg += 1
                        else:
                            stop_mark = False
        return jar_pom_share_data

    def filter_jar_using_java_import_file(self, jar_list):
        """
        Use the java file import to filter all collected jar files.
        param jar_list: -> list
            Detects all jar files contained in the object.
        return: -> list
            Common parts filtered by java file import.
        """
        jar_java_share_data = []

        if self.java_import_file:
            java_import_file_copy = copy.copy(self.java_import_file)
            for import_file in java_import_file_copy:
                match_str = import_file.replace('.', '/')

                stop_mark = True
                index_arg = 0
                while stop_mark:
                    jar_list_count = len(jar_list) - 1

                    if match_str in jar_list[index_arg]:
                        try:
                            self.jars.remove(jar_list[index_arg])
                            self.java_import_file.remove(import_file)
                            jar_java_share_data.append(match_str)
                            stop_mark = False
                        except Exception:
                            pass

                    if index_arg < jar_list_count:
                        index_arg += 1
                    else:
                        stop_mark = False

        return jar_java_share_data

    def loop_snippet_matching_java_import(self, mysql, snippet_list, match_str, table_name):
        """
        According to the snippet found in the database, then parse the dependency content,
        use java import to match it, and obtain the version number.
        param mysql: -> class
            Object for database operations.
        param snippet_list: -> list
            The snippet data read by the database.
        param match_str: -> string
            The java import data to be matched.
        param table_name: -> string
            The table name currently being searched.
        return: -> set
            The corresponding version number found in the database.
        """
        version_url_info = None
        groupid_arg = "groupId"
        atrifactid_arg = "artifactId"

        for snippet in snippet_list:
            jar_name = ''
            groupid_data = ''
            artifactid_data = ''
            dependency_data = []

            if snippet[0]:
                dependency_data = snippet[0].split('\n')

            if len(dependency_data) >= 3:

                if groupid_arg in dependency_data[1]:
                    groupid_data = dependency_data[1].strip(' ').split("{}>".format(groupid_arg))[1].rstrip("</")

                if atrifactid_arg in dependency_data[2]:
                    artifactid_data = dependency_data[2].strip(' ').split("{}>".format(atrifactid_arg))[1].rstrip("</")

                if groupid_data and artifactid_data:
                    jar_name = "{}.{}".format(groupid_data, artifactid_data)

            if match_str == jar_name:
                artifactid_data = so_name_to_search(artifactid_data)
                sql_search_version = "SELECT minversion, version, repo_url, snippet FROM {} WHERE name like '{}';" \
                    .format(table_name, artifactid_data + '%')
                version_url_info = mysql.search_one(sql_search_version)

                if version_url_info:
                    return version_url_info

        return version_url_info

    def pom_java_import_matching_version(self, pom_or_java_import_file, log_type, mark):
        """
        Match the version number of pom and java import.
        param pom_or_java_import_file: -> dictionary or list
            The pom analysis result or the import data in the java file.
        param log_type: -> string
            Specifies the log saving format.
        param mark: -> boolean
            Indicates whether to evaluate only.
        return: -> None
        """
        mark_arg = 'mark'
        version_arg = 'version'
        repo_url_arg = 'repo_url'
        minversion_arg = 'minversion'
        insert_table_name = 'so_el8'

        from_marks = ['0', '1', '2']
        java_import_pom_match_result = {}

        mysql = MySqlite(self.db_path)

        if type(pom_or_java_import_file) is dict:
            cycled_list = list(pom_or_java_import_file.keys())
            slice_mark = '/'
        else:
            cycled_list = pom_or_java_import_file
            slice_mark = '.'

        for list_arg in cycled_list:
            version_url_info = None
            stop_mark = True
            index_arg = 0
            while stop_mark:
                table_count = len(self.table_names) - 1
                table_name = self.table_names[index_arg]

                if type(pom_or_java_import_file) is dict:
                    so_name = list_arg.split(slice_mark)[-1]
                    so_name_sql = so_name_to_search(so_name)
                    sql_select = 'SELECT minversion, version, repo_url, snippet FROM {} WHERE name like "{}";'. \
                        format(table_name, so_name_sql + "%")
                    version_url_info = mysql.search_one(sql_select)
                else:
                    # Loop query results, parse out the dependency content and match it with java import.
                    sql_select = 'SELECT snippet FROM {};'.format(table_name)
                    snippet_info = mysql.search_all(sql_select)

                    if snippet_info and len(snippet_info) > 1:
                        version_url_info = self.loop_snippet_matching_java_import(mysql, snippet_info,
                                                                                  list_arg, table_name)

                if version_url_info:
                    stop_mark = False

                if index_arg < table_count:
                    index_arg += 1
                else:
                    stop_mark = False

            if (not version_url_info or
                    (not version_url_info[0] and
                     not version_url_info[1])):
                # If the database does not match, go to the maven warehouse or github to search,
                # and add the search results to the database.
                if type(pom_or_java_import_file) is dict:
                    search_key = list_arg.split('/')[-1]
                    save_key = list_arg.replace('.', '/')
                else:
                    search_key = list_arg
                    save_key = list_arg

                if mark:
                    maven_github_search = self.auto_recommendation(search_key, from_marks[0], log_type)
                    java_import_pom_match_result[save_key] = maven_github_search

                    insert_name = list_arg.split(slice_mark)[-1]
                    insert_version = maven_github_search[version_arg]

                    sql_insert = 'INSERT INTO {}(name, version) VALUES(?, ?);'.format(insert_table_name)

                    mysql.execute(sql_insert, (insert_name, insert_version))
                else:
                    java_import_pom_match_result[list_arg] = {mark_arg: -1,
                                                              version_arg: '',
                                                              minversion_arg: '',
                                                              repo_url_arg: ''}

            else:
                if version_url_info[3] in from_marks:
                    from_mark = int(version_url_info[3])
                else:
                    from_mark = 0

                if not version_url_info[0]:
                    minversion_arg = version_url_info[1]
                else:
                    minversion_arg = version_url_info[0]

                save_info = {
                    mark_arg: from_mark,
                    version_arg: version_url_info[1],
                    minversion_arg: minversion_arg,
                    repo_url_arg: version_url_info[2]
                }
                if type(pom_or_java_import_file) is dict:
                    java_import_pom_match_result[list_arg.replace('.', '/')] = save_info
                else:
                    java_import_pom_match_result[list_arg] = save_info

        return java_import_pom_match_result

    def pom_java_import_recommend(self, jar_filter_results, log_type, mark):
        """
        Recommended version of pom and java import data.
        param jar_filter_results: -> dictionary
            Use pom analysis results and java import to filter jar package results.
        param log_type: -> string
            Specifies the log saving format.
        param mark: -> boolean
            Indicates whether to evaluate only.
        return: -> None
        """
        pom_matching_result = {}
        java_import_matching_result = {}

        unique_poms = jar_filter_results["unique_pom"]
        unique_java_imports = jar_filter_results["unique_java_import"]

        if unique_poms:
            pom_matching_result = self.pom_java_import_matching_version(unique_poms, log_type, mark)
        if unique_java_imports:
            java_import_matching_result = self.pom_java_import_matching_version(unique_java_imports, log_type, mark)

        pom_java_import_matching_result = pp().pom_parsed_result_processing(pom_matching_result,
                                                                            java_import_matching_result)

        return pom_java_import_matching_result

    def jar_name_processing(self, jar_name):
        """
        Process the jar package name, if it has a version number,
        it will be removed, and if it has a suffix, it will also be removed.
        param jar_name: -> string
            The name of the jar package.
        return: -> None
        """
        if '.' in jar_name:
            jar_name = jar_name.split('.')[0]

        if '_' in jar_name:
            jar_name = jar_name.split('_')[1]

        if '-' in jar_name:
            jar_name = jar_name.split('-')[0]

        return jar_name

    def jar_package_filter_matching(self, initial_filter_result, jar_list, number, log_type, mark,
                                    quiet_mark, json_log_filename, parent_path=None):
        """
        Through the analysis and filtering of the pom file in the detection object,
        the analysis and filtering of java import data,
        the collection and filtering of sub-jar packages,
        and then the data remaining after filtering are sent to the database for matching.
        param initial_filter_result: -> dictionary
            The result of parsing the pom file and class file.
        param jar_list: -> list
        param number: -> int
            Specifies the number of threads.
        param log_type: -> str
            Specify the result record format.
        param mark: -> boolean
            Indicates whether to evaluate only.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        return: -> dictionary
            The result of the matching version of pom and java import,
            and all so files included in the detection object.
        """
        all_so_list = []
        other_list = []
        pom_java_import_match_version_res = {}

        if initial_filter_result:
            filter_jar_using_pom_file_result, pom_java_import_match_version_res \
                = self.initial_filter_result_processing(initial_filter_result, jar_list, number,
                                                        log_type, mark, quiet_mark, json_log_filename)

            if jar_list:
                # Decompress and evaluate the recommended operation.
                get_file = self.threading_executes(self.get_jar_so_files,
                                                   file_list=jar_list,
                                                   number=number,
                                                   log_type=log_type,
                                                   mark=mark,
                                                   quiet_mark=quiet_mark,
                                                   json_log_filename=json_log_filename,
                                                   parent_path=parent_path)
                all_so_list = []
                other_list_jar = []
                for item in get_file:
                    jar_so_files, other_list_inner = item
                    del jar_so_files['failed_zip_list']
                    del jar_so_files['zip_node_list']
                    all_so_list.append(jar_so_files)
                    other_list_jar.extend(other_list_inner)
                other_list.extend(other_list_jar)

        jar_package_filter_result = {
            "pom_java_import_match_version_res": pom_java_import_match_version_res,
            "all_so_list": all_so_list,
            "other_list": other_list
        }

        return jar_package_filter_result

    def initial_filter_result_processing(self, initial_filter_result, jar_list, number,
                                         log_type, mark, quiet_mark, json_log_filename):
        """
        Process the results of pom or java files parsed by
        the preliminary filtering of detected objects.
        param initial_filter_result: -> dictionary
            The result of parsing the pom file and class file.
        param jar_list: -> list
        param number: -> int
            Specifies the number of threads.
        param log_type: -> str
            Specify the result record format.
        param mark: -> boolean
            Indicates whether to evaluate only.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        return: -> None or dictionary
            The return is empty or the parsing result of the pom or java file.
        """
        filter_jar_using_pom_file_result = None
        pom_java_import_match_version_res = None

        pom_file_results = initial_filter_result["pom_file_results"]
        java_file_parse_result = initial_filter_result["java_file_parse_result"]

        # Pom analysis result.
        if pom_file_results:
            self.jar_pom_files = pp().pom_parsed_result_processing(pom_file_results, self.jar_pom_files)

        # Filter all jar packages using the results of java files and pom parsing data.
        if java_file_parse_result:
            filter_jar_using_pom_file_result = self.filter_jar_file(java_file_parse_result, jar_list, number,
                                                                    log_type, quiet_mark, json_log_filename)
        elif self.jar_pom_files:
            filter_jar_using_pom_file_result = {
                "jar_pom_share_data_dict": None,
                "jar_java_share_data_list": None,
                "unique_jar": None,
                "unique_pom": self.jar_pom_files,
                "unique_java_import": self.java_import_file
            }

        # In the detection and filtering results, if pom/java import still has data,
        # it will be searched and recommended in the database.
        if filter_jar_using_pom_file_result:
            pom_java_import_match_version_res = self.pom_java_import_recommend(filter_jar_using_pom_file_result,
                                                                               log_type, mark)

        return filter_jar_using_pom_file_result, pom_java_import_match_version_res

    def filter_non_text_file(self, package_paths):
        """
        Filter out text type files and detect whether the file contains py files or special compression type files.
        param package_paths: -> list
            A list of file paths to filter.
        return: -> boolean
            Whether the file contains py files or special compression types.
        """
        python_arg = 'python script'

        if type(package_paths) is int:
            return False

        for file_path in package_paths:
            if type(file_path) is not str:
                continue
            file_type = df().get_file_type(file_path)
            if not file_type:
                return True
            else:
                if python_arg in file_type.lower():
                    return True

        return False

    def get_dir_files_pool(self, dir_path, real_path, package_path):
        """
        Use multithreading to get all files in the test package.
        param dir_path: -> str
            The decompression directory of the zip file to be detected.
        param real_path: -> str
            The real path of the zip file to be detected.
        param package_path: -> str
            The absolute path of the zip file to be detected.
        return: -> list
            A list of all files in the test package.
        """
        so_list = []
        jar_list = []
        other_list = []
        java_list = []
        pom_list = []
        com_file_nu = 0
        inner_file_nu = 0
        with ThreadPoolExecutor(4) as thread_pool:
            tasks = []
            for root, dirs, files in os.walk(dir_path):
                if self.class_value == 'cs':
                    dirs[:] = [d for d in dirs if not self.skip_non_detection_dir(root, d, real_path)]

                for file in files:
                    inner_file_nu += 1
                    doc_path = os.path.join(root, file)
                    tasks.append(thread_pool.submit(self.class_file_type, doc_path))
            for task in as_completed(tasks):
                type_str, file_path, file_type = task.result()
                if package_path.endswith('.jar') and compatible_file.lower() in file_path.lower():
                    self.mf_path_dict[package_path] = file_path
                if self.warning_tag and file_type in self.skip_list:
                    if real_path:
                        file_path = file_path.replace(self.ep_temp_files, os.path.split(real_path)[0])
                    logger.info('Warning_ZIP3 {}'.format(file_path), 'java')
                    com_file_nu += 1
                elif type_str == 0:
                    com_file_nu += 1
                    if real_path:
                        file_path = file_path.replace(self.ep_temp_files, os.path.split(real_path)[0])
                        self.inner_path_print(file_path)

                elif type_str == "other":
                    file_path = remove_file_path_suffix(file_path)
                    other_list.append(file_path)

                elif type_str == "zip_file":
                    jar_list.append(file_path)

                elif type_str == "so_file":
                    so_list.append(file_path)

                elif type_str == "java":
                    java_list.append(file_path)

                elif type_str == "pom":
                    pom_list.append(file_path)

                elif type_str == 'incom_file':
                    if self.warning_tag:
                        if real_path:
                            file_path = file_path.replace(self.ep_temp_files, os.path.split(real_path)[0])
                        logger.info('Warning_ZIP3 {}'.format(file_path), 'java')
                        self.inner_path_print(file_path)
                    else:
                        so_list.append(file_path)
                else:
                    if real_path:
                        file_path = file_path.replace(self.ep_temp_files, os.path.split(real_path)[0])
                    self.inner_path_print(file_path)
                    com_file_nu += 1
        return jar_list, so_list, other_list, java_list, pom_list, com_file_nu, inner_file_nu

    def get_dir_files_single(self, dir_path, real_path, package_path):
        """
        Get all files in the test dir path.
        param dir_path: -> str
            The decompression directory of the zip file to be detected.
        param real_path: -> str
            The real path of the zip file to be detected.
        param package_path: -> str
            The absolute path of the zip file to be detected.
        return: -> list
            A list of all files in the test package.
        """
        so_list = []
        jar_list = []
        other_list = []
        java_list = []
        pom_list = []
        com_file_nu = 0
        inner_file_nu = 0
        for root, dirs, files in os.walk(dir_path):
            if self.class_value == 'cs':
                dirs[:] = [d for d in dirs if not self.skip_non_detection_dir(root, d, real_path)]

            for file in files:
                inner_file_nu += 1
                doc_path = os.path.join(root, file)
                type_str, file_path, file_type = self.class_file_type(doc_path)
                if package_path.endswith('.jar') and compatible_file.lower() in file_path.lower():
                    self.mf_path_dict[package_path] = file_path
                if self.warning_tag and file_type in self.skip_list:
                    if real_path:
                        file_path = file_path.replace(self.ep_temp_files, os.path.split(real_path)[0])
                    logger.info('Warning_ZIP3 {}'.format(file_path), 'java')
                    com_file_nu += 1
                elif type_str == 0:
                    com_file_nu += 1
                    if real_path:
                        file_path = file_path.replace(self.ep_temp_files, os.path.split(real_path)[0])
                        self.inner_path_print(file_path)

                elif type_str == "other":
                    file_path = remove_file_path_suffix(file_path)
                    other_list.append(file_path)

                elif type_str == "zip_file":
                    jar_list.append(file_path)

                elif type_str == "so_file":
                    so_list.append(file_path)

                elif type_str == "java":
                    java_list.append(file_path)

                elif type_str == "pom":
                    pom_list.append(file_path)

                elif type_str == 'incom_file':
                    if self.warning_tag:
                        if real_path:
                            file_path = file_path.replace(self.ep_temp_files, os.path.split(real_path)[0])
                        logger.info('Warning_ZIP3 {}'.format(file_path), 'java')
                        self.inner_path_print(file_path)
                    else:
                        so_list.append(file_path)
                else:
                    if real_path:
                        file_path = file_path.replace(self.ep_temp_files, os.path.split(real_path)[0])
                    self.inner_path_print(file_path)
                    com_file_nu += 1
        return jar_list, so_list, other_list, java_list, pom_list, com_file_nu, inner_file_nu

    def get_dir_files(self, dir_path, real_path):
        """
        Get all files in the test dir path.
        param dir_path: -> str
            The decompression directory of the zip file to be detected.
        param real_path: -> str
            The real path of the zip file to be detected.
        return: -> list
            A list of all files in the test package.
        """
        so_list = []
        jar_list = []
        other_list = []
        inner_file_nu = 0
        com_file_nu = 0
        for root, dirs, files in os.walk(dir_path):
            if self.class_value == 'cs':
                dirs[:] = [d for d in dirs if not self.skip_non_detection_dir(root, d, real_path)]

            for file in files:
                inner_file_nu += 1
                doc_path = os.path.join(root, file)
                type_str = self.check_file_suffix(doc_path, real_path)
                if type_str == 'S':
                    so_list.append(doc_path)
                elif type_str == 'Z':
                    jar_list.append(doc_path)
                elif type_str == 'C':
                    com_file_nu += 1
                else:
                    # other_list.append(doc_path)
                    com_file_nu += 1
                    logger.info('Warning_ZIP4 {}'.format(real_path), 'java')

        return jar_list, so_list, other_list, inner_file_nu, com_file_nu

    def get_all_so_file(self, package_path, number, log_type, mark,
                        quiet_mark, json_log_filename):
        """
        Get all so files in the test package.
        param package_path: -> str
            The absolute path of the packet to be detected.
        param number: -> int
            Specifies the number of threads.
        param log_type: -> str
            Specify the result record format.
        param mark: -> boolean
            Indicates whether to evaluate only.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        return: -> dictionary
            The decompressed file path of the file to be detected.
            And list of all so files. And failure identification.
        """
        all_so_list = []
        jar_list = []
        new_so_list = []
        failed_zip_list = []  # 解压失败的内部包相对路径
        zip_node_list = []  # 解压失败的内部包相对路径
        inner_file_nu = 0
        other_file_nu = 0
        com_file_nu = 0
        so_list = []
        other_list = []
        java_list = []
        pom_list = []

        so_dic = {}
        initial_filter_result = {}
        pom_java_import_match_version_res = {}

        decompress_failed_mark = False
        filter_non_text_file_result = False

        path_list_count = 1

        # 解压检测对象，收集对象包含的所有文件
        check_result = self.check_package_compatible(package_path,
                                                     number,
                                                     log_type,
                                                     mark,
                                                     quiet_mark,
                                                     json_log_filename)

        zip_path = check_result["package_path"]  # 可以直接使用package_path,不需要传入传出
        path_list = check_result["file_path_list"]  # 值为1时代表压缩包解压，列表时代表为elf或者java,class,pom文件
        if check_result.get("zip_node"):
            zip_node_list.append(check_result.get("zip_node"))  # 值为1时代表压缩包解压，列表时代表为elf或者java,class,pom文件
        # decompress_file_path 字段
        # 1 解压失败，
        # 5 解压失败，无解压命令
        # 字符串：解压成功,包自身路径, pom文件
        # 列表中是包自身路径：解压对象为 so,java,class
        # 列表中是解压后的路径：解压成功收集到内部文件
        decompress_file_path = check_result["decompress_file_path"]

        if check_result.get('decompress_failed', ''):
            decompress_failed_mark = True

        if check_result.get('miss_command'):
            filter_non_text_file_result = True
        if isinstance(decompress_file_path, list) and os.path.isdir(decompress_file_path[0]):
            # 根据解压路径，获取文件列表
            real_path = os.path.abspath(self.get_zip_path(package_path))
            if self.binary_check and self.warning_tag:
                # -b -w 只检测so与内部zip
                jar_list, so_list, other_list, inner_file_nu, com_file_nu = \
                    self.get_dir_files(decompress_file_path[0], real_path)
            else:
                if self.processes_number:
                    # 外部指定-n时，避免线程切换开销，默认使用单进程
                    try:
                        jar_list, so_list, other_list, java_list, pom_list, com_file_nu, inner_file_nu = \
                            self.get_dir_files_single(decompress_file_path[0], real_path, package_path)
                    except Exception:
                        print_exc()
                else:
                    # 外部不指定-n时，内部使用4线程进行检测，提升单包检测效率
                    jar_list, so_list, other_list, java_list, pom_list, com_file_nu, inner_file_nu = \
                        self.get_dir_files_pool(decompress_file_path[0], real_path, package_path)
            other_file_nu = len(other_list)
            if not self.quiet_mark:
                inner_dict = {
                    'project': package_path,
                    'current': com_file_nu,
                    'total': inner_file_nu
                }
                self.inner_queue.put(inner_dict)
        if not self.binary_check:
            # 首先在压缩包内过滤收集pom文件，把路径保存到列表中并解析pom文件保存结果.
            initial_filter_result = self.filter_pom_file_get_parsed_result(package_path, pom_list, java_list)
        all_import_data = []
        if not self.binary_check:
            all_import_data = get_import_data(package_path, path_list, self.processes_number)

        # 当压缩文件解压成功后
        if type(decompress_file_path) is list:
            self.zip_unzip_path[decompress_file_path[0]] = zip_path
            if not self.binary_check:
                jar_unpack_list = [i for i in jar_list if i.rstrip("/").split("/")[-1].endswith('.jar')]

                mysql = MySqlite(self.db_path)
                new_jar_unpack_list = []  # 收集import的jar包
                for item in jar_unpack_list:
                    jar_name = item.rstrip("/").split("/")[-1].replace(".jar", "")
                    for improt_data in all_import_data:
                        mapping_sql = "select jar_name from depend where import_data like ?;"
                        jar_info = mysql.search_one(mapping_sql, ("%" + improt_data + "%",))
                        if jar_info and jar_info[0] in jar_name:
                            new_jar_unpack_list.append(item)
                            break

                un_new_jar_unpack_list = list(set(new_jar_unpack_list) ^ set(jar_unpack_list))
                for un_jar in un_new_jar_unpack_list:
                    logger.warning("Skipped {}".format(un_jar), 'java')
                jar_list = list(set(un_new_jar_unpack_list) ^ set(jar_list))
            # 根据收集的子压缩包，多线程执行解压并获取子压缩包中的pom文件，解析pom文件，结果进行报错。
            if jar_list:
                if not self.binary_check:
                    jar_package_filter_result = self.jar_package_filter_matching(initial_filter_result,
                                                                                 jar_list,
                                                                                 number, log_type,
                                                                                 mark,
                                                                                 quiet_mark,
                                                                                 json_log_filename,
                                                                                 parent_path=package_path)
                    pom_java_import_match_version_res = jar_package_filter_result['pom_java_import_match_version_res']
                    all_so_list = jar_package_filter_result['all_so_list']
                    other_list.extend(jar_package_filter_result.get("other_list", []))

                else:
                    try:
                        with ThreadPoolExecutor(2) as thread_pool:
                            tasks = []
                            for jar_path in jar_list:
                                tasks.append(thread_pool.submit(self.get_jar_so_files, jar_path, number, log_type, mark,
                                                                quiet_mark, json_log_filename, parent_path=package_path))
                            all_so_list = []
                            for task in as_completed(tasks):
                                jar_so_files, other_list_inner = task.result()
                                failed_zip_list += jar_so_files.get('failed_zip_list', [])
                                zip_node_list += jar_so_files.get('zip_node_list', [])
                                del jar_so_files['failed_zip_list']
                                del jar_so_files['zip_node_list']
                                all_so_list.append(jar_so_files)
                                other_list += other_list_inner
                    except Exception:
                        print_exc()
                if not self.quiet_mark:
                    inner_dict = {
                        'project': package_path,
                        'current': com_file_nu + len(jar_list),
                        'total': inner_file_nu
                    }
                    self.inner_queue.put(inner_dict)
            # 如果检测对象不包含子压缩包，但包含pom文件。
            elif initial_filter_result:
                filter_jar_using_pom_file_result, pom_java_import_match_version_res \
                    = self.initial_filter_result_processing(initial_filter_result, jar_list, number,
                                                            log_type, mark, quiet_mark, json_log_filename)

                if filter_jar_using_pom_file_result:
                    unique_jars = filter_jar_using_pom_file_result["unique_jar"]

                    if unique_jars:
                        # 对压缩包进行解压并评估推荐。
                        get_file = self.threading_executes(self.get_jar_so_files,
                                                           file_list=unique_jars,
                                                           number=number,
                                                           log_type=log_type,
                                                           mark=mark,
                                                           quiet_mark=quiet_mark,
                                                           json_log_filename=json_log_filename,
                                                           parent_path=package_path)
                        all_so_list = []
                        other_list_jar = []
                        for item in get_file:
                            jar_so_files, other_list_inner = item
                            del jar_so_files['failed_zip_list']
                            del jar_so_files['zip_node_list']
                            all_so_list.append(jar_so_files)
                            other_list_jar.extend(other_list_inner)
                        other_list.extend(other_list_jar)

            # 检查子压缩包中是否存在解压失败，如果存在，则设置失败标志为True。
            if all_so_list:
                copy_all_so_list = copy.copy(all_so_list)
                for index in range(len(copy_all_so_list)):
                    decompress_failed = copy_all_so_list[index].get('decompress_failed_mark', '')
                    if decompress_failed:
                        decompress_failed_mark = True
                        del all_so_list[index]['decompress_failed_mark']

            if so_list:
                so_dic[package_path] = so_list
                all_so_list.append(so_dic)

            if all_so_list:

                for so_dic in all_so_list:

                    if type(so_dic) is dict and so_dic:
                        # 对子压缩包是否含有to be verified标识做出整体判断
                        if not filter_non_text_file_result and True in list(so_dic.values()):
                            filter_non_text_file_result = True
                        new_so_list.append(so_dic)
                    elif type(so_dic) is bool and so_dic:
                        # 对子压缩包是否含有to be verified标识做出整体判断
                        if not filter_non_text_file_result:
                            filter_non_text_file_result = True

                get_all_so_result = {
                    "decompress_file_path": decompress_file_path,
                    "so_list": new_so_list,
                    "jar_list": jar_list,
                    "sub_file_count": path_list_count,
                    "pom_import_match_version_res": pom_java_import_match_version_res,
                    "filter_non_text_file_result": filter_non_text_file_result,
                    "decompress_failed_mark": decompress_failed_mark,
                    'failed_zip_list': failed_zip_list,
                    'zip_node_list': zip_node_list,
                    'inner_file_nu': inner_file_nu
                }
            else:
                get_all_so_result = {
                    "decompress_file_path": decompress_file_path,
                    "so_list": all_so_list,
                    "jar_list": jar_list,
                    "sub_file_count": path_list_count,
                    "pom_import_match_version_res": pom_java_import_match_version_res,
                    "filter_non_text_file_result": filter_non_text_file_result,
                    "decompress_failed_mark": decompress_failed_mark,
                    'failed_zip_list': failed_zip_list,
                    'zip_node_list': zip_node_list,
                    'inner_file_nu': inner_file_nu,
                    'other_file_nu': other_file_nu
                }
            if other_list:
                get_all_so_result["other_list"] = other_list
                for other_file in other_list:
                    self.inner_path_print(self.get_zip_path(other_file))

        # 当检测对象为pom或者java文件时，且没有指定-b
        elif initial_filter_result:
            filter_jar_using_pom_file_result, pom_java_import_match_version_res \
                = self.initial_filter_result_processing(initial_filter_result, jar_list, number,
                                                        log_type, mark, quiet_mark, json_log_filename)

            get_all_so_result = {
                "decompress_file_path": [package_path],
                "so_list": all_so_list,
                "jar_list": jar_list,
                "sub_file_count": path_list_count,
                "pom_import_match_version_res": pom_java_import_match_version_res,
                "filter_non_text_file_result": filter_non_text_file_result,
                "decompress_failed_mark": decompress_failed_mark,
                'zip_node_list': zip_node_list,
                'inner_file_nu': inner_file_nu,
                'other_file_nu': other_file_nu
            }
        # 文件包含解压失败
        elif type(decompress_file_path) is int:
            get_all_so_result = {
                "decompress_file_path": decompress_file_path,
                "so_list": 1,
                "jar_list": jar_list,
                "sub_file_count": path_list_count,
                "pom_import_match_version_res": pom_java_import_match_version_res,
                "filter_non_text_file_result": filter_non_text_file_result,
                "decompress_failed_mark": decompress_failed_mark,
                'failed_zip_list': failed_zip_list,
                'zip_node_list': zip_node_list,
                'inner_file_nu': inner_file_nu,
                'other_file_nu': other_file_nu
            }
        # 其他情况
        else:
            get_all_so_result = {
                "decompress_file_path": decompress_file_path,
                "so_list": 1,
                "jar_list": jar_list,
                "sub_file_count": path_list_count,
                "pom_import_match_version_res": pom_java_import_match_version_res,
                "filter_non_text_file_result": filter_non_text_file_result,
                "decompress_failed_mark": decompress_failed_mark,
                'failed_zip_list': [get_file_name(package_path)],
                'zip_node_list': zip_node_list,
                'inner_file_nu': inner_file_nu,
                'other_file_nu': other_file_nu
            }
        if not self.binary_check:
            pom_import_match_version_res = get_all_so_result.get('pom_import_match_version_res', {})
            if pom_import_match_version_res:
                pom_import = {x.replace("/", '.'): y for x, y in pom_import_match_version_res.items()}
                java_import_list = pom_import.keys()
                # 对于没有引用的依赖筛选出不兼容的
                use_java_import = list(set([n for i in all_import_data for n in java_import_list if n in i]))
                new_pom_import = {}
                for item in use_java_import:
                    new_pom_import[item] = pom_import.get(item)
                get_all_so_result['pom_import_match_version_res'] = new_pom_import

                useless_java_import = {key: pom_import_match_version_res[key] for key in
                                       pom_import_match_version_res.keys() - new_pom_import.keys()}
                self.get_category({package_path: useless_java_import})
            get_all_so_result['import'] = all_import_data

        self.inner_path_print(self.get_zip_path(package_path))
        return get_all_so_result

    def get_zip_path(self, temporary_path):
        """
        When the compressed package path is in the temporary directory,
        replace it with the real path.
        param temporary_path: -> string
            The absolute path of the compressed package in the temporary directory.
        return: -> string
            The actual path of the compressed package.
        """
        compliant_data_list = []
        if self.zip_unzip_path:
            for key, value in self.zip_unzip_path.copy().items():
                if "{}/".format(key) in temporary_path:
                    compliant_data_list.append(key)

            if compliant_data_list:
                if len(compliant_data_list) > 1:
                    max_len_data = max(compliant_data_list, key=len)
                else:
                    max_len_data = compliant_data_list[0]

                if max_len_data == self.zip_unzip_path[max_len_data]:
                    temporary_path = max_len_data
                else:
                    temporary_path = temporary_path.replace(max_len_data, self.zip_unzip_path[max_len_data])
        temporary_path = remove_file_path_suffix(temporary_path)
        return temporary_path

    def check_all_so_file(self, package_path, number, log_type, mark,
                          quiet_mark, json_log_filename):
        """
        All so files in the acquired package to be tested shall be checked by category.
        param package_path: -> str
            The absolute path of the packet to be detected.
        param number: -> int
            Specifies the number of threads.
        param log_type: -> str
            Specify the result record format.
        param mark: -> boolean
            Indicates whether to evaluate only.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        return:
            check_all_so_result: -> dictionary
                The decompressed file path of the file to be detected.
                And so file classification test results.
                And failure identification.
        """
        so_count = 0
        pom_java_version_count = 0
        staticdata = [0, 0, 0, 0, 0]

        check_so_result = {}
        check_all_so_result = {}

        continue_list = ['filter_non_text_file_result', 'decompress_failed_mark']
        get_all_so_file_result = self.get_all_so_file(package_path, number,
                                                      log_type, mark, quiet_mark,
                                                      json_log_filename)
        so_list = get_all_so_file_result["so_list"]
        jar_list = get_all_so_file_result["jar_list"]
        sub_file_count = get_all_so_file_result["sub_file_count"]
        decompress_file_path = get_all_so_file_result["decompress_file_path"]
        pom_import_match_version_res = get_all_so_file_result["pom_import_match_version_res"]
        filter_non_text_file_result = get_all_so_file_result["filter_non_text_file_result"]
        decompress_failed_mark = get_all_so_file_result["decompress_failed_mark"]
        other_list = get_all_so_file_result.get("other_list")
        failed_zip_list = get_all_so_file_result.get("failed_zip_list")
        zip_node_list = get_all_so_file_result.get("zip_node_list", [])
        inner_file_nu = get_all_so_file_result.get("inner_file_nu", 0)
        other_file_nu = get_all_so_file_result.get("other_file_nu", 0)
        import_datas = []
        if not self.binary_check:
            import_datas = get_all_so_file_result.get("import")

        if pom_import_match_version_res:
            pom_java_version_count = len(list(pom_import_match_version_res.keys()))

        jar_count = len(jar_list)

        if not isinstance(so_list, int):
            for so_dic in so_list:
                for key, so_document_file in so_dic.items():
                    if key in continue_list:
                        continue
                    so_count += len(so_document_file)
                    # 压缩包中包含的所有so，包含子压缩中的so
                    if so_document_file:
                        # 对so按照project和so_name进行分组
                        so_dictionary = sp().so_document_classification(so_document_file)
                        if self.warning_tag:
                            so_dictionary = self.architecture_screen(so_dictionary, package_path, False)
                            so_dictionary, so_file_list = self.skip_warning3_so(so_dictionary, package_path)
                        if self.class_value != 'xarch':
                            so_parse_res = self.parse_so_document(so_dictionary, False)
                            # 根据分组检测结果，判断出分组整体是否兼容
                            so_final_res = self.final_recommendation_result(so_parse_res, so_dictionary)
                        else:
                            so_category_dict = so_document_classification(so_dictionary)
                            # 对分组后的so进行检测，是否是aarch64类型
                            so_final_res, staticdata = self.final_recommendation_result_xarch(so_dictionary,
                                                                                              so_category_dict,
                                                                                              False)
                        check_so_result[key] = so_final_res

            jar_so_otherfile_count = {
                "jar": jar_count,
                "so": so_count,
                "other": sub_file_count + pom_java_version_count
            }

            if not self.binary_check:
                mysql = MySqlite(self.db_path)

                if pom_import_match_version_res or import_datas:  # 如果没有指定-b，把解析完成的pom和java依赖和包中的so结果进行合并
                    if check_so_result:
                        check_so_result_keys = list(check_so_result.keys())
                        if package_path in check_so_result_keys:
                            new_so_list = []
                            import_no_so = []
                            import_no_jar = []
                            record = 0
                            for item in import_datas:
                                mapping_sql = "select import_data, jar_name, so_name from depend where import_data like ?;"
                                jar_info = mysql.search_one(mapping_sql, ("%" + item + "%",))
                                if jar_info:
                                    if jar_info[2]:
                                        new_so_list.append(jar_info[2])
                                        import_no_so.append(jar_info[1])
                                    record += 1
                                else:
                                    import_no_jar.append(item)
                            new_jar_unpack_list = []
                            for item in jar_list:
                                jar_name = item.rstrip("/").split("/")[-1].replace(".jar", "")
                                for import_jar in import_no_so:
                                    if import_jar in jar_name:
                                        new_jar_unpack_list.append(item)
                                        break
                            un_new_jar_unpack_list = list(set(new_jar_unpack_list) ^ set(jar_list))
                            for un_jar in un_new_jar_unpack_list:
                                logger.warning("Skipped {}".format(un_jar), 'java')
                            # 对不兼容的so只保留被引用jar所依赖的so
                            package_path_value = check_so_result[package_path]
                            lib_names = {}
                            for i in package_path_value.keys():
                                so_name = i.rstrip("/").split("/")[-1]
                                for so in new_so_list:
                                    if so in so_name:
                                        lib_names[i] = package_path_value.get(i)
                                        break
                                jar_name = package_path.rstrip("/").split("/")[-1].replace(".jar", "")
                                so_name = so_name_to_search(so_name)
                                sql_so = "SELECT lib FROM so_el8 WHERE name like ?;"
                                so_info = mysql.search_one(sql_so, (so_name + "%",))
                                if so_info:
                                    file_name = so_info[0]
                                    if file_name in jar_name:
                                        lib_names[i] = package_path_value.get(i)

                            diff = {key: package_path_value[key] for key in
                                    package_path_value.keys() - lib_names.keys()}

                            # 剔除兼容的so文件
                            so_no_depend_file = {}
                            for key, value in diff.items():
                                if isinstance(value, dict):
                                    so_no_depend_file[key] = value
                            self.get_category({package_path: so_no_depend_file})
                            if len(import_datas) == record:
                                package_path_value = lib_names
                            package_path_value.update(pom_import_match_version_res)
                            check_so_result[package_path] = package_path_value
                        else:
                            check_so_result[package_path] = pom_import_match_version_res
                    else:
                        check_so_result[package_path] = pom_import_match_version_res
                else:  # 如果没有引用三方jar，需要判断当前jar包中是否包含so文件，对于不依赖的文件进行筛选
                    so_file = check_so_result.get(package_path)
                    if so_file and isinstance(so_file, dict):
                        jar_name = package_path.rstrip("/").split("/")[-1].replace(".jar", "")
                        so_file_dict = {}
                        for key, value in so_file.items():
                            so_file_name = key.rstrip("/").split("/")[-1]
                            so_name = so_name_to_search(so_file_name)
                            sql_so = "SELECT lib FROM so_el8 WHERE name like ?;"
                            so_info = mysql.search_one(sql_so, (so_name + "%",))
                            if so_info:
                                file_name = so_info[0]
                                if file_name in jar_name:
                                    so_file_dict[key] = value
                        check_so_result[package_path] = so_file_dict
                        no_depend_so = {key: so_file[key] for key in so_file.keys() - so_file_dict.keys()}
                        so_no_depend_file = {}
                        for key, value in no_depend_so.items():
                            if isinstance(value, dict):
                                so_no_depend_file[key] = value
                        # 剔除兼容的so文件
                        self.get_category({package_path: so_no_depend_file})

            check_all_so_result["decompress_file_path"] = decompress_file_path
            check_all_so_result["so_result"] = check_so_result
            if self.class_value == 'xarch':
                x86_64_count = staticdata[0]
                aarch64_count = staticdata[1]
                noarch_count = staticdata[2]
                uncertain_count = staticdata[3]
                fail = staticdata[4]
                if fail:
                    check_all_so_result['category'] = 'failed'
                elif uncertain_count:
                    check_all_so_result['category'] = 'uncertain'
                elif x86_64_count:
                    check_all_so_result['category'] = 'x86_64'
                elif aarch64_count:
                    check_all_so_result['category'] = 'aarch64'
                elif noarch_count:
                    check_all_so_result['category'] = 'noarch'
                else:
                    check_all_so_result['category'] = 'noarch'
                if pom_import_match_version_res:
                    check_all_so_result["category"] = 'uncertain'

        # 解压失败
        elif type(so_list) is int and type(decompress_file_path) is int:
            jar_so_otherfile_count = {
                "jar": jar_count,
                "so": so_count,
                "other": sub_file_count + pom_java_version_count
            }
            check_all_so_result["so_result"] = 1

            # 解压失败
            if decompress_file_path == 5:
                check_all_so_result["category"] = 'failed'
                check_all_so_result["decompress_file_path"] = 5
            else:
                check_all_so_result["category"] = 'failed'  # failed
                check_all_so_result["decompress_file_path"] = 1

        else:  # 兼容的文件
            jar_so_otherfile_count = {
                "jar": jar_count,
                "so": so_count,
                "other": sub_file_count + pom_java_version_count
            }
            check_all_so_result["decompress_file_path"] = decompress_file_path
            check_all_so_result["so_result"] = 1
            check_all_so_result['category'] = 'noarch'  # 兼容

        check_all_so_result["sub_file_count"] = jar_so_otherfile_count
        check_all_so_result["is_to_be_verified"] = filter_non_text_file_result
        check_all_so_result["decompress_failed_mark"] = decompress_failed_mark
        check_all_so_result["failed_zip_list"] = failed_zip_list
        check_all_so_result["zip_node_list"] = zip_node_list
        if other_list:
            check_all_so_result["other_list"] = other_list
        return check_all_so_result

    def get_category(self, so_dict):
        no_depend_so_dict = self.recommend_by_jar(so_dict)
        for file, so_dict in no_depend_so_dict.items():
            result_dict = self.class_value_output({file: so_dict}, file)
            for key, value in result_dict.items():
                if value.isdigit():
                    category = "UJ" + str(value)
                else:
                    category = value.replace("J", "UJ")
                no_depend = no_depend_so_dict.get(key, {})
                for sub_key in no_depend:
                    if "jar_recomand_data" == sub_key:
                        continue
                    if self.warning_check:
                        self.warning_info_output(sub_key, category)
                    content = "Skipped {}".format(sub_key)
                    logger.warning(content, 'java')

    def whether_test_result_is_no_compatible(self, package_path, so_result,
                                             json_log_filename, is_to_be_verified):
        """
        According to the detection result, it is judged whether the detection object is compatible.
        param package_path: -> string
            The absolute path of the detection object.
        param so_result: -> dictionary
            The detection result of the detection object.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        param is_to_be_verified: -> list
            File summary result details.
        return compatible_mark: -> boolean
            Check if an object is compatible.
        """
        incompatible_dict = {}
        compatible_mark = True
        new_so_result = copy.deepcopy(so_result)
        for keys, values in so_result.items():
            file_names = keys.split("/")
            if file_names:
                compatible_so_file = []
                incompatible_so_file = []
                for sub_key, sub_value in values.items():
                    if type(sub_value) is int:
                        compatible_so_file.append(sub_key)
                    else:
                        incompatible_so_file.append(sub_key)
                if compatible_so_file and incompatible_so_file:
                    incompatible_so_name = [re.split(r"\d{1}", os.path.split(i)[-1])[0] for i in incompatible_so_file if
                                            os.path.split(i)]
                    compatible_so_name = [re.split(r"\d{1}", os.path.split(i)[-1])[0] for i in compatible_so_file if
                                          os.path.split(i)]
                    if sorted(list(set(incompatible_so_name) & set(compatible_so_name))) != sorted(
                            list(set(incompatible_so_name))):
                        compatible_mark = False
                        for sub_key, sub_value in values.items():
                            if type(sub_value) is not int:
                                for item in list(set(incompatible_so_name) & set(compatible_so_name)):
                                    if item in sub_key:
                                        if incompatible_dict.get(keys):
                                            incompatible_dict[keys].update({sub_key: sub_value})
                                        else:
                                            incompatible_dict[keys] = {sub_key: sub_value}
                                        del new_so_result.get(keys)[sub_key]
                    else:
                        for sub_key, sub_value in values.items():
                            if type(sub_value) is not int:
                                if incompatible_dict.get(keys):
                                    incompatible_dict[keys].update({sub_key: sub_value})
                                else:
                                    incompatible_dict[keys] = {sub_key: sub_value}
                                del new_so_result.get(keys)[sub_key]
                elif (compatible_so_file and not incompatible_so_file) or \
                        (not compatible_so_file and not incompatible_so_file):
                    pass
                else:
                    compatible_mark = False

        if incompatible_dict:
            incompatible_dict = self.recommend_by_jar(incompatible_dict)
            for file, so_dict in incompatible_dict.items():
                result_dict = self.class_value_output({file: so_dict}, file)
                for key, value in result_dict.items():
                    if value.isdigit():
                        category = "WJ" + str(value)
                    else:
                        category = value.replace("J", "WJ")
                    incompatible = incompatible_dict.get(key, {})
                    for warning_path in incompatible:
                        if "jar_recomand_data" == warning_path:
                            continue
                        if self.warning_check:
                            self.warning_info_output(warning_path, category)
                        content = "Warning_ZIP1 {}".format(os.path.abspath(self.get_zip_path(warning_path)))
                        logger.warning(content, 'java')

        so_result_key = list(new_so_result.keys())
        if so_result_key:
            self.package_compatible_jar_record_log(package_path, new_so_result, so_result_key,
                                                   self.log_type, json_log_filename, is_to_be_verified)

        return compatible_mark, new_so_result

    def verified_file_log_result_data_processing(self, file_path):
        """
        To be verified file detection results collection.
        param file_path: -> string
            The absolute path to the file.
        return: -> None
        """
        non_test_file_results = []
        file_path_slice_result = file_path.rstrip('/').split('/')
        project = file_path_slice_result[-2]
        md5_result = dp().package_name_processing(file_path)
        name = md5_result["name"]
        hash_value = md5_result["hash"]
        location = file_path.split("/{}".format(name))[0]
        file_type = get_file_type_by_suffix(file_path)
        if not file_type or (file_type in compatible_default_list):
            file_type = get_file_real_type(file_path)
        if not self.class_value:
            csv_data = [project, location, name, hash_value, 'J0', file_type, '', '', '', '', '', '', '', '']
        else:
            csv_data = [project, name, '0', file_type,
                        'NULL', 'NULL', 'NULL', 'NULL', 'NULL', 'NULL', '1']
        non_test_file_results.append(csv_data)
        return non_test_file_results

    def warning_info_output(self, file_path, category):
        """
        The result of warning is output and displayed.
        param file_path: -> string
            The absolute path to the file.
        return: -> None
        """
        output_terms = ["NAME", "MD5", "COMPATIBLE", "TYPE"]
        md5_result = dp().package_name_processing(file_path)
        name = md5_result["name"]
        hash_value = md5_result["hash"]
        file_type = df().get_file_precise_type(file_path)
        print(self.isolation)

        if self.class_value:
            print("{0:<15}: {1:<20} \n"
                  "{2:<15}: {3:<20} \n"
                  "{4:<15}: {5:<20} \n"
                  "{8:<15}: {9:<20} \n"
                  "{6:<15}: {7:<20} ".format(output_terms[0], name,
                                             output_terms[1], hash_value,
                                             output_terms[2], category,
                                             output_terms[3], file_type,
                                             'CLASS', '0'))
        else:
            print("{0:<15}: {1:<20} \n"
                  "{2:<15}: {3:<20} \n"
                  "{4:<15}: {5:<20} \n"
                  "{6:<15}: {7:<20} ".format(output_terms[0], name,
                                             output_terms[1], hash_value,
                                             output_terms[2], category,
                                             output_terms[3], file_type))
        return

    def to_be_verified_info_output(self, file_path):
        """
        The result of to be verified is output and displayed.
        param file_path: -> string
            The absolute path to the file.
        return: -> None
        """
        output_terms = ["NAME", "MD5", "COMPATIBLE", "TYPE"]
        md5_result = dp().package_name_processing(file_path)
        name = md5_result["name"]
        hash_value = md5_result["hash"]
        file_type = df().get_file_precise_type(file_path)
        print(self.isolation)

        if self.class_value:
            print("{0:<15}: {1:<20} \n"
                  "{2:<15}: {3:<20} \n"
                  "{4:<15}: {5:<20} \n"
                  "{8:<15}: {9:<20} \n"
                  "{6:<15}: {7:<20} ".format(output_terms[0], name,
                                             output_terms[1], hash_value,
                                             output_terms[2], 'WJ0',
                                             output_terms[3], file_type,
                                             'CLASS', '0'))
        else:
            print("{0:<15}: {1:<20} \n"
                  "{2:<15}: {3:<20} \n"
                  "{4:<15}: {5:<20} \n"
                  "{6:<15}: {7:<20} ".format(output_terms[0], name,
                                             output_terms[1], hash_value,
                                             output_terms[2], 'WJ0',
                                             output_terms[3], file_type))
        return

    def all_so_result_process(self, package_path, number, log_type, mark,
                              quiet_mark, json_log_filename, parent_path=None):
        """
        All so inspection results shall be processed.
        param package_path: -> str
            The absolute path of the packet to be detected.
        param number: -> int
            Specifies the number of threads.
        param log_type: -> str
            Specify the result record format.
        param mark: -> boolean
            Indicates whether to evaluate only.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        return:
            function:
                Save the test results.
            0:
                Indicates that when the detection object is decompressed successfully
                and there is no so file.
            2:
                It indicates that all scenarios except the above two are failures.
        """
        elf_values = 0
        not_arm_count = 0
        result_dic = {}

        if not os.path.isabs(package_path):  # 对检测对象为相对路径的进行处理，变成绝对路径
            package_path = os.path.abspath(package_path)
        package_path = package_path.rstrip('/')
        logger.info('Began collecting all files to be scanned.', 'java')
        if not os.path.isdir(package_path):
            self.file_type = 'file'
            zip_so_files = [package_path]
            self.check_file_type(package_path)
        else:
            # 当检测对象为目录时，收集目录下所有的文件放到list中
            zip_so_files = self.collect_compressed_so_file(package_path)
        if self.class_value == 'cs' and self.tree_output:
            self.root_node = tree_dir_files(package_path, initial=True)
        logger.info('Ended collecting all files to be scanned.', 'java')
        so_test_result = {
            "so_file_list": [],
            "so_final_res": [],
            "staticdata": [0, 0, 0, 0, 0]
        }

        so_list, so_file_list, so_final_res, so_file_list_new = [], [], [], []
        so_final_res_new, so_file_list_new = {}, []
        # 检测其他文件前，先对so文件做处理, udf 格式下so文件以及other文件由python引擎进行检测
        if self.class_value != 'udf':
            so_test_result = self.directory_so_file_processing(zip_so_files, self.total_queue,
                                                               self.quiet_mark, package_path, self.warning_tag)
            so_list = so_test_result.get("so_list", [])
            so_final_res = so_test_result.get("so_final_res", [])
            so_file_list = so_test_result.get("so_file_list", [])
            so_file_list_temp = copy.deepcopy(so_file_list)
            so_final_res_new, so_file_list_new = self.determine_all_compatibility(so_final_res, so_file_list_temp)
            zip_so_files = [so_file for so_file in zip_so_files if so_file not in set(so_list)]

        # 对收集到的文件进行全量检测
        if self.class_value == 'xarch':
            summary_data = [0, 0, 0, 0, 0]  # [x86_64, aarch64, noarch, uncertain, fail]
            staticdata = so_test_result['staticdata']
            summary_data[0] += staticdata[0]
            summary_data[1] += staticdata[1]
            summary_data[2] += staticdata[2]
            summary_data[3] += staticdata[3]
            summary_data[4] += staticdata[4]
            summary_data = self.check_jar_so_files_xarch(zip_so_files, mark, so_list, so_final_res,
                                                         so_file_list_new, summary_data)
            return summary_data
        else:
            check_jar_so_result = self.check_jar_so_files(zip_so_files, mark, so_test_result, so_final_res_new)
            so_result = check_jar_so_result["so_result"]
            sub_file_count = check_jar_so_result["sub_file_count"]
            decompress_file_path = check_jar_so_result["decompress_file_path"]
            is_to_be_verified = check_jar_so_result["is_to_be_verified"]
            all_child_file = check_jar_so_result["all_child_file"]
            # 挂载目录树
            if self.class_value == 'cs' and self.tree_output:
                for zip_tree_node in self.zip_node_list:
                    if zip_tree_node:
                        # 挂载至树上
                        self.mount_zip_dir_tree(zip_tree_node, package_path)

            if so_result != 1 and decompress_file_path != 1:

                if self.file_type == 'file':
                    # 构造结果数据，与检测dir的so检测结果数据结构一致
                    result_dic[package_path] = {}
                    for key in so_result:
                        for key1 in so_result[key]:
                            result_dic[package_path][key1] = so_result[key][key1]
                    so_result = result_dic
                # 根据检测对象中so的检测结果，判断整个检测对象是否兼容
                compatible_mark, so_result = self.whether_test_result_is_no_compatible(package_path, so_result,
                                                                                       json_log_filename,
                                                                                       is_to_be_verified)

                if (compatible_mark and
                        is_to_be_verified[2] != sum(is_to_be_verified) and
                        is_to_be_verified[3] != sum(is_to_be_verified)):
                    # 整体兼容，但是文件数不等于总数，文件数>1或者不全是TBV和failed
                    if self.class_value == "cs":
                        self.inspection_result_output(package_path, elf_values, not_arm_count,
                                                      log_type, quiet_mark, json_log_filename,
                                                      sub_file_count=sub_file_count, cs=True)
                    else:
                        self.inspection_result_output(package_path, elf_values, not_arm_count,
                                                      log_type, quiet_mark, json_log_filename,
                                                      sub_file_count=sub_file_count)
                elif self.class_value == 'cs' and compatible_mark:
                    if is_to_be_verified[2] + is_to_be_verified[3] == sum(is_to_be_verified):
                        if self.zip_package_pom_path_results:  # 如果有pom文件的解析结果，则去pom文件中匹配依赖的行号
                            so_result = self.match_pom_files_dependent_line_numbers(so_result)

                        so_result = self.recommend_by_jar(so_result)  # 对不兼容的so进行推荐version
                        failed_file_list = list(self.failed_files.keys())
                        failed_list = self.package_failed_file_organization(decompress_file_path,
                                                                            failed_file_list)
                        if not failed_list:
                            failed_list = failed_file_list

                        total_failed = len(failed_list)
                        self.inspection_result_output_cs(package_path, elf_values, not_arm_count,
                                                         log_type, quiet_mark, json_log_filename,
                                                         so_final_result=so_result,
                                                         failed_list=failed_list, total_failed=total_failed,
                                                         sub_file_count=sub_file_count, incompatible_flag=True)

                elif not compatible_mark:
                    if self.zip_package_pom_path_results:  # 如果有pom文件的解析结果，则去pom文件中匹配依赖的行号
                        so_result = self.match_pom_files_dependent_line_numbers(so_result)

                    so_result = self.recommend_by_jar(so_result)  # 对不兼容的so进行推荐version

                    failed_file_list = list(self.failed_files.keys())
                    # 根据检测对象从全局变量中收集解压失败的文件
                    failed_list = self.package_failed_file_organization(decompress_file_path,
                                                                        failed_file_list)
                    if not failed_list:
                        failed_list = failed_file_list

                    total_failed = len(failed_list)

                    self.incompatible_package_handling(package_path, total_failed,
                                                       failed_list, so_result, log_type, mark, quiet_mark,
                                                       json_log_filename, sub_file_count=sub_file_count,
                                                       all_child_file=all_child_file)
            elif so_result == 1 and decompress_file_path != 1:
                if not self.class_value and is_to_be_verified:
                    if self.quiet_mark and self.warning_check:
                        self.to_be_verified_info_output(package_path)
                    logger.warning("Skipped {}".format(package_path), 'java')
                    self.non_test_file.append(package_path)
                    non_test_file_results = self.verified_file_log_result_data_processing(package_path)
                    self.non_test_file_results += non_test_file_results
                    sl().execute_log_records(self.log_file, package_path)
                    is_to_be_verified = [0, 0, 1, 0]
                else:
                    is_to_be_verified = [1, 0, 0, 0]
                    self.inspection_result_output(package_path, 0, 0, log_type,
                                                  quiet_mark, json_log_filename)
            elif so_result == 1 and decompress_file_path == 1:
                sub_file_count = {'jar': 0, 'so': 0, 'other': 1}
                is_to_be_verified = [0, 0, 0, 1]
                self.incompatible_package_handling(package_path, 1, [package_path],
                                                   False, log_type, mark, False, json_log_filename,
                                                   sub_file_count=sub_file_count)
            elif so_result != 1 and decompress_file_path == 1:
                if self.class_value == "cs" and so_result == {}:
                    if self.zip_package_pom_path_results:  # 如果有pom文件的解析结果，则去pom文件中匹配依赖的行号
                        so_result = self.match_pom_files_dependent_line_numbers(so_result)

                    so_result = self.recommend_by_jar(so_result)  # 对不兼容的so进行推荐version

                    self.inspection_result_output_cs(package_path, elf_values, not_arm_count,
                                                     log_type, quiet_mark, json_log_filename, so_final_result=so_result,
                                                     failed_list=[], total_failed=0,
                                                     sub_file_count=sub_file_count, incompatible_flag=True)

            else:
                if not self.class_value:
                    if self.quiet_mark and self.warning_check:
                        self.to_be_verified_info_output(package_path)
                    logger.warning("Skipped {}".format(package_path), 'java')
                    self.non_test_file.append(package_path)
                    non_test_file_results = self.verified_file_log_result_data_processing(package_path)
                    self.non_test_file_results += non_test_file_results
                    is_to_be_verified = [0, 0, 1, 0]
                if self.class_value == 'cs' or self.class_value == 'udf':
                    if self.quiet_mark and self.warning_check:
                        self.to_be_verified_info_output(package_path)
                    logger.warning("Skipped {}".format(package_path), 'java')
                    self.non_test_file.append(package_path)
                    non_test_file_results = self.verified_file_log_result_data_processing(package_path)
                    self.non_test_file_results += non_test_file_results

            return is_to_be_verified

    def recommend_by_jar(self, so_result_dict):
        """
        Recommend the corresponding version through jar.
        param so_result_dict: -> string
            The dict of jar which contains so.
        return: -> dictionary
            The dict of jar which contains so.
        """
        if not so_result_dict:
            return {}
        # 判断是否可以接入内网
        if self.connect_taobao is None:
            self.connect_taobao = ping_website('http://rpm.corp.taobao.com')
        mysql = MySqlite(self.db_path)
        for jar_path in so_result_dict:
            if so_result_dict[jar_path] == 0:
                continue
            if jar_path.endswith('.jar'):
                jar_name = os.path.split(jar_path)[-1]
                jar_name = sp().get_jar_name(jar_name)  # 处理jarname
                jar_name_sql = so_name_to_search(jar_name)
                if self.connect_taobao:  # 可以链接内网
                    sql_ali = "SELECT name, version, repo_url, minversion FROM alibaba WHERE name like ?;"
                    rpm_info = mysql.search_one(sql_ali, (jar_name_sql + "%",))
                    if rpm_info:
                        version = rpm_info[1]
                        repo_url = rpm_info[2]
                        minversion = rpm_info[3]
                        so_result_dict[jar_path]['jar_recomand_data'] = {'mark': 3,
                                                                         'version': version,
                                                                         'repo_url': repo_url,
                                                                         'minversion': minversion}
                        continue
                # 1.根据jar名在数据库进行搜索
                sql_select = "SELECT name, version, repo_url, minversion FROM jar WHERE name like ?;"
                jar_info = mysql.search_one(sql_select, (jar_name_sql + "%",))
                if jar_info:
                    version = jar_info[1]
                    repo_url = jar_info[2]
                    minversion = jar_info[3]
                    so_result_dict[jar_path]['jar_recomand_data'] = {'mark': 0,
                                                                     'version': version,
                                                                     'repo_url': repo_url,
                                                                     'minversion': minversion}
                else:
                    for file_path_in_jar in so_result_dict[jar_path]:
                        if so_result_dict[jar_path][file_path_in_jar] == 0:
                            continue
                        if os.path.isfile(file_path_in_jar):  # 处理so，其他不是文件的属于class，pom
                            so_name = os.path.split(file_path_in_jar)[-1]
                            so_name_sql = so_name_to_search(so_name)
                            if not self.class_value:
                                sql_so = "SELECT name, version, repo_url, snippet, minversion FROM so_el8 WHERE name like ?;"
                                so_info = mysql.search_one(sql_so, (so_name_sql + "%",))
                                if so_info:
                                    version = so_info[1] if so_info[1] else so_info[2]
                                    repo_url = so_info[2]
                                    version_source = int(so_info[3]) if so_info[3] is not None else -1
                                    minversion = so_info[4]
                                    so_result_dict[jar_path][file_path_in_jar] = {'mark': version_source,
                                                                                  'version': version,
                                                                                  'repo_url': repo_url,
                                                                                  'minversion': minversion}
                                    continue

                            else:
                                sql_so = "SELECT name, version, repo_url, snippet, minversion FROM so_el7 WHERE name like ?;"
                                so_info = mysql.search_one(sql_so, (so_name_sql + "%",))
                                if so_info:
                                    version = so_info[1] if so_info[1] else so_info[2]
                                    repo_url = so_info[2]
                                    version_source = int(so_info[3]) if so_info[3] is not None else -1
                                    minversion = so_info[4]
                                    so_result_dict[jar_path][file_path_in_jar] = {'mark': version_source,
                                                                                  'version': version,
                                                                                  'repo_url': repo_url,
                                                                                  'minversion': minversion}
                                    continue

                            if self.recommend_mark:
                                # 根据截取的so名搜索
                                so_name = self.get_recommended_keyword(so_name)
                                so_result_dict[jar_path][file_path_in_jar] = self.recommend_by_so(so_name)
                            else:
                                so_result_dict[jar_path][file_path_in_jar] = {'mark': -1,
                                                                              'version': '',
                                                                              'repo_url': '',
                                                                              'minversion': ''}
            else:
                # 根据截取的so名搜索
                for file_path_in_so in so_result_dict[jar_path]:
                    if so_result_dict[jar_path][file_path_in_so] == 0:
                        continue

                    try:
                        line_no = so_result_dict[jar_path][file_path_in_so]['line_no']
                    except Exception:
                        line_no = ''

                    try:
                        if so_result_dict[jar_path][file_path_in_so]['mark'] in [0, 1]:
                            mark = so_result_dict[jar_path][file_path_in_so]['mark']
                            version = so_result_dict[jar_path][file_path_in_so]['version']
                            try:
                                minversion = so_result_dict[jar_path][file_path_in_so]['minversion']
                            except Exception:
                                minversion = ''

                            try:
                                repo_url = so_result_dict[jar_path][file_path_in_so]['repo_url']
                            except Exception:
                                repo_url = ''

                            file_path_in_so_type = df().get_file_type(file_path_in_so)
                            if (file_path_in_so_type and
                                    "elf" in file_path_in_so_type.lower()):
                                so_result_dict[jar_path][file_path_in_so] = {'mark': mark,
                                                                             'version': version,
                                                                             'repo_url': repo_url,
                                                                             'minversion': minversion}
                            else:
                                so_result_dict[jar_path][file_path_in_so] = {"mark": mark,
                                                                             "version": version,
                                                                             "line_no": line_no,
                                                                             'repo_url': repo_url,
                                                                             'minversion': minversion}
                            continue
                    except Exception:
                        pass

                    so_name = os.path.split(file_path_in_so)[-1]
                    so_name_sql = so_name_to_search(so_name)
                    if self.class_value != 'udf':
                        if self.class_value == 'xarch' and so_result_dict[jar_path][file_path_in_so] != 'x86_64':
                            so_result_dict[jar_path][file_path_in_so] = {'mark': -1,
                                                                         'version': '',
                                                                         'line_no': '',
                                                                         'repo_url': '',
                                                                         'minversion': ''}
                            continue
                        sql_so = "SELECT name, version, repo_url, snippet, minversion FROM so_el8 WHERE name like ?;"
                        so_info = mysql.search_one(sql_so, (so_name_sql + "%",))
                        if so_info:
                            version = so_info[1] if so_info[1] else so_info[2]
                            repo_url = so_info[2]
                            version_source = int(so_info[3]) if so_info[3] is not None else -1
                            minversion = so_info[4]
                            so_result_dict[jar_path][file_path_in_so] = {'mark': version_source,
                                                                         'version': version,
                                                                         'repo_url': repo_url,
                                                                         'minversion': minversion}
                            continue
                    else:
                        sql_so = "SELECT name, version, repo_url, snippet, minversion FROM so_el7 WHERE name like ?;"
                        so_info = mysql.search_one(sql_so, (so_name_sql + "%",))
                        if so_info:
                            version = so_info[1] if so_info[1] else so_info[2]
                            repo_url = so_info[2]
                            version_source = int(so_info[3]) if so_info[3] is not None else -1
                            minversion = so_info[4]

                            file_path_in_so_type = df().get_file_type(file_path_in_so)
                            if (file_path_in_so_type and
                                    "elf" in file_path_in_so_type.lower()):
                                so_result_dict[jar_path][file_path_in_so] = {'mark': version_source,
                                                                             'version': version,
                                                                             'repo_url': repo_url,
                                                                             'minversion': minversion}
                            else:
                                so_result_dict[jar_path][file_path_in_so] = {'mark': version_source,
                                                                             'version': version,
                                                                             'line_no': line_no,
                                                                             'repo_url': repo_url,
                                                                             'minversion': minversion}
                            continue

                    if self.recommend_mark:
                        so_name = self.get_recommended_keyword(so_name)
                        so_result_dict[jar_path][file_path_in_so] = self.recommend_by_so(so_name)
                    else:
                        so_result_dict[jar_path][file_path_in_so] = {'mark': -1,
                                                                     'version': '',
                                                                     'line_no': line_no,
                                                                     'repo_url': '',
                                                                     'minversion': ''}

        return so_result_dict

    def recommend_by_so(self, so_name):
        """
        Recommend the corresponding version through so.
        param so_name: -> string
            The processed so name to be recommended.
        return: -> dictionary
            The corresponding version searched by so is also the source identification.
        """
        url = ""
        mark_arg = 'mark'
        repo_ulr_arg = 'repo_url'
        version_arg = 'version'
        maven_arg = 'maven'
        github_arg = 'github'
        http_arg = 'http'

        parameters = self.auto_recommendation(so_name, '0', self.log_type)

        if parameters and parameters[mark_arg] != -1:
            mark_type = parameters[mark_arg]
            if mark_type == 0:
                repo_type = maven_arg
            else:
                repo_type = github_arg

            version = parameters[version_arg]
            version_copy = copy.copy(version)

            if http_arg in version:
                url = version
                version = ''

            mysql = MySqlite(self.db_path)
            sql_insert = "INSERT INTO so_el8(name, version, repo_url, snippet) values(?, ?, ?, ?);"
            mysql.execute(sql_insert, (so_name, version, url, repo_type))

            return {mark_arg: mark_type, version_arg: version_copy, repo_ulr_arg: url}

        else:
            return {mark_arg: -1, version_arg: '', repo_ulr_arg: ''}

    def match_pom_files_dependent_line_numbers(self, so_result):
        """
        According to the detection results, match the number of lines
        where the dependencies are located in the pom file.
        param so_result: -> dictionary
            The detection result of the detection object.
        return: -> dictionary
            Processed detection results.
        """
        # Traverse the detection results of the detected object, and obtain the so and
        # pom dependencies contained in each compressed package.
        for zip_package_key in so_result:
            try:
                zip_package_value = so_result[zip_package_key]
            except Exception:
                return so_result

            file_extension = zip_package_key.split('.')[-1]
            if ('java' in file_extension or
                    'class' in file_extension or
                    'so' in file_extension):
                continue

            if (zip_package_value and
                    type(zip_package_value) is dict):
                # Traverse the detection results corresponding to each compressed package.
                for dependent_or_so in zip_package_value:
                    # If it is an so file, it is not considered,
                    # only the dependent information is considered.
                    if not os.path.exists(dependent_or_so) and '/' in dependent_or_so:
                        # Traverse the pom file analysis results contained in the compressed package
                        # [this result contains the line number corresponding to the dependency].
                        for package_key in self.zip_package_pom_path_results:
                            try:
                                package_value = self.zip_package_pom_path_results[package_key]
                            except Exception:
                                continue

                            # Obtain the dependency information corresponding to each pom file.
                            for pom_file_key in package_value:
                                try:
                                    pom_file_value = package_value[pom_file_key]
                                except Exception:
                                    continue

                                if not pom_file_value:
                                    continue

                                # Use the dependency information corresponding to each pom file obtained to match
                                # the detected dependency information. If they are consistent,
                                # get its line number and save it.
                                for dependent in pom_file_value:
                                    if dependent_or_so.replace('/', '.') == dependent.replace('/', '.'):
                                        try:
                                            dependent_line_no = pom_file_value[dependent]['line_no']
                                        except Exception:
                                            continue

                                        if dependent_line_no:
                                            zip_name = package_key.split('/')[-1]
                                            pom_file_path = pom_file_key.split(zip_name)[-1]
                                            if pom_file_path.lstrip('/').split('/')[0] in zip_name:
                                                pom_file_path = pom_file_path.lstrip('/').split('/')
                                                del pom_file_path[0]
                                                pom_file_path = '/'.join(pom_file_path)
                                            else:
                                                pom_file_path = pom_file_key.strip('/').split('/')
                                                del pom_file_path[0]
                                                del pom_file_path[0]
                                                pom_file_path = '/'.join(pom_file_path)
                                                zip_name = ''

                                            # Determine whether the line number information already exists, if not,
                                            # save it directly, if it exists,
                                            # add new line number information based on it.
                                            try:
                                                zip_dependent_line_no = zip_package_value[dependent_or_so]['line_no']
                                                zip_package_value[dependent_or_so]['line_no'] = \
                                                    "{}, {}{} @ line {}".format(zip_dependent_line_no,
                                                                                zip_name + '/' if zip_name else zip_name,
                                                                                pom_file_path,
                                                                                dependent_line_no)
                                            except Exception:
                                                zip_package_value[dependent_or_so]['line_no'] = \
                                                    "Update the version in POM {}{} @ line {}".format(
                                                        zip_name + '/' if zip_name else zip_name,
                                                        pom_file_path,
                                                        dependent_line_no)
                                            break

        return so_result

    def package_compatible_jar_record_log(self, package_path, so_result,
                                          keys, log_type, json_log_filename,
                                          is_to_be_verified):
        """
        When the detection object is a directory, save the detection result
        as a compatible compressed package to the log.
        param package_path: -> str
            The absolute path of the packet to be detected.
        param so_result: -> dictionary
            The detection result of the detection object.
        param keys: -> list
            The key value of the detected object detection result.
        param log_type: -> str
            Specify the result record format.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        param is_to_be_verified: -> list
            File summary result details.
        return: -> None
        """
        for key in keys:
            res = so_result[key]
            sub_result_key = list(res.keys())

            mark = True
            if sub_result_key:
                for sub_key in sub_result_key:
                    if type(res[sub_key]) is not int:
                        mark = False

            if (os.path.isdir(package_path) and
                    mark and
                    key not in self.non_test_file and
                    log_type != 'json' and
                    is_to_be_verified[2] != sum(is_to_be_verified) and
                    is_to_be_verified[3] != sum(is_to_be_verified)):
                self.inspection_result_output(key, 0, 0,
                                              log_type, False, json_log_filename)
        return

    def directory_so_file_processing(self, zip_so_files, schedule, quiet_mark, package_path, warning_tag):
        """
        When the detection object is a directory, classify the so that
        the directory directly contains [not in the subcompression],
        and judge the compatibility.
        param zip_so_files: -> list
            `The so, jar, Java and python files contained in the directory.
        return so_test_result: -> dictionary
            The directory contains the detection results of so.
        """
        so_final_result = {}
        staticdata = [0, 0, 0, 0, 0]
        so_list = dp().filter_so_binary_file(zip_so_files, schedule, quiet_mark)
        so_file_list = copy.deepcopy(so_list)
        if so_list:
            # 根据分组检测结果，判断出分组整体是否兼容
            # 对so按照project和so_name进行分组
            so_classification_result = sp().so_document_classification(so_file_list)
            if self.warning_tag:
                so_classification_result = self.architecture_screen(so_classification_result)
                so_classification_result, so_file_list = self.skip_warning3_so(so_classification_result)

            if self.class_value != 'xarch':
                # 对分组后的so进行检测，是否是aarch64类型
                so_parse_res = self.parse_so_document(so_classification_result, dir_tag=True)
                so_final_res = self.final_recommendation_result(so_parse_res, so_classification_result)
                for so_path, value in so_final_res.items():
                    so_final_result[so_path] = {
                        so_path: value
                    }
            else:
                result = so_document_classification(so_classification_result)
                so_final_res, staticdata = self.final_recommendation_result_xarch(so_classification_result, result)
                for so_path in so_final_res:
                    so_final_result[so_path] = {
                        so_path: so_final_res[so_path]
                    }

        so_test_result = {
            "so_list": so_list,
            "so_file_list": so_file_list,
            "so_final_res": so_final_result,
            "staticdata": staticdata
        }
        return so_test_result

    def check_file_type(self, file_path):
        elf_type_list = ['jnilib', 'Windows lib', 'Windows dll', 'Mac lib', 'lib']
        file_type = get_file_type_by_suffix(file_path)
        file_type_by_cmd = get_file_real_type(file_path)
        file_type_lower = file_type_by_cmd.lower()

        if (file_type == "ELF" or file_type in elf_type_list or 'elf' in file_type_lower or "dll" in file_type_lower) \
                and not list(filter(lambda x: x.lower() in file_type_lower, compatible_default_list)):
            self.so_file_count += 1

        elif file_path.endswith(".class") or 'java class data' in file_type_lower:
            self.class_file_count += 1

        elif file_type == "java" or 'java source' in file_type_lower:
            self.java_file_count += 1

        elif file_type == "pom" or file_path.endswith('pom.xml'):
            self.pom_file_count += 1

        elif determine_unpack(file_path) and (("(jar)" in file_type_lower or "jar" in file_type) or
                                              (file_path.endswith(".ear") or file_path.endswith(".war"))):
            self.jar_file_count += 1

        elif determine_unpack(file_path) and "(jar)" not in file_type_lower and not file_path.endswith(".war") \
                and not file_path.endswith(".ear"):
            self.zip_file_count += 1

        else:
            self.other_file_count += 1

    def check_file_is_py_class_so_zip(self, file_path):
        """
        Check whether the file is a python, java, zip, or so file.
        param file_path: -> string
            The file to be checked.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        return: -> string
            The detected file type.
        """
        python_str = 'py'
        java_str = 'java'
        zip_str = 'zip'
        so_str = 'so'
        pom_str = 'pom'

        file_type = df().get_file_precise_type(file_path).lower()
        file_path_type = df().get_file_type(file_path)
        type_slice = file_type.split()
        if file_type == python_str or 'python' in type_slice:
            result_arg = python_str
        elif file_type == 'text':
            result_arg = 'other'
        elif file_type == java_str or 'java source' in file_type or 'java class data' in file_type:
            result_arg = java_str
        elif file_type == so_str or 'elf' in type_slice or file_type in constant.elf_type_list:
            if file_path.endswith('.bin') and file_path_type:
                new_type = file_path_type.split(',')[0].lower()
                if 'text' in new_type or 'data' in new_type:
                    result_arg = 'other'
                else:
                    result_arg = so_str
            else:
                result_arg = so_str
        elif determine_unpack(file_path):
            result_arg = zip_str
        elif not self.binary_check and \
                (file_type == pom_str or
                 file_path.endswith('.pom') or
                 file_path.endswith('pom.xml')):
            result_arg = pom_str
        elif self.warning_tag and check_file(file_path_type):
            result_arg = 'warning'
        else:
            result_arg = 'other'
        return result_arg

    def class_file_type(self, file_path):
        # 0 兼容，不需要检测 1 so文件 2 java文件 3 zip文件 4不兼容文件 5TBV
        file_type = get_file_type_by_suffix(file_path)
        file_type_lower = file_type.lower()
        file_type_by_cmd = get_file_real_type(file_path)
        file_type_by_cmd_lower = file_type_by_cmd.lower()
        file_name = get_file_name(file_path)
        type_str = 0
        if file_name in constant.confirmed_list or file_type == 'text':
            type_str = 0
        elif file_type == 'py' or 'python' in file_type_by_cmd_lower:
            type_str = 'other'
            if file_name.endswith('.rst'):
                type_str = 0
        elif file_type == 'java' or 'java source' in file_type_lower or 'java class data' in file_type_lower:
            type_str = 'java'
        elif file_type == '.jar' and '.xml' in file_type_by_cmd_lower:
            type_str = 0
        elif file_type == "ELF" or file_type in constant.elf_type_list or 'elf' in file_type_by_cmd_lower:
            type_str = 'so_file'
            if file_path.endswith('.bin'):
                if 'text' in file_type_by_cmd_lower or 'data' in file_type_by_cmd_lower \
                        and 'archive' not in file_type_by_cmd_lower:
                    type_str = 0
        elif determine_unpack(file_path):
            type_str = 'zip_file'
        elif file_type == 'pom' or file_path.endswith('.pom') or file_path.endswith('pom.xml'):
            if self.binary_check:
                type_str = 'pom'
            else:
                type_str = 0
        elif is_default_compatible_file(file_type_by_cmd_lower, file_type_lower):
            type_str = 0
        elif check_file_incompatible(file_type_by_cmd):
            type_str = 'incom_file'
        else:
            type_str = 'other'
        return type_str, file_path, file_type

    def check_file_suffix(self, file_path, real_path):
        # O other文件 C 兼容文件 S so文件 Z zip类
        file_type = get_file_type_by_suffix(file_path)
        file_name = get_file_name(file_path)
        file_type_cmd = ""
        type_str = "O"
        if file_name in constant.confirmed_list or file_type == 'text' or file_type == 'java':
            type_str = 'C'
        elif file_type == "ELF" or file_type in constant.elf_type_list or 'elf' in file_type_cmd:
            if file_name.endswith('.bin'):
                file_type_cmd = get_file_real_type(file_path)
                if 'text' in file_type_cmd or 'data' in file_type_cmd and 'archive' not in file_type_cmd:
                    type_str = "O"
            elif file_type in self.skip_list:
                real_path = file_path.replace(self.ep_temp_files, os.path.split(real_path)[0])
                logger.info('Warning_ZIP3 {}'.format(real_path), 'java')
                type_str = 'C'
            else:
                type_str = 'S'
        elif file_type in compatible_default_list:
            # 兼容
            type_str = 'C'
        elif file_type in zip_arg and file_type not in compatible_default_list:
            type_str = 'Z'

        return type_str

    def so_file_processing(self, file_path, is_no_to_be_verified):
        non_test_file = []
        non_test_file_results = []
        noarch_count = 0
        uncertain_count = 0
        is_no_to_be_verified[2] += 1
        if self.quiet_mark and self.warning_check:
            self.to_be_verified_info_output(file_path)
        if not self.class_value:
            non_test_file.append(file_path)
            non_test_file_results = self.verified_file_log_result_data_processing(file_path)
        uncertain_count += 1

        other_result = {
            "is_no_to_be_verified": is_no_to_be_verified,
            "non_test_file": non_test_file,
            "non_test_file_results": non_test_file_results,
            'uncertain': uncertain_count,
            'noarch': noarch_count
        }
        return other_result

    def other_file_processing_internal(self, file_path):
        """
        Count and save files of the other type.
        param file_path: -> string
            The absolute path of the to be verified type file.
        param is_no_to_be_verified: -> list
            to be verified statistical results.
        return:
            other_result: -> dictionary
                Other types of file detection results.
        """
        python_file_tag = ["py", 'python']
        non_test_file = []
        non_test_file_results = []
        uncertain_count = 0
        noarch_count = 0
        try:
            ret, file_type = gft(file_path)
            file_type_lower = file_type.lower()
            file_type_str = df().get_file_type(file_path).split(',')[0]
            file_type_suffix = get_file_type_by_suffix(file_path)
            file_type_suffix_lower = file_type_suffix.lower()
            file_type_py = df().get_file_precise_type(file_path).lower()
            type_slice = file_type_py.split()
            file_name = get_file_name(file_path)
            if link_file in file_type:
                file_type = read_link_src_path(file_path)
            if self.warning_tag:
                if file_name in constant.confirmed_list:
                    return {}
                if check_file(file_type):
                    logger.warning('Warning_ZIP3 {}'.format(os.path.abspath(self.get_zip_path(file_path))), 'java')
            else:
                if (file_type_py == python_file_tag[0] or python_file_tag[1] in type_slice) or \
                        ((not file_path.endswith('.jar') and 'xml' not in file_type_str.lower()) and
                         (self.broken_link not in file_type) and (file_type_str not in compatible_default_list) and
                         "text" not in file_type_str and not
                         is_default_compatible_file(file_type_lower, file_type_suffix_lower) and
                         compatible_file not in file_path):
                    non_test_file.append(file_path)
                    non_test_file_results = self.verified_file_log_result_data_processing(file_path)
        except Exception:
            pass

        other_result = {
            "non_test_file": non_test_file,
            "non_test_file_results": non_test_file_results,
            'uncertain': uncertain_count,
            'noarch': noarch_count
        }
        return other_result

    def other_file_processing(self, file_path, is_no_to_be_verified):
        """
        Count and save files of the other type.
        param file_path: -> string
            The absolute path of the to be verified type file.
        param is_no_to_be_verified: -> list
            to be verified statistical results.
        return:
            other_result: -> dictionary
                Other types of file detection results.
        """
        json_arg = 'json'

        non_test_file = []
        non_test_file_results = []
        uncertain_count = 0
        noarch_count = 0
        warning_count = 0
        try:
            ret, file_type = gft(file_path)
            file_type_lower = file_type.lower()
            file_type_str = df().get_file_type(file_path).split(',')[0]
            file_type_str_lower = file_type_str.lower()
            file_type_suffix = get_file_type_by_suffix(file_path)
            file_type_suffix_lower = file_type_suffix.lower()
            if link_file in file_type:
                file_type = read_link_src_path(file_path)
                if not file_type:
                    noarch_count += 1
                    is_no_to_be_verified[0] += 1
                    if self.log_file != json_arg:
                        self.inspection_result_output(file_path, 0, 0,
                                                      self.log_file, False, self.json_log_filename)

                    other_result = {
                        "is_no_to_be_verified": is_no_to_be_verified,
                        "non_test_file": non_test_file,
                        "non_test_file_results": non_test_file_results,
                        'uncertain': uncertain_count,
                        'noarch': noarch_count
                    }
                    return other_result

            # warning3
            if self.warning_tag and check_file(file_type):
                logger.warning("Warning3 {}".format(os.path.abspath(self.get_zip_path(file_path))), 'java')
                warning_count += 1
            else:
                if (not file_path.endswith('.jar') and 'xml' not in file_type_str_lower) and \
                        (self.broken_link not in file_type_str) and (file_type_str not in compatible_default_list) \
                        and ("text" not in file_type_str) and not \
                        is_default_compatible_file(file_type_lower, file_type_suffix_lower) \
                        and compatible_file not in file_path:
                    if self.class_value != 'cs':
                        is_no_to_be_verified[2] += 1
                        if self.quiet_mark and self.warning_check:
                            self.to_be_verified_info_output(file_path)
                        logger.warning("Skipped {}".format(file_path), 'java')
                        if not self.class_value:
                            non_test_file.append(file_path)
                            non_test_file_results = self.verified_file_log_result_data_processing(file_path)
                        uncertain_count += 1
                    else:
                        is_no_to_be_verified[2] += 1
                        if self.quiet_mark and self.warning_check:
                            self.to_be_verified_info_output(file_path)
                        logger.warning("Skipped {}".format(file_path), 'java')
                        non_test_file.append(file_path)
                        non_test_file_results = self.verified_file_log_result_data_processing(file_path)
                        uncertain_count += 1
                else:
                    noarch_count += 1
                    is_no_to_be_verified[0] += 1
                    if self.log_file != json_arg:
                        self.inspection_result_output(file_path, 0, 0,
                                                      self.log_file, False, self.json_log_filename)
        except Exception:
            pass

        other_result = {
            "is_no_to_be_verified": is_no_to_be_verified,
            "non_test_file": non_test_file,
            "non_test_file_results": non_test_file_results,
            'uncertain': uncertain_count,
            'noarch': noarch_count,
            'warning_count': warning_count
        }
        return other_result

    def other_file_processing_xarch(self, file_path):
        """
        Count and save files of the other type.
        param file_path: -> string
            The absolute path of the to be verified type file.
        param is_no_to_be_verified: -> list
            to be verified statistical results.
        return:
            other_result: -> dictionary
                Other types of file detection results.
        """
        file_type = get_file_type_by_suffix(file_path)
        file_type_lower = file_type.lower()
        file_type_cmd = get_file_real_type(file_path)
        file_type_cmd_lower = file_type_cmd.lower()
        file_name = get_file_name(file_path)
        if link_file in file_type_cmd_lower:
            file_type_cmd = read_link_src_path(file_path)
            file_type_cmd_lower = file_type_cmd.lower()
        if file_name in constant.confirmed_list or file_type == 'text':
            category = 'noarch'
        elif (check_file(file_type) and not list(filter(lambda x: x.lower() in file_type_cmd_lower or x.lower()
                                                        in file_type_lower, compatible_default_list))) \
                or check_file(file_type_cmd):
            if self.warning_tag:
                logger.warning('Warning3 {}'.format(os.path.abspath(self.get_zip_path(file_path))), 'java')
                category = 'warning'
            else:
                category = 'x86_64'
        elif (file_path.endswith('.jar') and 'xml' in file_type_lower) or self.broken_link in file_type_cmd_lower:
            category = 'noarch'
        elif (file_path.endswith('.bin') and "text" in file_type_lower) or compatible_file not in file_path:
            category = 'noarch'
        elif not is_default_compatible_file(file_type_cmd_lower, file_type_lower):
            category = 'uncertain'
        else:
            category = 'noarch'

        return category

    def python_file_processing(self, file_path, is_no_to_be_verified):
        """
        Count and save files of the python type.
        param file_path: -> string
            The absolute path of the to be verified type file.
        param is_no_to_be_verified: -> list
            to be verified statistical results.
        return:
            python_result: -> dictionary
                Python types of file detection results.
        """

        non_test_file = []
        non_test_file_results = []

        if not self.class_value or self.class_value == 'cs':
            is_no_to_be_verified[2] += 1
            if self.quiet_mark and self.warning_check:
                self.to_be_verified_info_output(file_path)
            logger.warning("Skipped {}".format(file_path), 'java')
            non_test_file.append(file_path)
            non_test_file_results = self.verified_file_log_result_data_processing(file_path)
        else:
            is_no_to_be_verified[2] += 1
            if self.quiet_mark and self.warning_check:
                self.to_be_verified_info_output(file_path)
            logger.warning("Skipped {}".format(file_path), 'java')

        python_result = {
            "is_no_to_be_verified": is_no_to_be_verified,
            "non_test_file": non_test_file,
            "non_test_file_results": non_test_file_results
        }
        return python_result

    def java_file_processing(self, file_path, is_no_to_be_verified):
        """
        Count and save files of the java type.
        param file_path: -> string
            The absolute path of the to be verified type file.
        param is_no_to_be_verified: -> list
            to be verified statistical results.
        return:
            java_result: -> dictionary
                Java types of file detection results.
        """
        json_arg = 'json'

        non_test_file = []
        non_test_file_results = []

        is_no_to_be_verified[0] += 1
        if self.log_type != json_arg:
            self.inspection_result_output(file_path, 0, 0,
                                          self.log_type, False, self.json_log_filename)

        java_result = {
            "is_no_to_be_verified": is_no_to_be_verified,
            "non_test_file": non_test_file,
            "non_test_file_results": non_test_file_results
        }
        return java_result

    def to_be_verified_file_processing(self, file_path, is_no_to_be_verified):
        """
        Count and save files of the to be verified type.
        param file_path: -> string
            The absolute path of the to be verified type file.
        param is_no_to_be_verified: -> list
            to be verified statistical results.
        return:
            verified_result: -> dictionary
                To be verified types of file detection results.
        """
        non_test_file = []

        is_no_to_be_verified[2] += 1
        if self.quiet_mark and self.warning_check:
            self.to_be_verified_info_output(file_path)
        logger.warning("Skipped {}".format(file_path), 'java')
        non_test_file_results = self.verified_file_log_result_data_processing(file_path)
        sl().execute_log_records(self.log_file, file_path)
        verified_result = {
            "is_no_to_be_verified": is_no_to_be_verified,
            "non_test_file": non_test_file,
            "non_test_file_results": non_test_file_results
        }
        return verified_result

    def compatible_file_processing(self, file_path, decompress_failed_mark, decompress_file, is_to_be_verified,
                                   decompress_file_path, so_result_dic, is_no_to_be_verified):
        """
        Compatible files are processed and file detection results are collected.
        param file_path: -> string
            The absolute path of the to be verified type file.
        param decompress_failed_mark: -> boolean
            File decompression failure flag.
        param decompress_file: -> list
            The storage path of the decompressed file.
        param is_to_be_verified: -> boolean
            Whether the file is to be verified type file identification.
        param decompress_file_path: -> string
            Detect the decompression path of the object.
        param so_result_dic: -> dictionary
            The result of whether the so files detected in the file are compatible.
        param is_no_to_be_verified: -> list
            The result list of which type [compatible, incompatible, to be verified, failed]
            the statistical file belongs to.
        return:
            compatible_result: -> dictionary
                File compatibility results.
        """
        json_arg = 'json'
        compressed_to_python = []

        if not self.class_value:
            if is_to_be_verified:
                verified_result = self.to_be_verified_file_processing(file_path,
                                                                      is_no_to_be_verified)
                compatible_result = {
                    "is_no_to_be_verified": verified_result.get("is_no_to_be_verified", [0, 0, 0, 0]),
                    "decompress_file_path": decompress_file_path,
                    "so_result_dic": so_result_dic,
                    "compressed_to_python": compressed_to_python,
                    "non_test_file": verified_result.get("non_test_file", []),
                    "non_test_file_results": verified_result.get("non_test_file_results", []),
                }
                return compatible_result
        else:
            if is_to_be_verified:
                if self.quiet_mark and self.warning_check:
                    self.to_be_verified_info_output(file_path)
                logger.warning("Skipped {}".format(file_path), 'java')
                is_no_to_be_verified[2] += 1
                if not self.engine:
                    compressed_to_python.append(file_path)
                    decompress_file_path.remove(decompress_file[0])
                    del so_result_dic[file_path]

                compatible_result = {
                    "is_no_to_be_verified": is_no_to_be_verified,
                    "decompress_file_path": decompress_file_path,
                    "so_result_dic": so_result_dic,
                    "compressed_to_python": compressed_to_python
                }
                return compatible_result

        if decompress_failed_mark:
            is_no_to_be_verified[3] += 1
            self.inspection_result_output(file_path, 0, -1,
                                          self.log_type, False, self.json_log_filename)
        else:
            is_no_to_be_verified[0] += 1
            if self.log_type != json_arg:
                self.inspection_result_output(file_path, 0, 0,
                                              self.log_type, False, self.json_log_filename)

        compatible_result = {
            "is_no_to_be_verified": is_no_to_be_verified,
            "decompress_file_path": decompress_file_path,
            "so_result_dic": so_result_dic,
            "compressed_to_python": compressed_to_python
        }
        return compatible_result

    def zip_so_file_processing(self, file_path, zip_so_files, is_no_to_be_verified, decompress_file_path,
                               so_result_dic, jar_arg, so_arg, other_arg, mark):
        """
        Compressed package or so file processing.
        param file_path: -> string
            The absolute path of the to be verified type file.
        param zip_so_files: -> list
            Detect all tarballs and so files contained in the directory.
        param is_no_to_be_verified: -> list
            The result list of which type [compatible, incompatible, to be verified, failed]
            the statistical file belongs to.
        param decompress_file_path: -> string
            Detect the decompression path of the object.
        param so_result_dic: -> dictionary
            The result of whether the so files detected in the file are compatible.
        param jar_arg: -> int
            The initial value of how many subcompressed packages are
            counted in the compressed package.
        param so_arg: -> int
            Count the initial value of how many so files are in the compressed package.
        param other_arg: -> int
            Count the initial value of how many non-compressed and non-so files
            in the compressed package.
        param mark: -> boolean
            Indicates whether to evaluate only.
        return:
            test_results: -> dictionary
                Inspection results for all inspection files.
        """
        json_arg = 'json'
        non_test_file = []
        non_test_file_results = []
        compressed_to_python = []
        non_test_file_other = []
        non_test_file_results_other = []
        is_no_to_be_verified_other = copy.copy(is_no_to_be_verified)
        compatible_mark = True
        # udf且无指定引擎情景下，非jar的压缩包如果包含了py关键字，则跳过检测
        if (self.class_value == 'udf' and
                not self.engine and
                self.is_py_zip(file_path.split('/')[-1]) and
                not file_path.split('/')[-1].endswith('.jar')):
            is_no_to_be_verified[2] += 1
            if self.quiet_mark and self.warning_check:
                self.to_be_verified_info_output(file_path)
            logger.warning("Skipped {}".format(file_path), 'java')

            test_results = {
                "scan_result": is_no_to_be_verified,
                "decompress_file_path": decompress_file_path,
                "so_result_dic": so_result_dic,
                "jar_arg": jar_arg,
                "so_arg": so_arg,
                "other_arg": other_arg,
            }
            return test_results

        file_type = df().get_file_type(file_path).split(',')[0]
        # 如果压缩包已jar结尾，且jar不属于压缩类型只包含xml，则跳过检测直接默认兼容
        if file_path.endswith('.jar') and 'xml' in file_type.lower():
            is_no_to_be_verified[0] += 1
            if self.log_type != json_arg:
                self.inspection_result_output(file_path, 0, 0,
                                              self.log_type, False, self.json_log_filename)
            test_results = {
                "scan_result": is_no_to_be_verified,
                "decompress_file_path": decompress_file_path,
                "so_result_dic": so_result_dic,
                "jar_arg": jar_arg,
                "so_arg": so_arg,
                "other_arg": other_arg,
            }
            return test_results
        check_jar_so_result = self.check_all_so_file(file_path,
                                                     self.number,
                                                     self.log_type,
                                                     mark,
                                                     self.quiet_mark,
                                                     self.json_log_filename)

        so_result = check_jar_so_result["so_result"]  # 1 兼容或者解压失败
        sub_file_count = check_jar_so_result["sub_file_count"]
        decompress_file = check_jar_so_result["decompress_file_path"]  # 1,5 解压失败
        is_to_be_verified = check_jar_so_result["is_to_be_verified"]
        decompress_failed_mark = check_jar_so_result["decompress_failed_mark"]
        other_list = check_jar_so_result.get("other_list", [])
        failed_zip_list = check_jar_so_result.get("failed_zip_list", [])
        zip_node_list = check_jar_so_result.get("zip_node_list", [])
        non_test_file_other += other_list
        zip_name = get_file_name(file_path)
        if self.class_value != 'cs':
            non_test_file_other = [tbv_file.split(zip_name)[-1].strip('/') for tbv_file in non_test_file_other]
        non_test_file.extend(non_test_file_other)
        if failed_zip_list:
            so_result = 1
            decompress_file = 1

        if (so_result != 1 and
                (decompress_file != 1 and decompress_file != 5)):  # 解压成功且有收集到so、pom、java文件依赖

            # 判断file_path整体是否兼容
            compatible_mark, so_result = self.whether_test_result_is_no_compatible(file_path, so_result,
                                                                                   self.json_log_filename,
                                                                                   is_to_be_verified)

            decompress_file_path.append(decompress_file[0])
            so_result_dic[file_path] = {}
            for key in so_result:
                for key1 in so_result[key]:
                    so_result_dic[file_path][key1] = so_result[key][key1]

            jar_arg += sub_file_count["jar"]
            so_arg += sub_file_count["so"]
            other_arg += sub_file_count["other"]

            if compatible_mark:
                if list(so_result.keys()):
                    so_result_key = list(so_result.keys())[0]
                    self.compatible_list.put(so_result_key)
                compatible_res = self.compatible_file_processing(file_path, decompress_failed_mark, decompress_file,
                                                                 is_to_be_verified, decompress_file_path,
                                                                 so_result_dic, is_no_to_be_verified)
                is_no_to_be_verified = compatible_res.get("is_no_to_be_verified", [0, 0, 0, 0])
                decompress_file_path = compatible_res.get("decompress_file_path", [])
                so_result_dic = {}
                compressed_to_python = compatible_res.get("compressed_to_python", [])
                non_test_file += compatible_res.get("non_test_file", [])
                non_test_file_results = compatible_res.get("non_test_file_results", [])
            else:
                is_no_to_be_verified[1] += 1

        elif (so_result == 1 and
              (decompress_file != 1 and decompress_file != 5)):  # 兼容的检测对象处理
            decompress_file_path.append(decompress_file[0])

            if (not self.class_value and
                    is_to_be_verified):
                to_be_verified_res = self.to_be_verified_file_processing(file_path,
                                                                         is_no_to_be_verified)
                is_no_to_be_verified = to_be_verified_res.get("is_no_to_be_verified", [0, 0, 0, 0])
                non_test_file += to_be_verified_res.get("non_test_file", [])
                non_test_file_results = to_be_verified_res.get("non_test_file_results", [])
            else:
                is_no_to_be_verified[0] += 1
                if self.log_type != json_arg:
                    self.inspection_result_output(file_path, 0, 0,
                                                  self.log_type, False, self.json_log_filename)

        else:  # 解压报错的检测对象处理
            tbv_list = failed_zip_list + non_test_file
            if decompress_file == 5:
                is_no_to_be_verified[2] += 1
                if self.quiet_mark and self.warning_check:
                    self.to_be_verified_info_output(file_path)
                logger.warning("Skipped {}".format(file_path), 'java')
                self.inspection_result_output(file_path, 0, -2,
                                              self.log_type, False, self.json_log_filename, tbv_list=tbv_list)
            else:
                is_no_to_be_verified[3] += 1
                self.inspection_result_output(file_path, 0, -1,
                                              self.log_type, False, self.json_log_filename, tbv_list=tbv_list)

        non_test_file_results.extend(non_test_file_results_other)
        test_results = {
            "scan_result": is_no_to_be_verified,
            "decompress_file_path": decompress_file_path,
            "so_result_dic": so_result_dic,
            "jar_arg": jar_arg,
            "so_arg": so_arg,
            "other_arg": other_arg,
            "compressed_to_python": compressed_to_python,
            "non_test_file": non_test_file,
            "non_test_file_results": non_test_file_results,
            "zip_node_list": zip_node_list,
            "to_be_verified": False
        }

        if non_test_file and not failed_zip_list:
            if not self.class_value:
                if compatible_mark is False:
                    is_no_to_be_verified_other[1] = 1
                    test_results["scan_result"] = is_no_to_be_verified_other
                    test_results["to_be_verified"] = True
                else:
                    is_no_to_be_verified_other[2] = 1
                    test_results["scan_result"] = is_no_to_be_verified_other
                    test_results["to_be_verified"] = True
                    self.compatible_results = []
            else:
                is_no_to_be_verified_other[2] = 1
                test_results["scan_result"] = is_no_to_be_verified_other
                test_results["to_be_verified"] = True
                self.compatible_results = []
        return test_results

    def all_file_processing(self, file_path, decompress_file_path, zip_so_files, mark):
        """
        Classify and process all the files in the detection object,
        and obtain the processing results.
        param file_path: -> string
            The absolute path of the to be verified type file.
        param decompress_file_path: -> string
            Detect the decompression path of the object.
        param zip_so_files:
            Detect all tarballs and so files contained in the directory.
        param mark: -> boolean
            Indicates whether to evaluate only.
        return:
            process_result: -> dictionary
                The detection result of the detection object.
        """
        jar_arg = 0
        so_arg = 0
        other_arg = 0
        warning_count = 0

        non_test_file = []
        non_test_file_results = []
        is_no_to_be_verified = [0, 0, 0, 0]  # 兼容、不兼容、to be verified、failed
        compatible_results = []
        incompatible_results = []
        failed_results = []
        compressed_to_python = []
        child_tbv_file = {}
        pom_line_no_info = {}
        self.jars = []
        self.java_import_file = []
        self.decompress_file_paths = []
        file_type_by_cmd = get_file_real_type(file_path)
        file_type_lower = file_type_by_cmd.lower()

        so_result_dic = {}
        zip_unzip_path = {}
        self.jar_pom_files = {}
        zip_node_list = []
        check_py_java_result = self.check_file_is_py_class_so_zip(file_path)  # 检测文件类型，根据类型走不同逻辑
        logger.info('Began {}'.format(os.path.abspath(file_path)), 'java')
        if check_py_java_result == 'warning':
            logger.info('Warning3 {}'.format(os.path.abspath(file_path)), 'java')
            warning_count += 1
        elif self.class_value != "udf" and check_py_java_result == 'other':
            other_res = self.other_file_processing(file_path, is_no_to_be_verified)
            is_no_to_be_verified = other_res.get('is_no_to_be_verified', [0, 0, 0, 0])
            non_test_file = other_res.get('non_test_file', [])
            non_test_file_results = other_res.get('non_test_file_results', [])
            warning_count += other_res.get('warning_count', 0)
            if not warning_count:
                other_arg += 1

        elif self.class_value == "udf" and check_py_java_result == 'other':
            other_arg += 1
            file_type = get_file_real_type(file_path)
            if 'XML 1.0 document' in file_type and file_path.endswith(".jar"):
                other_res = self.other_file_processing(file_path, is_no_to_be_verified)
                is_no_to_be_verified = other_res.get('is_no_to_be_verified', [0, 0, 0, 0])
                non_test_file = other_res.get('non_test_file', [])
                non_test_file_results = other_res.get('non_test_file_results', [])
            else:
                is_no_to_be_verified[2] += 1
                if self.quiet_mark and self.warning_check:
                    self.to_be_verified_info_output(file_path)
                logger.warning("Skipped {}".format(file_path), 'java')
                if file_path.endswith(".jar") or 'jar' in file_type_lower:
                    non_test_file = [file_path]
                    non_test_file_results = self.verified_file_log_result_data_processing(file_path)
                else:
                    non_test_file = []
                    non_test_file_results = []

        elif check_py_java_result == 'py':
            python_res = self.python_file_processing(file_path, is_no_to_be_verified)
            is_no_to_be_verified = python_res.get('is_no_to_be_verified', [0, 0, 0, 0])
            non_test_file = python_res.get('non_test_file', [])
            non_test_file_results = python_res.get('non_test_file_results', [])

        elif self.binary_check and check_py_java_result == 'java':
            java_res = self.java_file_processing(file_path, is_no_to_be_verified)
            is_no_to_be_verified = java_res.get('is_no_to_be_verified', [0, 0, 0, 0])
            non_test_file = java_res.get('non_test_file', [])
            non_test_file_results = java_res.get('non_test_file_results', [])

        elif check_py_java_result == 'so':
            if self.class_value != 'udf':
                so_arg += 1
                os_res = self.so_file_processing(file_path, is_no_to_be_verified)
                is_no_to_be_verified = os_res.get('is_no_to_be_verified', [0, 0, 0, 0])
                non_test_file = os_res.get('non_test_file', [])
                non_test_file_results = os_res.get('non_test_file_results', [])
            else:
                is_no_to_be_verified[2] += 1
                if self.quiet_mark and self.warning_check:
                    self.to_be_verified_info_output(file_path)
                logger.warning("Skipped {}".format(file_path), 'java')
                self.compressed_to_python.append(file_path)
                non_test_file = []
                non_test_file_results = []

        else:
            if check_py_java_result == 'zip':
                jar_arg += 1
            # 对压缩包、so、没有指定-b下的pom和java文件进行检测
            processing_result = \
                self.zip_so_file_processing(file_path, zip_so_files, is_no_to_be_verified, decompress_file_path,
                                            so_result_dic, jar_arg, so_arg, other_arg, mark)
            if not self.quiet_mark:
                inner_dict = {
                    'project': file_path,
                    'current': 1,
                    'total': 1
                }
                self.inner_queue.put(inner_dict)
            is_no_to_be_verified = processing_result.get('scan_result')
            decompress_file_path = processing_result.get('decompress_file_path')
            so_result_dic = processing_result.get('so_result_dic')
            jar_arg = processing_result.get('jar_arg')
            so_arg = processing_result.get('so_arg')
            other_arg = processing_result.get('other_arg')
            zip_node_list = processing_result.get('zip_node_list', [])
            to_python = []
            if processing_result.get("to_be_verified") is True:
                if self.quiet_mark and self.warning_check:
                    self.to_be_verified_info_output(file_path)
                logger.warning("Skipped {}".format(file_path), 'java')
                if self.class_value == "udf":
                    if file_path.endswith(".jar") or 'jar' in file_type_lower:
                        if not processing_result.get('compressed_to_python', []):
                            non_test_file = [file_path]
                            non_test_file_results = self.verified_file_log_result_data_processing(file_path)
                        else:
                            non_test_file = []
                            non_test_file_results = []
                    else:
                        to_python.append(file_path)
                        non_test_file = []
                        non_test_file_results = []
                else:
                    if self.class_value == "cs":
                        non_test_file = processing_result.get('non_test_file', [])
                        non_test_file_results = processing_result.get('non_test_file_results', [])
                    elif not self.class_value:
                        if so_result_dic and so_result_dic.get(file_path):
                            non_test_file = []
                            non_test_file_results = []
                            child_tbv_files = "\n".join(processing_result.get('non_test_file', []))
                            child_tbv_file[file_path] = child_tbv_files
                        else:
                            non_test_file = [file_path]
                            non_test_file_results = self.verified_file_log_result_data_processing(file_path)
                            child_tbv_files = "\n".join(
                                [i.replace(self.ep_temp_files, '') if self.ep_temp_files in i else i for i
                                 in processing_result.get('non_test_file', [])])
                            if non_test_file_results:
                                non_test_file_results[0].append(child_tbv_files)
                    else:
                        non_test_file = [file_path]
                        non_test_file_results = self.verified_file_log_result_data_processing(file_path)
            else:
                non_test_file = processing_result.get('non_test_file', [])
                non_test_file_results = processing_result.get('non_test_file_results', [])
            compressed_to_python = processing_result.get('compressed_to_python', []) if processing_result.get(
                'compressed_to_python', []) else to_python

        pom_line_no_info.update(self.zip_package_pom_path_results)
        compatible_results += self.compatible_results
        incompatible_results += self.incompatible_results
        failed_results += self.failed_results
        zip_unzip_path.update(self.zip_unzip_path)
        process_result = {}
        try:
            process_result = {"is_no_to_be_verified": is_no_to_be_verified,
                              "decompress_file_path": decompress_file_path,
                              "so_result_dic": so_result_dic,
                              "jar_arg": jar_arg,
                              "so_arg": so_arg,
                              "other_arg": other_arg,
                              "non_test_file": non_test_file,
                              "non_test_file_results": non_test_file_results,
                              "compressed_to_python": compressed_to_python,
                              "compatible_results": sp().filter_list_duplicate_values(compatible_results),
                              "incompatible_results": sp().filter_list_duplicate_values(incompatible_results),
                              "failed_results": sp().filter_list_duplicate_values(failed_results),
                              "zip_unzip_path": zip_unzip_path,
                              "pom_line_no_info": pom_line_no_info,
                              "child_tbv_file": child_tbv_file,
                              "warning_count": warning_count,
                              "mf_path_dict": self.mf_path_dict,
                              "zip_node_list": zip_node_list
                              }
        except Exception:
            print_exc()
        if not self.quiet_mark:
            self.total_queue.put(1)
        logger.info('Ended {}'.format(os.path.abspath(file_path)), 'java')
        return process_result

    def check_result_output_xarch(self, file_path, base_result):
        """
        When the specified class parameter is xarch,
        the corresponding detection result will be output on the screen.
        param file_path: -> string
            The absolute path of the to be verified type file.
        param base_result: -> dictionary
            File detection results.
        return: -> None
        """
        output_parameters = ["NAME", "MD5", "COMPATIBILITY", "TYPE", "INCOMPATIBILITY",
                             "CONCLUSION", "UPGRADE", "TYPE-SRC", "PACKAGE", "VERSION"]
        incom_list = base_result.get('incom_list', [])
        file_value = dp().package_name_processing(file_path)
        file_type = get_file_real_type(file_path)
        name_arg = file_value['name']
        md5_arg = file_value['hash']
        if not incom_list:
            print("\n{0:<15}: {1:<20} \n"
                  "{2:<15}: {3:<20} \n"
                  "{4:<15}: {5:<20} \n"
                  "{6:<15}: {7:<20} \n".format(output_parameters[0], name_arg,
                                               output_parameters[1], md5_arg,
                                               output_parameters[2], base_result.get('category', ''),
                                               output_parameters[3], file_type))
        else:
            type_src_list = base_result.get('from_list', [])
            name_list = base_result.get('package_list', [])
            version_list = base_result.get('version_list', [])
            conclusion = "Open source" if '' not in version_list else "Self-compiled"
            print("\n{0:<15}: {1:<20} \n"
                  "{2:<15}: {3:<20} \n"
                  "{4:<15}: {5:<20} \n"
                  "{6:<15}: {7:<20} \n"
                  "{8:<15}: {9:<20} \n"
                  "{10:<15}: {11:<20} \n"
                  "{12:<15}: {13:<20} \n"
                  "    |{14:<50} |{15:<10} |{16:<30} |{17:<50}"
                  .format(output_parameters[0], name_arg,
                          output_parameters[1], md5_arg,
                          output_parameters[2], base_result.get('category', ''),
                          output_parameters[3], file_type,
                          output_parameters[4], ";".join(incom_list),
                          output_parameters[5], conclusion,
                          output_parameters[6], file_type,
                          output_parameters[0], output_parameters[7],
                          output_parameters[8], output_parameters[9]))
            for index in range(len(incom_list)):
                print("    |{0:<50} |{1:<10} |{2:<30} |{3:<50}".format(incom_list[index], type_src_list[index],
                                                                       name_list[index], version_list[index]))
        return

    def all_file_processing_xarch(self, file_path, mark):
        """
        Classify and process all the files in the detection object,
        and obtain the processing results.
        param file_path: -> string
            The absolute path of the to be verified type file.
        param decompress_file_path: -> string
            Detect the decompression path of the object.
        param zip_so_files:
            Detect all tarballs and so files contained in the directory.
        param mark: -> boolean
            Indicates whether to evaluate only.
        return:
            process_result: -> dictionary
                The detection result of the detection object.
        """
        logger.info('Began {}'.format(os.path.abspath(file_path)), 'java')
        warning_count = 0
        summary_data = [0, 0, 0, 0, 0]  # [x86_64, aarch64, noarch, uncertain, fail]
        recom_result = {}
        base_result = {}

        check_py_java_result = self.check_file_is_py_class_so_zip(file_path)
        if check_py_java_result == 'warning':
            logger.info('Warning3 {}'.format(os.path.abspath(file_path)), 'java')
            warning_count += 1
        elif check_py_java_result == 'other':
            category = self.other_file_processing_xarch(file_path)
            base_result['category'] = category
            if category == 'uncertain':
                summary_data[3] += 1
            elif category == 'noarch':
                summary_data[2] += 1
            elif category == 'x86_64':
                summary_data[0] += 1
            elif category == 'warning':
                warning_count += 1
            else:
                summary_data[2] += 1

        elif check_py_java_result == 'py':
            summary_data[3] += 1
            base_result['category'] = 'uncertain'
        elif check_py_java_result == 'java' or check_py_java_result == 'pom':
            if self.binary_check:
                summary_data[2] += 1
                base_result['category'] = 'noarch'
            else:
                summary_data[3] += 1
                base_result['category'] = 'uncertain'
        else:
            if check_py_java_result == 'zip':
                jar_result = self.check_all_so_file(file_path,
                                                    self.number,
                                                    self.log_type,
                                                    mark,
                                                    self.quiet_mark,
                                                    self.json_log_filename)
                if jar_result.get('failed_zip_list', []):
                    jar_result['category'] = 'failed'
                other_list = jar_result.get('other_list', [])
                # 兼容文件忽略
                incompatible_list, tbv_list = self.classfy_zip_file(other_list, file_path)
                incom_count = len(incompatible_list)
                tbv_count = len(tbv_list)
                uncertain_count = tbv_count
                x86_64_count = incom_count
                aarch64_count = 0
                noarch_count = 0
                failed_count = 0
                uncertain_count += 1 if jar_result.get('category', '') == 'uncertain' else 0
                x86_64_count += 1 if jar_result.get('category', '') == 'x86_64' else 0
                aarch64_count += 1 if jar_result.get('category', '') == 'aarch64' else 0
                noarch_count += 1 if jar_result.get('category', '') == 'noarch' else 0
                failed_count += 1 if jar_result.get('category', '') == 'failed' else 0
                category = 'uncertain'
                if failed_count:
                    category = 'failed'
                elif uncertain_count:
                    category = 'uncertain'
                elif x86_64_count:
                    category = 'x86_64'
                elif aarch64_count:
                    category = 'aarch64'
                elif noarch_count:
                    category = 'noarch'
                else:
                    category = 'uncertain'
                if category == 'uncertain':
                    summary_data[3] += 1
                elif category == 'x86_64':
                    summary_data[0] += 1
                    so_result = jar_result.get('so_result', {})
                    if self.zip_package_pom_path_results:  # 如果有pom文件的解析结果，则去pom文件中匹配依赖的行号
                        so_result = self.match_pom_files_dependent_line_numbers(so_result)
                    so_result = self.recommend_by_jar(so_result)
                    recom_result = self.get_so_recommand_info_in_zip(so_result)
                elif category == 'aarch64':
                    summary_data[1] += 1
                elif category == 'noarch':
                    summary_data[2] += 1
                elif category == 'failed':
                    summary_data[4] += 1
                else:
                    summary_data[2] += 1
                base_result['category'] = category
                if recom_result:
                    base_result.update(recom_result)

            else:
                summary_data[3] += 1
                base_result['category'] = 'uncertain'
        self.inner_path_print(file_path)

        if self.quiet_mark:
            self.check_result_output_xarch(file_path, base_result)
        if not warning_count:
            base_result.update(self.get_file_csv_data(file_path))
        process_result = {
            'summary_data': summary_data,
            'base_result': base_result,
            'warning_count': warning_count
        }

        logger.info('Ended {}'.format(os.path.abspath(file_path)), 'java')
        if not self.quiet_mark:
            self.total_queue.put(1)
        return process_result

    def classfy_zip_file(self, other_list, zip_path):
        incompatible_list = []
        tbv_list = []
        for file_path in other_list:
            type_str, file_path, file_type = self.class_file_type(file_path)

            if type_str in ['pom', 'java']:
                if not self.binary_check:
                    tbv_list.append(file_path)
            elif type_str == 'incom_file':
                if self.binary_check:
                    logger.warning('Warning_ZIP3 {}'.format(os.path.abspath(self.get_zip_path(file_path))), 'java')
                    continue
                else:
                    incompatible_list.append(file_path)
            else:
                tbv_list.append(file_path)
            self.inner_path_print(os.path.abspath(self.get_zip_path(file_path)))
        return incompatible_list, tbv_list

    def get_advice_str(self, minversion, version, repo_url):
        """
        Generate advice string
        param minversion: -> string
            The minversion of recommended jar package.
        param version: -> string
            The version of recommended jar package.
        param repo_url: -> string
            The repo_url of recommended jar package.
        return: -> string or None
            Returns the classification and strings of advice
        """
        if minversion:
            return 0, 'Compatibility version >= {}.'.format(minversion)
        elif version:
            return 1, 'Compatible with the verified version of {}.'.format(version)
        elif repo_url:
            return 2, 'Compatible wtih the verified one in DOWNLOAD column.'
        else:
            return 3, 'Need to recompile on aarch64 with the source.'

    def get_so_recommand_info_in_zip(self, jar_so_result):
        '''
        Obtain recommended information for zip.
        param jar_so_result: -> dict
            Existing recommendation information
        return jar_so_result -> dict
            All so recommended information in zip.
        '''
        incom_list = []
        advice_list = []
        upgrade_list = []
        package_list = []
        version_list = []
        from_list = []
        download_list = []
        action_list = []

        for jar_path in jar_so_result:
            mark, minversion, version, repo_url, line_no = '', '', '', '', ''

            if 'jar_recomand_data' in jar_so_result[jar_path]:
                jar_recomand_result = jar_so_result[jar_path]['jar_recomand_data']
                mark = jar_recomand_result.get('mark', -1)
                minversion = jar_recomand_result.get('minversion', '')
                version = jar_recomand_result.get('version', '')
                repo_url = jar_recomand_result.get('repo_url', '')
                line_no = jar_recomand_result.get('line_no', '')

            for so_path in jar_so_result[jar_path]:
                if so_path == 'jar_recomand_data':
                    continue
                so_result = jar_so_result[jar_path][so_path]
                file_name = get_file_name(so_path)
                jar_name = get_file_name(jar_path)
                relative_path = so_path.split(jar_name)[-1].lstrip('/')
                mark = mark if isinstance(so_result, str) else so_result.get('mark', -1)
                minversion = minversion if isinstance(so_result, str) else so_result.get('minversion', '')
                version = version if isinstance(so_result, str) else so_result.get('version', '')
                repo_url = repo_url if isinstance(so_result, str) else so_result.get('repo_url', '')
                line_no = line_no if isinstance(so_result, str) else so_result.get('line_no', '')

                advice_ret = self.get_advice_str(minversion, version, repo_url)
                action = self.get_action_str_java(advice_ret[0], line_no)
                package = self.get_recommended_keyword(file_name)
                from_str = rc().check_type_src(mark)
                incom_list.append(relative_path)
                advice_list.append(advice_ret[1])
                upgrade_list.append(file_name if version else '')
                package_list.append(package if version else '')
                version_list.append(version if version else '')
                from_list.append(from_str if version else '')
                download_list.append(repo_url if repo_url else '')
                action_list.append(action)

        result = {
            'incom_list': incom_list,
            'advice_list': advice_list,
            'upgrade_list': upgrade_list,
            'package_list': package_list,
            'version_list': version_list,
            'from_list': from_list,
            'download_list': download_list,
            'action_list': action_list
        }
        return result

    def get_so_recommand_info(self, so_path, so_result):
        '''
        Obtain recommended information for individual so files in the directory
        param so_path: -> str
            The absolute path of so file.
        param so_result: -> str
            Existing recommendation information
        return -> dict
            All recommended information
        '''
        incom_list = []
        advice_list = []
        upgrade_list = []
        package_list = []
        version_list = []
        from_list = []
        download_list = []
        action_list = []

        file_name = get_file_name(so_path)
        so_recom_result = so_result.get(so_path, {})
        mark = so_recom_result.get('mark', -1)
        minversion = so_recom_result.get('minversion', '')
        version = so_recom_result.get('version', '')
        repo_url = so_recom_result.get('repo_url', '')
        line_no = so_recom_result.get('line_no', '')
        advice_ret = self.get_advice_str(minversion, version, repo_url)
        action = self.get_action_str_java(advice_ret[0], line_no)
        package = self.get_recommended_keyword(file_name)
        from_str = rc().check_type_src(mark)
        incom_list.append(file_name)
        advice_list.append(advice_ret[1])
        upgrade_list.append(file_name if version else '')
        package_list.append(package if version else '')
        version_list.append(version if version else '')
        from_list.append(from_str if version else '')
        download_list.append(repo_url if repo_url else '')
        action_list.append(action)

        result = {
            'incom_list': incom_list,
            'advice_list': advice_list,
            'upgrade_list': upgrade_list,
            'package_list': package_list,
            'version_list': version_list,
            'from_list': from_list,
            'download_list': download_list,
            'action_list': action_list
        }
        return result

    def get_action_str_java(self, advice_level, line_no=None):
        '''
        Obtain action content
        param advice_level: -> int
        param line_no: -> str
            Action content which include pom line numbers.
        return
            action content
        '''
        action_dict = {
            'N': [
                'Check if it is used in your references and if yes update with DOWNLOAD.',
                'Check if it is used in your references and if yes update with DOWNLOAD.',
                'Check if it is used in your references and if yes update with DOWNLOAD.',
                'Check if it is used in your references and if yes recompiled one on aarch64.']
        }
        action = ''
        if advice_level != '':
            if line_no:
                action = line_no
            else:
                action = action_dict['N'][advice_level]

        return action

    def multi_process_detection(self, param_set):
        """
        Pass in the corresponding parameters to the multi-process method that needs to be executed.
        param param_set: -> set
            The parameter set required by multi-process.
        return:
            res: -> dictionary
                Process execution result.
        """
        try:
            res = self.all_file_processing(param_set[0], param_set[1], param_set[2], param_set[3])
        except Exception:
            print_exc()
        self.queue_paths.put(res)
        return res

    def determine_all_compatibility(self, so_result, so_file_list):
        incompatible_dict = {}
        new_so_result = copy.deepcopy(so_result)
        compatible_so_file = []
        for keys, values in so_result.items():
            for sub_key, sub_value in values.items():
                if type(sub_value) is int:
                    compatible_so_file.append(sub_key)
        # 1. 找到兼容的so文件,循环兼容的so文件，去匹配不兼容so文件，判断是否为同结构so文件，如果是则默认其兼容
        for keys, values in so_result.items():
            for sub_key, sub_value in values.items():
                for so_file in compatible_so_file:
                    # 2. 以第一个数字切割去除版本信息获取so文件有用名称
                    so_name = re.split(r"\d{1}", os.path.split(so_file)[-1])[0]
                    if type(sub_value) is not int:
                        incompatible_so_file = re.split(r"\d{1}", os.path.split(sub_key)[-1])[0]
                        os_directory_hierarchy = so_file.count("/")
                        incompatible_directory_hierarchy = sub_key.count("/")
                        # 判断目录层级是否大于2
                        if so_name == incompatible_so_file:  # 切割后的名称如果相同则继续判断目录结构
                            if abs(incompatible_directory_hierarchy - os_directory_hierarchy) <= 1:
                                common_path = os.path.commonpath([sub_key, so_file])
                                if common_path == os.sep:
                                    incompatible_path = sub_key.replace(common_path, '', 0).split('/')[1]
                                else:
                                    incompatible_path = sub_key.replace(common_path, '').split('/')[1]

                                tag = path_intersection(incompatible_path, path_keyword)
                                if tag:  # 如果每一个层级目录都在白名单中则默认兼容
                                    if incompatible_dict.get(keys):
                                        incompatible_dict[keys].update({sub_key: sub_value})
                                    else:
                                        incompatible_dict[keys] = {sub_key: sub_value}
                                    if sub_key in so_file_list:
                                        so_file_list.remove(sub_key)
                                    if sub_key in new_so_result.get(keys, {}):
                                        del new_so_result.get(keys)[sub_key]
                                else:
                                    tag = path_intersection(os.path.split(common_path)[-1], path_keyword)
                                    if tag:
                                        if incompatible_dict.get(keys):
                                            incompatible_dict[keys].update({sub_key: sub_value})
                                        else:
                                            incompatible_dict[keys] = {sub_key: sub_value}
                                        if sub_key in so_file_list:
                                            so_file_list.remove(sub_key)
                                        if sub_key in new_so_result.get(keys, {}):
                                            del new_so_result.get(keys)[sub_key]

        rewrite_so_result = {}
        for key, value in new_so_result.items():
            if value:
                rewrite_so_result[key] = value

        if incompatible_dict:
            incompatible_dict = self.recommend_by_jar(incompatible_dict)
            for file, so_dict in incompatible_dict.items():
                result_dict = self.class_value_output({file: so_dict}, file)
                for key, value in result_dict.items():
                    if value.isdigit():
                        category = "WJ" + str(value)
                    else:
                        category = value.replace("J", "WJ")
                    incompatible = incompatible_dict.get(key)
                    for warning_path in incompatible:
                        if self.warning_check:
                            self.warning_info_output(warning_path, category)
                        content = "Warning1 {}".format(os.path.abspath(self.get_zip_path(warning_path)))
                        logger.warning(content, 'java')
                        self.so_warning_count += 1
        return rewrite_so_result, so_file_list

    def check_jar_so_files(self, zip_so_files, mark, so_test_result, so_final_res_new):
        """
        When the detection object is a directory,
        check whether the collected compressed files and so files are compatible.
        param zip_so_files:
            Detect all tarballs and so files contained in the directory.
        param mark: -> boolean
            Indicates whether to evaluate only.
        return:
            check_jar_so_result: -> dictionary
                The absolute path of the directory formed after the compressed package is decompressed.
                And so file detection results.
                And Summary information about the number of all detected files.
        """
        # 下面三个变量是对检测对象中包含的jar、so、其他文件的数量统计，为输出json格式时需要
        jar_arg = 0
        so_arg = 0
        other_arg = 0

        # 屏幕打印输出、监控日志以及标准化输出中summary详情【兼容、不兼容、to be verified、failed】
        is_no_to_be_verified = [0, 0, 0, 0]
        decompress_file_path = []
        parameter_set = []
        so_result_dic = {}
        all_child_file = {}
        # 使用多进程，对所有的文件进行检测
        for file_path in zip_so_files:  # 遍历文件列表，形成set类型的入参，方便进行多进程处理
            parameter_set.append((file_path, decompress_file_path, zip_so_files, mark))

        summary_list = self.multi_process_execution(self.multi_process_detection, None,
                                                    self.processes_number, parameter_set)
        if summary_list:  # 对检测结果进行处理
            for summary in summary_list:
                summary_to_be_verified = summary.get('is_no_to_be_verified', [0, 0, 0, 0])
                summary_decompress_file_path = summary.get('decompress_file_path', [])
                summary_so_result_dic = summary.get('so_result_dic', {})
                summary_child_tbv_file = summary.get("child_tbv_file", '')
                summary_jar_arg = summary.get('jar_arg', 0)
                summary_so_arg = summary.get('so_arg', 0)
                summary_other_arg = summary.get('other_arg', 0)
                summary_non_test_file = summary.get('non_test_file', [])
                summary_non_test_file_results = summary.get('non_test_file_results', []) \
                    if summary.get('non_test_file_results', []) else []
                summary_compressed_to_python = summary.get('compressed_to_python', [])
                summary_compatible_results = summary.get('compatible_results', [])
                summary_incompatible_results = summary.get('incompatible_results', [])
                summary_failed_results = summary.get('failed_results', [])
                summary_zip_unzip_path = summary.get('zip_unzip_path', {})
                summary_pom_line_no_info = summary.get('pom_line_no_info', {})
                mf_path_dict = summary.get('mf_path_dict', {})
                zip_node_list = summary.get('zip_node_list', [])

                is_no_to_be_verified = [x + y for x, y in zip(is_no_to_be_verified, summary_to_be_verified)]
                decompress_file_path += summary_decompress_file_path
                if not (summary_to_be_verified[2] == sum(summary_to_be_verified) or
                        summary_to_be_verified[3] == sum(summary_to_be_verified)):
                    so_result_dic.update(summary_so_result_dic)
                if self.class_value == "cs":
                    so_result_dic.update(summary_so_result_dic)
                jar_arg += summary_jar_arg
                so_arg += summary_so_arg
                other_arg += summary_other_arg
                self.other_warning_count += summary.get('warning_count', 0)
                self.non_test_file += summary_non_test_file
                self.non_test_file_results += summary_non_test_file_results
                self.compressed_to_python += summary_compressed_to_python
                self.compatible_results += summary_compatible_results
                self.incompatible_results += summary_incompatible_results
                self.failed_results += summary_failed_results
                self.zip_unzip_path.update(summary_zip_unzip_path)
                self.zip_package_pom_path_results.update(summary_pom_line_no_info)
                self.mf_path_dict.update(mf_path_dict)
                self.zip_node_list += zip_node_list
                all_child_file.update(summary_child_tbv_file)
                del summary_compatible_results, summary_incompatible_results, summary_zip_unzip_path

        sub_file_count_dic = {
            "jar": jar_arg,
            "so": so_arg,
            "other": other_arg
        }
        if so_final_res_new:
            for key in so_final_res_new:
                if type(so_final_res_new[key][key]) is dict:
                    is_no_to_be_verified[1] += 1
                else:
                    is_no_to_be_verified[0] += 1
            so_result_dic.update(so_final_res_new)

        if not decompress_file_path:
            decompress_file_path = list(so_result_dic.keys())

        check_jar_so_result = {
            "decompress_file_path": decompress_file_path if decompress_file_path else 1,
            "so_result": so_result_dic if so_test_result else 1,
            "sub_file_count": sub_file_count_dic,
            "is_to_be_verified": is_no_to_be_verified,
            "all_child_file": all_child_file,
        }
        return check_jar_so_result

    def check_jar_so_files_xarch(self, zip_so_files, mark, so_list, so_final_res, so_file_list_new, summary_data):
        """
        Detect all other files and summarize the results when --class xarch.
        param zip_so_files:
            Detect all tarballs and so files contained in the directory.
        param mark: -> boolean
            Indicates whether to evaluate only.
        param so_list: -> list
            so files list.
        param so_final_res: -> dict
            Recommended results for all so files.
        param so_file_list_new: -> so_file_list_new
            The result obtained by filtering the so file through warning based on the recommended results
        return summary_data -> list
            Summary of all file detection results
        """
        temp_result = copy.deepcopy(so_final_res)
        recom_result = self.recommend_by_jar(temp_result)
        for so_path in so_file_list_new:
            is_compatiable = so_final_res.get(so_path, {}).get(so_path, 'uncertain')
            base_result = self.get_file_csv_data(so_path)
            base_result['category'] = is_compatiable
            base_result.update(self.get_so_recommand_info(so_path, recom_result))
            self.summary_data.append(base_result)

        # 遍历文件列表，形成set类型的入参，方便进行多进程处理
        parameter_set = [(file_path, mark) for file_path in zip_so_files if file_path not in so_list]
        tasks = []
        with ProcessPoolExecutor(self.processes_number) as t_xarch:
            for param_set in parameter_set:
                tasks.append(t_xarch.submit(self.all_file_processing_xarch, param_set[0], param_set[1]))
            # 收集结果
            for task in as_completed(tasks):
                summary = task.result()
                multi_data = summary.get('summary_data', [0, 0, 0, 0, 0])
                summary_data[0] += multi_data[0]
                summary_data[1] += multi_data[1]
                summary_data[2] += multi_data[2]
                summary_data[3] += multi_data[3]
                summary_data[4] += multi_data[4]
                self.so_warning_count += summary.get('warning_count', 0)
                self.summary_data.append(summary.get('base_result', {}))

        return summary_data

    def get_file_csv_data(self, file_path):
        project = os.path.split(file_path[:file_path.rfind(os.path.sep)])[-1]
        location = os.path.split(file_path)[0]
        file_type = get_file_type(file_path)[1]
        try:
            md5 = get_file_md5(file_path)
            file_path.encode('utf-8')
            file_name = get_file_name(file_path)
        except Exception:
            file_name = file_path.encode('utf-8', 'ignore').decode('utf-8', 'ignore') + '?'
            md5 = 'E0000000000000000000000000000001'
        result = {
            'project': project,
            'location': location,
            'file_name': file_name,
            'file_type': file_type,
            'file_md5': md5,
            'incombile': file_name,
        }

        return result

    def collect_compressed_so_file(self, dir_path):
        """
        Collect all compressed packages and so files contained in the detection object.
        param dir_path:
            The absolute path of the detection object.
        return: -> list
            All compressed files and so files included in the detection object.
        """
        all_file_path = []
        if dir_path:
            for root, dirs, files in os.walk(dir_path):
                if self.class_value == 'cs':
                    dirs[:] = [d for d in dirs if not self.skip_non_detection_dir(root, d)]
                for file in files:
                    file_path = os.path.join(root, file)
                    self.check_file_type(file_path)
                    all_file_path.append(file_path)
        return all_file_path

    def skip_non_detection_dir(self, project, detection_dir, real_path=None):
        """
        Skip default directory detection for Mac, Windows, etc
        :param project: parent dir
        :param detection_dir: directory for detection
        :return:
        """
        if detection_dir.lower() in constant.ignored_list:
            dir_path = os.path.join(project, detection_dir)
            if real_path:
                dir_path = dir_path.replace(self.ep_temp_files, os.path.split(real_path)[0])
            logger.info('Warning4 {}.'.format(dir_path), 'java')
            return True
        return False

    def define_log_save_filename(self, specify_log_name, log_type):
        """
        Defines the filename of the log output before evaluation.
        param specify_log_name: -> None or string
            The file name to save the log specified on the command line.
        return: -> string
            The defined file name for saving the log.
        """
        if not log_type:
            log_type = "log"
        if not specify_log_name:  # 当命令行没有指定结果文件名时
            if (self.class_value and
                    log_type == 'csv' and
                    not self.engine):
                result_log_filename = "{}_{}".format(self.result_log_file, self.time_str)
            else:
                result_log_filename = "{}_{}_java".format(self.result_log_file, self.time_str)

        else:  # 当命令行指定了结果文件名时
            result_log_filename = os.path.abspath(os.path.join(java_current_path, specify_log_name))
            if result_log_filename == '/' + specify_log_name and '/' not in specify_log_name:
                dir_path = java_current_path
                specify_name = specify_log_name.lstrip('/')
            else:
                dir_path = result_log_filename[:result_log_filename.rfind('/')]
                specify_name = result_log_filename.split('/')[-1]

            if not os.path.exists(dir_path):
                os.makedirs(dir_path)

            if (self.class_value and
                    log_type == 'csv' and
                    not self.engine):
                if os.path.exists(result_log_filename + '.csv'):
                    result_log_filename = "{}_{}".format(result_log_filename, self.time_str)
                open(result_log_filename + constant.suffix_dict[self.log_type], 'a').close()
                return result_log_filename

            if not specify_name:
                result_log_filename = "{}/result_{}_java".format(result_log_filename, self.time_str)
                open(result_log_filename + constant.suffix_dict[self.log_type], 'a').close()
                return result_log_filename

            if not self.engine:
                if log_type == 'txt':
                    json_log_filename = "{}_java.{}".format(result_log_filename, 'log')
                else:
                    json_log_filename = "{}_java.{}".format(result_log_filename, log_type)

                if os.path.exists(json_log_filename.rstrip('/')):
                    result_log_filename = "{}_{}_java".format(result_log_filename, self.time_str)
                else:
                    result_log_filename = "{}_java".format(result_log_filename)
            else:
                if log_type == 'txt':
                    json_log_filename = "{}.{}".format(result_log_filename, 'log')
                else:
                    json_log_filename = "{}.{}".format(result_log_filename, log_type)

                if os.path.exists(json_log_filename.rstrip('/')):
                    result_log_filename = "{}_{}".format(result_log_filename, self.time_str)
                else:
                    result_log_filename = "{}".format(result_log_filename)
        open(result_log_filename + constant.suffix_dict[self.log_type], 'a').close()
        return result_log_filename

    def package_failed_file_organization(self, package_path, failed_file_list):
        """
        Collect files that failed to decompress.
        param package_path: -> string
            Path to detect objects.
        param failed_file_list: -> list
            All file sets that failed to unpack.
        return: -> list
            A list of collected files that fail to decompress.
        """
        fail_files = []

        for package in package_path:
            for failed_file in failed_file_list:
                if package in failed_file:
                    fail_files.append(failed_file)

        return list(set(fail_files))

    def check_type_src(self, type_mark):
        """
        Get the so package search source.
        param type_mark: -> number
            Search method identification of so package.
        return: -> string
            maven_arg: It comes from Maven warehouse.
            github_arg: It comes from github warehouse.
            "": No source.
        """
        maven_arg = "Maven"
        github_arg = "Github"
        org_arg = "Org"
        ali_arg = 'Alibaba'
        huawei_arg = 'Huawei'

        if type_mark == 0:
            return maven_arg

        elif type_mark == 1:
            return github_arg

        elif type_mark == 2:
            return org_arg

        elif type_mark == 3:
            return ali_arg

        elif type_mark == 4:
            return huawei_arg

        else:
            return ""

    def get_current_version(self, so_final_result):
        current_version_dict = dict()
        for jar_or_incomfile, recommand_dict in so_final_result.items():
            current_version = None
            jar_or_incomfile = os.path.abspath(jar_or_incomfile)
            file_name = get_file_name(jar_or_incomfile)
            file_suffix = file_name.split('.')[-1]
            zip_suffix_list = constant.zip_arg + ['jar']
            if file_suffix in zip_suffix_list:
                current_version = get_obj_version(file_name, 'zip')
                if current_version is None:
                    # 补充MANIFEST.MF 文件路径获取
                    mf_path = self.mf_path_dict.get(jar_or_incomfile, "")
                    if mf_path:
                        current_version = get_version_in_mf(mf_path)
                for so_file in recommand_dict:
                    so_file = os.path.abspath(so_file)
                    so_file_name = get_file_name(so_file)
                    so_current_version = get_obj_version(so_file_name, 'so')
                    if not so_current_version and file_name.endswith('jar'):
                        current_version_dict[so_file] = current_version
            else:
                current_version = get_obj_version(file_name, 'so')
                current_version_dict[jar_or_incomfile] = current_version
        return current_version_dict

    def get_incompatible_so_document(self, so_final_result, all_child_file={}):
        """
        Get incompatible so files.
        param so_final_result: -> dictionary
            Final test results of so files.
        return: -> dictionary
            The final processing result of so detection results.
        """
        mark_arg = 'mark'
        version_arg = 'version'
        location_arg = 'line_no'
        repo_url_arg = 'repo_url'
        minversion_arg = 'minversion'
        jar_recomand_arg = 'jar_recomand_data'

        so_file_list = []
        so_mark_list = []
        so_version_list = []
        location_list = []
        repo_url_list = []
        minversion_list = []
        info_mark_list = []
        all_child_file_list = []
        current_version_dict = {}

        document_key = list(so_final_result.keys())

        if document_key:
            for key in document_key:
                so_result = so_final_result[key]
                so_key = list(so_result.keys())
                all_child_file_list.append(all_child_file.get(key, ''))
                if so_key and \
                        (mark_arg not in so_key and
                         version_arg not in so_key):
                    if jar_recomand_arg not in so_key:
                        for key0 in so_key:
                            if (type(so_result[key0]) is not int and
                                    key0 not in so_file_list):
                                so_file_list.append(key0)
                                so_mark_list.append(so_result[key0][mark_arg])
                                version = so_result[key0][version_arg]
                                so_version_list.append(version)
                                try:
                                    repo_url = so_result[key0][repo_url_arg]
                                except Exception:
                                    repo_url = ''
                                repo_url_list.append(repo_url if repo_url else '')

                                try:
                                    minversion = so_result[key0][minversion_arg]
                                except Exception:
                                    minversion = ''

                                info_mark, minversion_info = no().get_advice_str(minversion, version,
                                                                                 repo_url)  # advice
                                info_mark_list.append(info_mark)
                                if minversion_info:
                                    minversion_list.append(minversion_info)
                                else:
                                    minversion_list.append('')
                    else:
                        for key1 in so_key:
                            if (type(so_result[key1]) is not int and
                                    key1 not in so_file_list):
                                if key1 != jar_recomand_arg:
                                    so_file_list.append(key1)
                                    so_mark_list.append(so_result[jar_recomand_arg][mark_arg])
                                    try:
                                        repo_url = so_result[jar_recomand_arg][repo_url_arg]
                                    except Exception:
                                        repo_url = ''
                                    repo_url_list.append(repo_url if repo_url else '')
                                    version = so_result[jar_recomand_arg][version_arg]
                                    so_version_list.append("{}:{}".format('jar version', version))
                                    try:
                                        minversion = so_result[jar_recomand_arg][minversion_arg]
                                    except Exception:
                                        minversion = ''

                                    info_mark, minversion_info = no().get_advice_str(minversion, version, repo_url)
                                    info_mark_list.append(info_mark)
                                    if minversion_info:
                                        minversion_list.append(minversion_info)
                                    else:
                                        minversion_list.append('')

                    for so_path in so_key:
                        if (so_path != jar_recomand_arg and
                                type(so_result[so_path]) is not int):
                            try:
                                line_no = so_result[so_path][location_arg]
                                new_line_info = self.get_action_info(line_no, location_list, info_mark_list)
                            except Exception:
                                new_line_info = 'Check if it is used in your references and ' \
                                                'if yes update with DOWNLOAD.'
                            location_list.append(new_line_info)

            current_version_dict = self.get_current_version(so_final_result)

        result = {"so_file_list": so_file_list,
                  "so_mark_list": so_mark_list,
                  "so_version_list": so_version_list,
                  "location_list": location_list,
                  "repo_url_list": repo_url_list,
                  "minversion_list": minversion_list,
                  "current_version_dict": current_version_dict,
                  "all_child_file_list": all_child_file_list}

        return result

    def get_action_info(self, line_info, line_list, minversion_info_mark):
        """
        According to the pom location information matched by dependencies,
        combined with advice, update the pom location description.
        param line_info: ->string
            Depends on the location information in the pom file.
        param line_list: ->list
            The location information of the updated dependencies in the pom file.
        param minversion_info_mark: ->list
            The collected advice information set.
        return: -> string
            The new dependency information description that has been processed.
        """
        line_list_len = len(line_list)
        if not line_info:
            new_line_info = "Check if it is used in your references and if yes recompiled one on aarch64."
        else:
            minversion_info = minversion_info_mark[line_list_len]
            pom_info = line_info.split(' POM ')[1]
            if minversion_info in [0, 1]:
                new_line_info = line_info
            elif minversion_info == 2:
                new_line_info = "Update the file depended by POM [{}] with the DOWNLOAD.".format(pom_info)
            else:
                new_line_info = "Update the file depended by POM [{}] with the recompiled one on aarch64." \
                    .format(pom_info)
        return new_line_info

    def get_recommended_keyword(self, so_name):
        mysql = MySqlite(self.db_path)
        so_name = so_name.split("/")[-1]
        so_name = so_name_to_search(so_name)
        if self.class_value == "udf":
            sql_so = "SELECT lib FROM so_el7 WHERE name like ?;"
        else:
            sql_so = "SELECT lib FROM so_el8 WHERE name like ?;"
        so_name_fuzzy = "{}%".format(so_name)
        so_info = mysql.search_one(sql_so, (so_name_fuzzy,))
        if so_info:
            file_name = so_info[0]
        else:
            lib_arg = "lib"
            judgment_field = ["_linux", "_x86", "_amd"]

            so_name = so_name.split(".so")[0]
            if so_name[:3] == lib_arg:
                file_name = so_name[3:]
            else:
                file_name = so_name

            for field in judgment_field:
                if field in file_name:
                    return file_name.split(field)[0]
        return file_name

    def so_result_process(self, result, so_list):
        """
        Process the evaluation results and obtain the recommended identification and
         version corresponding to the incompatible so file.
        param result: -> dictionary
            Recommended results for so files.
        param so_list: -> list
            List of incompatible so files.
        return: -> dictionary
            A dictionary formed from processed data.
        """
        arg_list = ["mark_list", "version_list", "pak_arg_list",
                    "so_mark_list", "so_version_list"]
        mark_list = []
        version_list = []
        pak_arg_list = []

        data_dic = {}
        for index in range(len(result[arg_list[3]])):
            source_type = self.check_type_src(result[arg_list[3]][index])
            mark_list.append(source_type)
            version_list.append(str(result[arg_list[4]][index]))

        for index0 in range(len(so_list)):
            if mark_list[index0]:
                pak_arg = self.get_recommended_keyword(so_list[index0])
                pak_arg_list.append(pak_arg)

            else:
                pak_arg_list.append("")

        data_dic[arg_list[0]] = mark_list
        data_dic[arg_list[1]] = version_list
        data_dic[arg_list[2]] = pak_arg_list

        return data_dic

    def detection_result_stdout(self, **kwargs):
        """
        Printout of detection results for packages or directories.
        param kwargs: -> dictionary
            Print out the required parameter set.
        return: -> None
        """
        incompatible_flag = kwargs["incompatible_flag"]
        package_name = kwargs["package_name"]
        package_path = kwargs.get("package_path", 0)
        package_hash = kwargs["package_hash"]
        package_type = kwargs["package_type"]
        output_terms = kwargs["output_terms"]
        output_data = kwargs["output_data"]
        result_dict = kwargs.get("result_dict", {})

        print(self.isolation)

        if incompatible_flag:
            incompatible_pkg = kwargs["incompatible_pkg"]
            conclusion_arg = kwargs["conclusion_arg"]

            incompatible_so_list = kwargs["incompatible_so_list"]
            mark_list = kwargs["mark_list"]
            pak_arg_list = kwargs["pak_arg_list"]
            version_list = kwargs["version_list"]

            if self.class_value:
                print("{0:<15}: {1:<20} \n"
                      "{2:<15}: {3:<20} \n"
                      "{4:<15}: {5:<20} \n"
                      "{18:<15}: {19:<20} \n"
                      "{6:<15}: {7:<20} \n"
                      "{8:<15}: {9:<20} \n"
                      "{10:<15}: {11:<20} \n"
                      "{12:<15}: {13:<20} \n"
                      "    |{14:<60} |{15:<10} |{16:<30} |{17:<50} "
                      .format(output_terms[0], package_name,
                              output_terms[1], package_hash,
                              output_terms[2], output_data[0],
                              output_terms[3], package_type,
                              output_terms[4], incompatible_pkg,
                              output_terms[5], conclusion_arg,
                              output_terms[6], package_type,
                              output_terms[7], output_terms[8],
                              output_terms[9], output_terms[10],
                              'CLASS', result_dict.get(package_path, "")
                              ))
            else:
                print("{0:<15}: {1:<20} \n"
                      "{2:<15}: {3:<20} \n"
                      "{4:<15}: {5:<20} \n"
                      "{6:<15}: {7:<20} \n"
                      "{8:<15}: {9:<20} \n"
                      "{10:<15}: {11:<20} \n"
                      "{12:<15}: {13:<20} \n"
                      "    |{14:<60} |{15:<10} |{16:<30} |{17:<50} "
                      .format(output_terms[0], package_name,
                              output_terms[1], package_hash,
                              output_terms[2], output_data[0],
                              output_terms[3], package_type,
                              output_terms[4], incompatible_pkg,
                              output_terms[5], conclusion_arg,
                              output_terms[6], package_type,
                              output_terms[7], output_terms[8],
                              output_terms[9], output_terms[10]
                              ))

            for index in range(len(incompatible_so_list)):
                print("    |{0:<60} |{1:<10} |{2:<30} |{3:<50} "
                      .format(incompatible_so_list[index],
                              mark_list[index],
                              pak_arg_list[index] if len(pak_arg_list) > index else "",
                              version_list[index] if len(version_list) > index else ""))

        else:
            if self.class_value:
                print("{0:<15}: {1:<20} \n"
                      "{2:<15}: {3:<20} \n"
                      "{4:<15}: {5:<20} \n"
                      "{8:<15}: {9:<20} \n"
                      "{6:<15}: {7:<20} \n".format(output_terms[0], package_name,
                                                   output_terms[1], package_hash,
                                                   output_terms[2], output_data[1],
                                                   output_terms[3], package_type,
                                                   'CLASS', 1))
            else:
                print("{0:<15}: {1:<20} \n"
                      "{2:<15}: {3:<20} \n"
                      "{4:<15}: {5:<20} \n"
                      "{6:<15}: {7:<20} \n".format(output_terms[0], package_name,
                                                   output_terms[1], package_hash,
                                                   output_terms[2], output_data[1],
                                                   output_terms[3], package_type))

        return

    def result_save_fail_format(self, **kwargs):
        """
        Save the error results in the package or directory detection results
        to a temporary file in csv format.
        param kwargs: -> dictionary
            Print out the required parameter set.
        return: -> None
        """
        package_name = kwargs["package_name"]
        package_path = kwargs["package_path"]
        package_hash = kwargs["package_hash"]
        package_type = kwargs["package_type"]
        not_arm_count = kwargs["not_arm_count"]
        failed_path_list = kwargs.get("failed_path", [])
        output_arg_list = ["Decompressible", "Issues", "decompression failed",
                           '"unzip" is needed to decompress and check']

        if not_arm_count == -1 or not_arm_count == -2:
            quiet_mark = kwargs["quiet_mark"]
            if quiet_mark:
                print(self.isolation)
                print("{} File decompression failed. Please check and re execute.\n".format(package_name))

            package_path_slice = package_path.split('/')
            project = package_path_slice[-2]
            new_package_path = '/'.join(package_path_slice[:-1])
            if self.class_value:
                csv_data = [project, package_name, 'NULL', package_type,
                            'NULL', 'NULL', 'NULL', 'NULL', 'NULL', 'NULL']
                if self.log_type == 'csv':
                    csv_data.append('0')
                else:
                    if not_arm_count == -2:
                        csv_data = [project, new_package_path, package_name, package_hash, 'NULL', package_type,
                                    output_arg_list[3], '', '', '', '', '', '', '']
                    else:
                        csv_data = [project, new_package_path, package_name, package_hash, 'NULL', package_type,
                                    output_arg_list[2], '', '', '', '', '', '', '']
            else:
                if not_arm_count == -2:
                    csv_data = [project, new_package_path, package_name, package_hash, 'NULL', package_type,
                                'NULL', 'NULL', 'NULL', 'NULL', 'NULL', 'NULL', 'NULL', 'NULL',
                                '\n'.join(failed_path_list)]
                else:
                    csv_data = [project, new_package_path, package_name, package_hash, 'NULL', package_type,
                                'NULL', 'NULL', 'NULL', 'NULL', 'NULL', 'NULL', 'NULL', 'NULL',
                                '\n'.join(failed_path_list)]

            self.failed_results.append(csv_data)

        return

    def check_category(self, so_pkg_list, incompatible_pkg):
        """
        Check whether the category has a value, and reassign it according
        to the condition if there is no value.
        param so_pkg_list: -> string
            All so that are not compatible.
        param incompatible_pkg: -> string
            All incompatible so that match the version.
        return: -> string
            The processed category.
        """
        so_list = so_pkg_list.split(':')
        if '' in so_list:
            for index in range(so_list.count('')):
                so_list.remove('')
        incompatible_list = list(set(incompatible_pkg.split('\n')))
        if '' in incompatible_list:
            for index in range(incompatible_list.count('')):
                incompatible_list.remove('')
        if len(so_list) == len(incompatible_list):
            category_arg = '2'
        else:
            category_arg = '5'
        return category_arg

    def result_save_csv_format(self, **kwargs):
        """
        Save the detection results of packages or directories to a temporary file in csv format.
        param kwargs: -> dictionary
            Print out the required parameter set.
        return: -> None
        """
        csv_arg = "csv"
        flag = kwargs["flag"]
        incompatible_flag = kwargs["incompatible_flag"]
        package_name = kwargs["package_name"]
        package_path = kwargs["package_path"]
        package_hash = kwargs["package_hash"]
        package_type = kwargs["package_type"]
        result_dict = kwargs.get("result_dict", {})
        all_child_file = "".join(kwargs.get("all_child_file", ""))

        package_path_slice = package_path.split('/')
        project = package_path_slice[-2]
        location = "/".join(package_path_slice[:len(package_path_slice) - 1])

        if incompatible_flag:
            incompatible_pkg = kwargs["incompatible_pkg"]
            mark_list = kwargs["mark_list"]
            pak_arg_list = kwargs["pak_arg_list"]
            version_list = kwargs["version_list"]
            so_pkg_list = kwargs["so_pkg_list"]
            line_no = kwargs["line_no"]
            repo_url = kwargs["repo_url"]
            minversion = kwargs["minversion"]

            version = "\n".join(version_list)
            source_type = "\n".join(mark_list)
            so_name_str = "\n".join(pak_arg_list)

            if (self.class_value and
                    self.log_type == csv_arg):
                category_data = result_dict.get(package_path, "")
                if not category_data:
                    category_data = self.check_category(so_pkg_list, incompatible_pkg)
            else:
                category_data = result_dict.get(package_path, "J0")

            if (self.class_value and
                    self.log_type == csv_arg):
                csv_data = [location, package_hash, project, package_name, category_data, package_type, so_pkg_list,
                            package_type, incompatible_pkg, so_name_str, version + '\t', line_no, '1']
            else:
                csv_data = [project, location, package_name, package_hash, category_data,
                            package_type, so_pkg_list, minversion, incompatible_pkg,
                            so_name_str, version + '\t', source_type, repo_url, line_no, all_child_file]
            self.incompatible_results.append(csv_data)

        elif not incompatible_flag and flag:
            if self.class_value and self.log_type == csv_arg:
                csv_data = [location, package_hash, project, package_name, "1", package_type,
                            "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", '1']
            else:
                csv_data = [project, location, package_name, package_hash, "1", package_type]

            if csv_data not in self.compatible_results and package_type != 'director':
                self.compatible_results.append(csv_data)
        return

    def csv_format_long_characters_intercepted_save(self, csv_data):
        """
        The output of csv data that is too long is cut off.
        param csv_data: -> list
            The csv data to be saved.
        return: -> Boolean
            True: True indicates that the csv log record is completed.
            False: False indicates that the csv log is not recorded.
        """
        try:
            project = csv_data[0]
            location = csv_data[1]
            file_name = csv_data[2]
            file_md5 = csv_data[3]
            category = csv_data[4]
            file_type = csv_data[5]
            incom = csv_data[6] if len(csv_data) > 6 else ''
            advice = csv_data[7] if len(csv_data) > 7 else ''
            upgrade = csv_data[8] if len(csv_data) > 8 else ''
            package = csv_data[9] if len(csv_data) > 9 else ''
            version = csv_data[10] if len(csv_data) > 10 else ''
            from_str = csv_data[11] if len(csv_data) > 11 else ''
            download = csv_data[12] if len(csv_data) > 12 else ''
            action = csv_data[13] if len(csv_data) > 13 else ''
            tbv_path = csv_data[14] if len(csv_data) > 14 else ''

            if self.class_value:
                cut_nu = len(package.rstrip('\n').split('\n')) // 100 + 1
                # 防止单元格超限30000
                incom_list = self.cut_field_xarch(category.rstrip('\n'), cut_nu)
                name_so_list = self.cut_field_xarch(incom.rstrip('\n'), cut_nu)
                version_list = self.cut_field_xarch(upgrade.rstrip('\n'), cut_nu)
                package_list = self.cut_field_xarch(advice.rstrip('\n'), cut_nu)
                action_list = self.cut_field_xarch(package.rstrip('\n'), cut_nu)
                for csv_data in zip_longest([project], [location], [file_name], [file_md5], incom_list, [file_type],
                                            name_so_list, package_list, version_list, action_list, [version],
                                            fillvalue='NULL'):
                    if not any(csv_data):
                        continue
                    temp_data = list(csv_data)
                    temp_data[0] = project
                    temp_data[1] = file_name
                    temp_data[2] = category
                    temp_data[3] = file_type
                    yield temp_data
            else:
                cut_nu = len(action.rstrip('\n').split('\n')) // 100 + 1 if len(action.rstrip('\n').split('\n')) >= len(
                    tbv_path.rstrip('\n').split('\n')) else len(tbv_path.rstrip('\n').split('\n')) // 100 + 1
                incom_list = self.cut_field_xarch(incom.rstrip('\n'), cut_nu)
                advice_list = self.cut_field_xarch(advice.rstrip('\n'), cut_nu)
                upgrade_list = self.cut_field_xarch(upgrade.rstrip('\n'), cut_nu)
                package_list = self.cut_field_xarch(package.rstrip('\n'), cut_nu)
                version_list = self.cut_field_xarch(version.rstrip('\n'), cut_nu)
                from_list = self.cut_field_xarch(from_str.rstrip('\n'), cut_nu)
                download_list = self.cut_field_xarch(download.rstrip('\n'), cut_nu)
                action_list = self.cut_field_xarch(action.rstrip('\n'), cut_nu)
                tbv_path_list = self.cut_field_xarch(tbv_path.rstrip('\n'), cut_nu)
                for csv_data in zip_longest([project], [location], [file_name], [file_md5], [category],
                                            [file_type], incom_list, advice_list, upgrade_list, package_list,
                                            version_list, from_list, download_list, action_list, tbv_path_list,
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
                    yield temp_data
            return True
        except Exception:
            return False

    def csv_format_long_characters_intercepted_save_udf(self, csv_data):
        """
        The output of csv data that is too long is cut off.
        param csv_data: -> list
            The csv data to be saved.
        return: -> Boolean
            True: True indicates that the csv log record is completed.
            False: False indicates that the csv log is not recorded.
        """
        project = csv_data[0]
        file_name = csv_data[1]
        category = csv_data[2]
        file_type = csv_data[3]
        incom = csv_data[4] if len(csv_data) > 4 else ''
        upgrade = csv_data[5] if len(csv_data) > 5 else ''
        name_so = csv_data[6] if len(csv_data) > 6 else ''
        package = csv_data[7] if len(csv_data) > 7 else ''
        version = csv_data[8] if len(csv_data) > 8 else ''
        action = csv_data[9] if len(csv_data) > 9 else ''
        status = csv_data[10] if len(csv_data) > 9 else '0'

        line_nu = len(action.rstrip('\n').split('\n'))
        cut_nu = line_nu // 100 + (1 if line_nu % 100 > 0 else 0)
        # 防止单元格超限30000
        incom_list = self.cut_field(incom.rstrip('\n'), cut_nu)
        name_so_list = self.cut_field_xarch(name_so.rstrip('\n'), cut_nu)
        version_list = self.cut_field_xarch(version.rstrip('\n'), cut_nu)
        package_list = self.cut_field_xarch(package.rstrip('\n'), cut_nu)
        action_list = self.cut_field_xarch(package.rstrip('\n'), cut_nu)
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
            yield temp_data

    def json_issue_error_info_write(self, **kwargs):
        """
        Issue and error details are written to the log in json format.
        param kwargs: -> dictionary
            various parameters required.
        return: -> list
            advice_list:
                A list containing issue and error details;
        """
        arg_list = kwargs["arg_list"]
        check_point = kwargs["check_point"]
        other_keys = kwargs["other_keys"]
        issue_keys = kwargs["issue_keys"]
        advice_keys = kwargs["advice_keys"]
        des_arg = kwargs["des_arg"]
        type_arg = kwargs["type_arg"]

        advice_details = kwargs["advice_details"]
        output_terms = kwargs["output_terms"]
        advice_list = kwargs["advice_list"]
        mark_list = kwargs["mark_list"]
        pak_arg_list = kwargs["pak_arg_list"]
        version_list = kwargs["version_list"]
        download_list = kwargs["download_list"]
        description = kwargs["description"]
        snippet = kwargs["snippet"]
        current_version_dict = kwargs.get('current_version_dict', {})

        for index in range(len(arg_list)):
            file_path = arg_list[index]
            file_path = os.path.abspath(file_path)
            advice = ""
            if advice_details:
                advice_details = {
                    output_terms[8]: arg_list[index].split('/')[-1],
                    output_terms[9]: mark_list[index],
                    output_terms[10]: pak_arg_list[index],
                    output_terms[11]: version_list[index],
                    output_terms[12]: download_list[index]
                }
            else:
                if snippet == "Need to be verified.":
                    advice = 'Need to be verified by other engines, or if compatible, it can be ignored.'
                elif snippet == "Files were broken.":
                    advice = "Need to be rechecked manually, or if compatible, it can be ignored."
                else:
                    advice = None

            suffix = arg_list[index].split('.')[-1]
            suffix = suffix if suffix else 'so'
            arg_list[index] = self.get_zip_path(arg_list[index])

            advice_dic = {
                advice_keys[0]: check_point.format(suffix),
                advice_keys[1]: description,
                issue_keys[3]: arg_list[index],
                advice_keys[3]: {
                    advice_keys[4]: des_arg,
                    advice_keys[5]: type_arg
                },
                advice_keys[6]: other_keys[0] if other_keys[0] else None,
                'current': current_version_dict.get(file_path),
                advice_keys[7]: snippet,
                advice_keys[8]: advice if advice else advice_details
            }
            advice_list.append(advice_dic)

        return advice_list

    def json_file_summary_info_write(self, **kwargs):
        """
        When outputting in json format, fill in the file summary according to
        the type of detected object.
        param kwargs: -> dictionary
            various parameters required.
        return: -> dictionary
            Completed file summary.
        """
        json_keys = kwargs["json_keys"]
        advice_keys = kwargs["advice_keys"]
        sub_file_count = kwargs["sub_file_count"]

        key_description1 = ["JAR Archived Data", "SO/ELF Data", "Java SOURCE Data", "Java CLASS Data",
                            "Java POM.xml", "ZIP Archived Data", "Other Files"]
        key_description2 = ["jar", "so", "java", "class", "pom", "zip", "other"]

        file_summary = {
            json_keys[5]: {
                json_keys[6]: 0,
                advice_keys[2]: key_description1[0],
                json_keys[7]: 0
            },
            json_keys[20]: {
                json_keys[6]: 0,
                advice_keys[2]: key_description1[1],
                json_keys[7]: 0
            },
            json_keys[22]: {
                json_keys[6]: 0,
                advice_keys[2]: key_description1[2],
                json_keys[7]: 0
            },
            json_keys[25]: {
                json_keys[6]: 0,
                advice_keys[2]: key_description1[3],
                json_keys[7]: 0
            },
            json_keys[23]: {
                json_keys[6]: 0,
                advice_keys[2]: key_description1[4],
                json_keys[7]: 0
            },
            json_keys[24]: {
                json_keys[6]: 0,
                advice_keys[2]: key_description1[5],
                json_keys[7]: 0
            },
            json_keys[21]: {
                json_keys[6]: 0,
                advice_keys[2]: key_description1[6],
                json_keys[7]: 0
            },
        }

        if type(sub_file_count) is dict:
            file_summary[json_keys[5]][json_keys[6]] = sub_file_count[key_description2[0]]
            file_summary[json_keys[20]][json_keys[6]] = sub_file_count[key_description2[1]]
            file_summary[json_keys[22]][json_keys[6]] = sub_file_count.get(key_description2[2], 0)
            file_summary[json_keys[25]][json_keys[6]] = sub_file_count.get(key_description2[3], 0)
            file_summary[json_keys[23]][json_keys[6]] = sub_file_count.get(key_description2[4], 0)
            file_summary[json_keys[24]][json_keys[6]] = sub_file_count.get(key_description2[5], 0)
            file_summary[json_keys[21]][json_keys[6]] = sub_file_count.get(key_description2[6], 0)
        else:
            file_summary[json_keys[21]][json_keys[6]] = sub_file_count

        return file_summary

    def json_file_root_source_info(self, package_path):
        """
        Handle the three values of root_directory/source_dirs/source_files
        in json format.
        param package_path: -> string
            The absolute path of the detection object.
        return: -> dictionary
            Return the json format root_directory.source_dir.
            source_files The value corresponding to.
        """
        source_dir = []
        source_files = []
        format_arg = ["root_directory", "source_dirs", "source_files"]

        if os.path.isfile(package_path):
            root_directory = package_path[:package_path.rfind('/')]
            json_format = {
                format_arg[0]: root_directory,
                format_arg[1]: [root_directory],
                format_arg[2]: [package_path]
            }

        else:
            root_directory = package_path
            check_dir_files_command = "ls '{}'".format(package_path)
            dir_files = lc().get_command_result(check_dir_files_command)
            if dir_files:
                for file in dir_files.split('\n'):
                    sub_file = "{}/{}".format(package_path.rstrip('/'), file)

                    if os.path.isfile(sub_file):
                        source_files.append(os.path.abspath(sub_file))
                    else:
                        source_dir.append(os.path.abspath(sub_file))

            json_format = {
                format_arg[0]: os.path.abspath(root_directory),
                format_arg[1]: source_dir,
                format_arg[2]: source_files
            }

        return json_format

    def result_save_json_format_v1(self, **kwargs):
        """
        Save the detection results of packages or directories to
        a temporary file in json format.
        param kwargs: -> dictionary
            Print out the required parameter set.
        return: -> None
        """
        json_arg = "json"
        advice_details = {}
        issue_list = []
        advice_arg = []
        incompatible_flag = kwargs["incompatible_flag"]
        write_mode = kwargs["write_mode"]
        output_terms = kwargs["output_terms"]
        package_path = kwargs["package_path"]
        incompatible_so_list = kwargs["incompatible_so_list"]
        conclusion_arg = kwargs["conclusion_arg"]
        sub_file_count = kwargs["sub_file_count"]
        json_log_filename = kwargs["json_log_filename"]

        json_key_arg = {
            "json_keys":
                ["arch", "branch", "commit", "errors", "file_summary",
                 "jar", "count", "loc", "git_repo", "language_type",
                 "march", "output", "progress", "quiet", "remarks",
                 "root_directory", "source_dirs", "source_files", "target_os",
                 "total_issue_count", "so", "other", "java", "pom", "zip", "class"],
            "issue_keys":
                ["issue_summary", "issue_type_config", "issues", "filename"],
            "issue_details":
                ["ArchSpecificLibraryIssue", "count", "des", "INCOMPATIBLE_LIBRARY_FOUND_REMARK",
                 "Error", "FILE_BROKEN_REMARK", "OtherIssue", "TO_BE_VERIFIED_REMARK", "ArchSpecificJarIssue",
                 "INCOMPATIBLE_JAR_FOUND_REMARK", "PomDependencyIssue", "POM_DEPENDENCY_FOUND_REMARK",
                 "AppReferenceIssue", "FILE_NOT_FOUND_REMARK", "Warning", "FILE_IRRELEVANT_REMARK"],
            "advice_keys":
                ["checkpoint", "description", "fileName", "issue_type",
                 "des", "type", "lineno", "snippet", "advice"],
            "other_keys":
                ["", "aarch64", "JAVA", True, False, "OpenAnolis"],
            "checkpoint":
                "Check whether the type of so file is aarch64, and if not, "
                "judge whether it is incompatible.",
            "errorinfo": "File decompression failed."
        }

        checkpoint_dict = {
            "so_compatible": ["Incompatible '{}' libraries have been here.",
                              "Need to be upgraded or compiled as compatible."],
            "other_compatible": ("Beyond the support types of current engine.",
                                 "Need to be verified."),
            "jar_compatible": ("Non-existent 'jar' package have been here.",
                               "Need to be added with compatible 'jar' package."),
            "pom_compatible": ("Incompatible 'pom' libraries have been here.",
                               "Automatically resolve using compatible pom."),
        }

        issue_type_dict = {
            "ArchSpecificLibraryIssue": "INCOMPATIBLE_LIBRARY_FOUND_REMARK",
            "ArchSpecificJarIssue": "INCOMPATIBLE_JAR_FOUND_REMARK",
            "PomDependencyIssue": "POM_DEPENDENCY_FOUND_REMARK",
            "Error": "FILE_BROKEN_REMARK",
            "AppReferenceIssue": "FILE_NOT_FOUND_REMARK",
            "OtherIssue": "TO_BE_VERIFIED_REMARK",
        }

        json_keys = json_key_arg["json_keys"]
        other_keys = json_key_arg["other_keys"]
        issue_keys = json_key_arg["issue_keys"]
        advice_keys = json_key_arg["advice_keys"]
        issue_details = json_key_arg["issue_details"]

        non_test_file_results = []
        failed_list = []

        so_list = []
        jar_list = []
        pom_list = []
        miss_list = []

        if incompatible_flag:
            mark_list = kwargs["mark_list"]
            pak_arg_list = kwargs["pak_arg_list"]
            version_list = kwargs["version_list"]
            download_list = kwargs["download_list"]
            current_version_dict = kwargs.get("current_version_dict", {})
            error_info = json_key_arg["errorinfo"]

            non_test_file_results = [os.path.abspath(i) for i in self.non_test_file if i]
            i = 0
            for index, file in enumerate(incompatible_so_list):
                tag = self.compression_filter(file, collect_jar_mark=True, collect_so_mark=True)
                if tag == "zip_file":
                    jar_list.append(os.path.abspath(file))
                elif tag == "so_file":
                    so_list.append(os.path.abspath(file))
                elif tag == 'pom':
                    pom_list.append(os.path.abspath(file))
                elif tag in [0, 'java']:
                    continue
                elif tag == 'incom_file':
                    real_path = os.path.abspath(self.get_zip_path(file))
                    logger.info('Warning_ZIP3 {}'.format(real_path), 'java')
                else:
                    non_test_file_results.append(os.path.abspath(file))
                if tag != "so_file":
                    mark_list.pop(index - i)
                    pak_arg_list.pop(index - i)
                    version_list.pop(index - i)
                    download_list.pop(index - i)
                    i += 1

            if so_list:
                issue_list = self.json_issue_error_info_write(arg_list=so_list,
                                                              check_point=checkpoint_dict['so_compatible'][0],
                                                              other_keys=other_keys, issue_keys=issue_keys,
                                                              des_arg=issue_type_dict.get('ArchSpecificLibraryIssue'),
                                                              type_arg="ArchSpecificLibraryIssue",
                                                              advice_list=advice_arg, advice_details=True,
                                                              output_terms=output_terms, mark_list=mark_list,
                                                              pak_arg_list=pak_arg_list, version_list=version_list,
                                                              advice_keys=advice_keys,
                                                              description=checkpoint_dict['so_compatible'][1],
                                                              snippet="incompatible", download_list=download_list,
                                                              current_version_dict=current_version_dict)
            if jar_list:
                issue_list = self.json_issue_error_info_write(arg_list=jar_list,
                                                              check_point=checkpoint_dict['jar_compatible'][0],
                                                              other_keys=other_keys, issue_keys=issue_keys,
                                                              des_arg=issue_type_dict.get('ArchSpecificLibraryIssue'),
                                                              type_arg="ArchSpecificLibraryIssue",
                                                              advice_list=issue_list, advice_details=True,
                                                              output_terms=output_terms, mark_list=mark_list,
                                                              pak_arg_list=pak_arg_list, version_list=version_list,
                                                              advice_keys=advice_keys,
                                                              description=checkpoint_dict['jar_compatible'][1],
                                                              snippet="incompatible", download_list=download_list,
                                                              current_version_dict=current_version_dict)
            if pom_list:
                issue_list = self.json_issue_error_info_write(arg_list=pom_list,
                                                              check_point=checkpoint_dict['pom_compatible'][0],
                                                              other_keys=other_keys, issue_keys=issue_keys,
                                                              des_arg=issue_type_dict.get('ArchSpecificLibraryIssue'),
                                                              type_arg="ArchSpecificLibraryIssue",
                                                              advice_list=issue_list, advice_details=True,
                                                              output_terms=output_terms, mark_list=mark_list,
                                                              pak_arg_list=pak_arg_list, version_list=version_list,
                                                              advice_keys=advice_keys,
                                                              description=checkpoint_dict['pom_compatible'][1],
                                                              snippet="incompatible", download_list=download_list,
                                                              current_version_dict=current_version_dict)
            non_test_file_results = [os.path.abspath(i) for i in self.non_test_file if i]
            if non_test_file_results:
                issue_list = self.json_issue_error_info_write(arg_list=non_test_file_results,
                                                              check_point=checkpoint_dict['other_compatible'][0],
                                                              other_keys=other_keys, issue_keys=issue_keys,
                                                              des_arg=issue_type_dict.get('OtherIssue'),
                                                              type_arg="OtherIssue",
                                                              advice_list=issue_list, advice_details=advice_details,
                                                              output_terms=None, mark_list=None,
                                                              pak_arg_list=None, version_list=None,
                                                              advice_keys=advice_keys,
                                                              description=checkpoint_dict['other_compatible'][1],
                                                              snippet="Need to be verified.",
                                                              download_list=download_list,
                                                              )
            failed_list = [i[1] + os.sep + i[2] for i in self.failed_results if len(i) > 3]
            if failed_list:
                issue_list = self.json_issue_error_info_write(arg_list=failed_list, check_point=error_info,
                                                              other_keys=other_keys, issue_keys=issue_keys,
                                                              des_arg=issue_type_dict.get('Error'), type_arg="Error",
                                                              advice_list=issue_list, advice_details=advice_details,
                                                              output_terms=None, mark_list=None,
                                                              pak_arg_list=None, version_list=None,
                                                              advice_keys=advice_keys, description='',
                                                              snippet="Files were broken.", download_list=download_list
                                                              )
        try:
            issue_list.sort(key=lambda x: x.get('filename'))
        except Exception as e:
            MyError().display(MyError().report(e, '', "result_save_json_format", "CS type JSON file sorting failed"))

        file_summary = self.json_file_summary_info_write(json_keys=json_keys, file_path=package_path,
                                                         advice_keys=advice_keys, sub_file_count=sub_file_count)

        file_summary.get('jar')['count'] = self.jar_file_count
        file_summary.get('so')['count'] = self.so_file_count - self.so_warning_count
        file_summary.get('pom')['count'] = self.pom_file_count
        file_summary.get('java')['count'] = self.java_file_count
        file_summary.get('class')['count'] = self.class_file_count
        file_summary.get('zip')['count'] = self.zip_file_count
        file_summary.get('other')['count'] = self.other_file_count - self.other_warning_count

        json_format = self.json_file_root_source_info(package_path)

        json_data = {
            json_keys[0]: other_keys[1],
            json_keys[1]: other_keys[0],
            json_keys[2]: other_keys[0],
            json_keys[3]: [],
            json_keys[4]: file_summary,
            json_keys[8]: other_keys[0],
            issue_keys[0]: {
                issue_details[0]: {
                    issue_details[1]: len(so_list),
                    issue_details[2]: issue_details[3]
                },
                issue_details[8]: {
                    issue_details[1]: len(jar_list),
                    issue_details[2]: issue_details[9]
                },
                issue_details[10]: {
                    issue_details[1]: len(pom_list),
                    issue_details[2]: issue_details[11]
                },
                issue_details[12]: {
                    issue_details[1]: len(miss_list),
                    issue_details[2]: issue_details[13]
                },
                issue_details[4]: {
                    issue_details[1]: len(failed_list),
                    issue_details[2]: issue_details[5]
                },
                issue_details[6]: {
                    issue_details[1]: len(non_test_file_results),
                    issue_details[2]: issue_details[7]
                },
                issue_details[14]: {
                    issue_details[1]: self.so_warning_count + self.other_warning_count,
                    issue_details[2]: issue_details[15]
                },
            },
            issue_keys[1]: conclusion_arg,
            issue_keys[2]: issue_list,
            json_keys[9]: other_keys[2],
            json_keys[10]: other_keys[0],
            json_keys[11]: other_keys[0],
            json_keys[12]: other_keys[3],
            json_keys[13]: other_keys[4],
            json_keys[14]: [],
            json_keys[15]: json_format[json_keys[15]],
            json_keys[16]: json_format[json_keys[16]],
            json_keys[17]: json_format[json_keys[17]],
            json_keys[18]: other_keys[5],
            json_keys[19]: len(issue_list) + self.so_warning_count + self.other_warning_count
        }

        dp().file_read_write(json_log_filename, write_mode, json_arg, json_data)

        return

    def result_save_json_format(self, **kwargs):
        """
        Save the detection results of packages or directories to
        a temporary file in json format.
        param kwargs: -> dictionary
            Print out the required parameter set.
        return: -> None
        """
        json_arg = "json"
        advice_details = {}
        issue_list = []
        advice_arg = []
        incompatible_flag = kwargs["incompatible_flag"]
        write_mode = kwargs["write_mode"]
        output_terms = kwargs["output_terms"]
        package_path = kwargs["package_path"]
        incompatible_so_list = kwargs["incompatible_so_list"]
        conclusion_arg = kwargs["conclusion_arg"]
        sub_file_count = kwargs["sub_file_count"]
        json_log_filename = kwargs["json_log_filename"]

        json_key_arg = {
            "json_keys":
                ["arch", "branch", "commit", "errors", "file_summary",
                 "jar", "count", "loc", "git_repo", "language_type",
                 "march", "output", "progress", "quiet", "remarks",
                 "root_directory", "source_dirs", "source_files", "target_os",
                 "total_issue_count", "so", "other", "java", "pom", "zip", "class"],
            "issue_keys":
                ["issue_summary", "issue_type_config", "issues", "filename"],
            "issue_details":
                ["ArchSpecificLibraryIssue", "count", "des", "INCOMPATIBLE_LIBRARY_FOUND_REMARK",
                 "Error", "FILE_BROKEN_REMARK", "OtherIssue", "TO_BE_VERIFIED_REMARK", "ArchSpecificJarIssue",
                 "INCOMPATIBLE_JAR_FOUND_REMARK", "PomDependencyIssue", "POM_DEPENDENCY_FOUND_REMARK",
                 "AppReferenceIssue", "FILE_NOT_FOUND_REMARK", "Warning", "FILE_IRRELEVANT_REMARK"],
            "advice_keys":
                ["checkpoint", "description", "fileName", "issue_type",
                 "des", "type", "lineno", "snippet", "advice"],
            "other_keys":
                ["", "aarch64", "JAVA", True, False, "OpenAnolis"],
            "checkpoint":
                "Check whether the type of so file is aarch64, and if not, "
                "judge whether it is incompatible.",
            "errorinfo": "File decompression failed."
        }

        checkpoint_dict = {
            "so_compatible": ["Incompatible '{}' libraries have been here.",
                              "Need to be upgraded or compiled as compatible."],
            "other_compatible": ("Beyond the support types of current engine.",
                                 "Need to be verified."),
            "jar_compatible": ("Non-existent 'jar' package have been here.",
                               "Need to be added with compatible 'jar' package."),
            "pom_compatible": ("Incompatible 'pom' libraries have been here.",
                               "Automatically resolve using compatible pom."),
        }

        issue_type_dict = {
            "ArchSpecificLibraryIssue": "INCOMPATIBLE_LIBRARY_FOUND_REMARK",
            "ArchSpecificJarIssue": "INCOMPATIBLE_JAR_FOUND_REMARK",
            "PomDependencyIssue": "POM_DEPENDENCY_FOUND_REMARK",
            "Error": "FILE_BROKEN_REMARK",
            "AppReferenceIssue": "FILE_NOT_FOUND_REMARK",
            "OtherIssue": "TO_BE_VERIFIED_REMARK",
        }

        json_keys = json_key_arg["json_keys"]
        other_keys = json_key_arg["other_keys"]
        issue_keys = json_key_arg["issue_keys"]
        advice_keys = json_key_arg["advice_keys"]
        issue_details = json_key_arg["issue_details"]

        non_test_file_results = []
        failed_list = []

        so_list = []
        jar_list = []
        pom_list = []
        miss_list = []

        if incompatible_flag:
            mark_list = kwargs["mark_list"]
            pak_arg_list = kwargs["pak_arg_list"]
            version_list = kwargs["version_list"]
            download_list = kwargs["download_list"]
            current_version_dict = kwargs.get("current_version_dict", {})
            error_info = json_key_arg["errorinfo"]

            non_test_file_results = [os.path.abspath(i) for i in self.non_test_file if i]
            i = 0
            for index, file in enumerate(incompatible_so_list):
                tag = self.compression_filter(file, collect_jar_mark=True, collect_so_mark=True)
                if tag == "zip_file":
                    jar_list.append(os.path.abspath(file))
                elif tag == "so_file":
                    so_list.append(os.path.abspath(file))
                elif tag == 'pom':
                    pom_list.append(os.path.abspath(file))
                elif tag in [0, 'java']:
                    continue
                elif tag == 'incom_file':
                    real_path = os.path.abspath(self.get_zip_path(file))
                    logger.info('Warning_ZIP3 {}'.format(real_path), 'java')
                else:
                    non_test_file_results.append(os.path.abspath(file))
                if tag != "so_file":
                    mark_list.pop(index - i)
                    pak_arg_list.pop(index - i)
                    version_list.pop(index - i)
                    download_list.pop(index - i)
                    i += 1

            if so_list:
                issue_list = self.json_issue_error_info_write(arg_list=so_list,
                                                              check_point=checkpoint_dict['so_compatible'][0],
                                                              other_keys=other_keys, issue_keys=issue_keys,
                                                              des_arg=issue_type_dict.get('ArchSpecificLibraryIssue'),
                                                              type_arg="ArchSpecificLibraryIssue",
                                                              advice_list=advice_arg, advice_details=True,
                                                              output_terms=output_terms, mark_list=mark_list,
                                                              pak_arg_list=pak_arg_list, version_list=version_list,
                                                              advice_keys=advice_keys,
                                                              description=checkpoint_dict['so_compatible'][1],
                                                              snippet="incompatible", download_list=download_list,
                                                              current_version_dict=current_version_dict)
            if jar_list:
                issue_list = self.json_issue_error_info_write(arg_list=jar_list,
                                                              check_point=checkpoint_dict['jar_compatible'][0],
                                                              other_keys=other_keys, issue_keys=issue_keys,
                                                              des_arg=issue_type_dict.get('ArchSpecificLibraryIssue'),
                                                              type_arg="ArchSpecificLibraryIssue",
                                                              advice_list=issue_list, advice_details=True,
                                                              output_terms=output_terms, mark_list=mark_list,
                                                              pak_arg_list=pak_arg_list, version_list=version_list,
                                                              advice_keys=advice_keys,
                                                              description=checkpoint_dict['jar_compatible'][1],
                                                              snippet="incompatible", download_list=download_list,
                                                              current_version_dict=current_version_dict)
            if pom_list:
                issue_list = self.json_issue_error_info_write(arg_list=pom_list,
                                                              check_point=checkpoint_dict['pom_compatible'][0],
                                                              other_keys=other_keys, issue_keys=issue_keys,
                                                              des_arg=issue_type_dict.get('ArchSpecificLibraryIssue'),
                                                              type_arg="ArchSpecificLibraryIssue",
                                                              advice_list=issue_list, advice_details=True,
                                                              output_terms=output_terms, mark_list=mark_list,
                                                              pak_arg_list=pak_arg_list, version_list=version_list,
                                                              advice_keys=advice_keys,
                                                              description=checkpoint_dict['pom_compatible'][1],
                                                              snippet="incompatible", download_list=download_list,
                                                              current_version_dict=current_version_dict)

            if non_test_file_results:
                issue_list = self.json_issue_error_info_write(arg_list=non_test_file_results,
                                                              check_point=checkpoint_dict['other_compatible'][0],
                                                              other_keys=other_keys, issue_keys=issue_keys,
                                                              des_arg=issue_type_dict.get('OtherIssue'),
                                                              type_arg="OtherIssue",
                                                              advice_list=issue_list, advice_details=advice_details,
                                                              output_terms=None, mark_list=None,
                                                              pak_arg_list=None, version_list=None,
                                                              advice_keys=advice_keys,
                                                              description=checkpoint_dict['other_compatible'][1],
                                                              snippet="Need to be verified.",
                                                              download_list=download_list)
            failed_list = [i[1] + os.sep + i[2] for i in self.failed_results if len(i) > 3]
            if failed_list:
                issue_list = self.json_issue_error_info_write(arg_list=failed_list, check_point=error_info,
                                                              other_keys=other_keys, issue_keys=issue_keys,
                                                              des_arg=issue_type_dict.get('Error'), type_arg="Error",
                                                              advice_list=issue_list, advice_details=advice_details,
                                                              output_terms=None, mark_list=None,
                                                              pak_arg_list=None, version_list=None,
                                                              advice_keys=advice_keys, description='',
                                                              snippet="Files were broken.", download_list=download_list
                                                              )
        try:
            issue_list.sort(key=lambda x: x.get('filename'))
        except Exception as e:
            MyError().display(MyError().report(e, '', "result_save_json_format", "CS type JSON file sorting failed"))

        file_summary = self.json_file_summary_info_write(json_keys=json_keys, file_path=package_path,
                                                         advice_keys=advice_keys, sub_file_count=sub_file_count)

        file_summary.get('jar')['count'] = self.jar_file_count
        file_summary.get('so')['count'] = self.so_file_count - self.so_warning_count
        file_summary.get('pom')['count'] = self.pom_file_count
        file_summary.get('java')['count'] = self.java_file_count
        file_summary.get('class')['count'] = self.class_file_count
        file_summary.get('zip')['count'] = self.zip_file_count
        file_summary.get('other')['count'] = self.other_file_count - self.other_warning_count

        json_format = self.json_file_root_source_info(package_path)

        json_data = {
            json_keys[0]: other_keys[1],
            json_keys[1]: other_keys[0],
            json_keys[2]: other_keys[0],
            json_keys[3]: [],
            json_keys[4]: file_summary,
            json_keys[8]: other_keys[0],
            issue_keys[0]: {
                issue_details[0]: {
                    issue_details[1]: len(so_list),
                    issue_details[2]: issue_details[3]
                },
                issue_details[8]: {
                    issue_details[1]: len(jar_list),
                    issue_details[2]: issue_details[9]
                },
                issue_details[10]: {
                    issue_details[1]: len(pom_list),
                    issue_details[2]: issue_details[11]
                },
                issue_details[12]: {
                    issue_details[1]: len(miss_list),
                    issue_details[2]: issue_details[13]
                },
                issue_details[4]: {
                    issue_details[1]: len(failed_list),
                    issue_details[2]: issue_details[5]
                },
                issue_details[6]: {
                    issue_details[1]: len(non_test_file_results),
                    issue_details[2]: issue_details[7]
                }
            },
            issue_keys[1]: conclusion_arg,
            issue_keys[2]: issue_list,
            json_keys[9]: other_keys[2],
            json_keys[10]: other_keys[0],
            json_keys[11]: other_keys[0],
            json_keys[12]: other_keys[3],
            json_keys[13]: other_keys[4],
            json_keys[14]: [],
            json_keys[15]: json_format[json_keys[15]],
            json_keys[16]: json_format[json_keys[16]],
            json_keys[17]: json_format[json_keys[17]],
            json_keys[18]: other_keys[5],
            json_keys[19]: len(issue_list)
        }
        if self.tree_output:
            mount_compatibility_into_node(package_path, issue_list, self.root_node)
            dp().file_read_write(self.dir_tree_path, 'a', 'json', self.root_node)
        dp().file_read_write(json_log_filename, write_mode, json_arg, json_data)

        return

    def log_output(self, log_type, log_file_path, temporary_files,
                   detection_object, execution_results):
        """
        Summarize the temporary result files to output in the result log.
        param log_type: -> string
            Log save format.
        param log_file_path: -> string
            The target file to save when the results are summarized and output.
        param temporary_files: -> list
            All temporary log files.
        param detection_object: -> list
            A list of objects to detect.
        param execution_results: -> list
            Execution results, including failed, successful, and error flags.
        return: -> None
        """
        encod_arg = "utf-8-sig"
        csv_arg = 'csv'
        java_arg = 'java'

        write_modes = ['a', 'r']
        csv_headers = ["PROJECT", "LOCATION", "NAME", "MD5", "CATEGORY", "TYPE",
                       "INCOMPATIBILITY", "ADVICE", "UPGRADE", "PACKAGE",
                       "VERSION", "FROM", "DOWNLOAD", "ACTION"]
        if not self.class_value:
            csv_headers.append("UNVERIFIED")
        csv_udf_headers = ["PROJECT", "NAME", "CATEGORY", "TYPE", "INCOMPATIBILITY",
                           "UPGRADE", "NAME-SO", "PACKAGE", "VERSION", 'ACTION', 'STATUS']

        if (self.class_value == 'udf' and
                log_type == csv_arg):
            csv_header_info = csv_udf_headers

        else:
            csv_header_info = csv_headers
            if self.class_value != 'xarch':
                no().log_normalized_output(log_type, log_file_path, detection_object, execution_results,
                                           self.detection_command, self.execution_detection_time, java_arg)
            else:
                row_datas = no().get_xarch_header(detection_object, execution_results, self.detection_command,
                                                  self.execution_detection_time)

        with open(log_file_path, write_modes[0], encoding=encod_arg, errors="surrogatepass") as f:
            if log_type == csv_arg:
                f_csv = csv.writer(f)
                if self.class_value == 'xarch':
                    f_csv.writerows(row_datas)
                f_csv.writerow(csv_header_info)
            if self.class_value != 'xarch':
                for temporary_file in temporary_files:
                    if (type(temporary_file) is list
                            and not temporary_file):
                        continue
                    elif (type(temporary_file) is str and
                          not os.path.exists(temporary_file)):
                        continue

                    for line_info in temporary_file:
                        if line_info.count('') == len(line_info):
                            continue
                        if self.log_type == csv_arg:
                            line_infos = False
                            if self.class_value == 'udf':
                                line_infos = self.csv_format_long_characters_intercepted_save_udf(line_info)
                            elif self.class_value != 'udf' and line_info[4] != "1":
                                line_infos = self.csv_format_long_characters_intercepted_save(line_info)
                            if line_infos is False:
                                f_csv.writerow(line_info)
                            else:
                                for line_info in line_infos:
                                    f_csv.writerow(line_info)
                        else:
                            for info in line_info:
                                info_index = line_info.index(info)
                                if info == '':
                                    info = ";"
                                if '\n' in info:
                                    info = info.replace('\n', ',')
                                line_info[info_index] = info

                            new_line_info = ';'.join(line_info) + ';\n'
                            f.write(new_line_info)
            else:
                for result in self.summary_data:
                    project = result.get('project')
                    location = result.get('location')
                    file_name = result.get('file_name')
                    file_md5 = result.get('file_md5')
                    category = result.get('category')
                    file_type = result.get('file_type')
                    incom_list = result.get('incom_list', []) if category == 'x86_64' else []
                    upgrade_list = result.get('upgrade_list', []) if category == 'x86_64' else []
                    package_list = result.get('package_list', []) if category == 'x86_64' else []
                    advice_list = result.get('advice_list', []) if category == 'x86_64' else []
                    version_list = result.get('version_list', []) if category == 'x86_64' else []
                    from_list = result.get('from_list', []) if category == 'x86_64' else []
                    download_list = result.get('download_list', []) if category == 'x86_64' else []
                    action_list = result.get('action_list', []) if category == 'x86_64' else []

                    cut_nu = len(action_list) // 100 + (1 if len(action_list) % 100 > 0 else 0)
                    # 防止单元格超限30000
                    incom_list = self.cut_field_xarch(incom_list, cut_nu)
                    advice_list = self.cut_field_xarch(advice_list, cut_nu)
                    version_list = self.cut_field_xarch(version_list, cut_nu)
                    upgrade_list = self.cut_field_xarch(upgrade_list, cut_nu)
                    package_list = self.cut_field_xarch(package_list, cut_nu)
                    from_list = self.cut_field_xarch(from_list, cut_nu)
                    download_list = self.cut_field_xarch(download_list, cut_nu)
                    action_list = self.cut_field_xarch(action_list, cut_nu)
                    incompatible_results = list(zip_longest([project], [location], [file_name], [file_md5], [category],
                                                            [file_type], incom_list, advice_list, upgrade_list,
                                                            package_list,
                                                            version_list, from_list, download_list, action_list,
                                                            fillvalue=''))
                    incompatible_results = self.sort_incompatible(incompatible_results)
                    for csv_data in incompatible_results:
                        if not any(csv_data):
                            continue
                        temp_data = list(csv_data)
                        temp_data[0] = project
                        temp_data[1] = location
                        temp_data[2] = file_name
                        temp_data[3] = file_md5
                        temp_data[4] = category
                        temp_data[5] = file_type
                        f_csv.writerow(temp_data)

        if (log_type == csv_arg and
                self.class_value and
                not self.engine):
            self.csv_log_path = log_file_path

        return

    def cut_field_xarch(self, field, cut_nu):
        """
        Slice fields according to cell limitations
        param field: -> string
            Source Field String
        param cut_nu: -> int
            Slice count
        Return field_list -> list
            List of sliced strings
        """
        field_list = []
        for i in range(cut_nu):
            if isinstance(field, list):
                field_cut = field[100 * i: 100 * (i + 1)]
                field_list.append('\n'.join(field_cut))
            else:
                field_cut = field.split('\n')[100 * i: 100 * (i + 1)]
                field_list.append('\n'.join(field_cut))
        return field_list

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
        field_list = []
        for i in range(cut_nu):
            field_cut = field.split(':')[100 * i: 100 * (i + 1)]
            field_list.append(':'.join(field_cut))
        return field_list

    def json_details_format(self, temporary_files):
        """
        Standardized output of details in json format.
        param temporary_files: -> list
            Temporary log files for compatibility, incompatibilities, and errors.
        return: -> list
            Details of the completed details after parsing the temporary file.
        """
        details = []
        item_args = ["item", "advice", "upgrade", "package", "version", "from", "download", "action"]
        details_args = ["project", "location", "name", "md5", "category", "type", "incompatibility"]

        if temporary_files:
            for temporary_file in temporary_files:
                entry_information = {}
                if not temporary_file:
                    continue
                for line_info in temporary_file:
                    incompatibility_so_result_list = []
                    try:
                        category = line_info[4]
                    except Exception:
                        category = ''
                    try:
                        incompatibility = line_info[6]
                    except Exception:
                        incompatibility = ''
                    if incompatibility:
                        incompatibility_so_list = incompatibility.split('\n')
                        advice_list = line_info[7].split('\n')
                        upgrade_list = line_info[8].split('\n')
                        package_list = line_info[9].split('\n')
                        version_list = line_info[10].split('\n')
                        from_list = line_info[11].split('\n')
                        download_list = line_info[12].split('\n')
                        action_list = line_info[13].split('\n')
                        for index in range(len(upgrade_list)):
                            incompatibility_so_result = {
                                item_args[0]: incompatibility_so_list[index],
                                item_args[1]: advice_list[index],
                                item_args[2]: upgrade_list[index],
                                item_args[3]: package_list[index],
                                item_args[4]: version_list[index],
                                item_args[5]: from_list[index],
                                item_args[6]: download_list[index],
                                item_args[7]: action_list[index]
                            }
                            incompatibility_so_result_list.append(incompatibility_so_result)

                    entry_information = {
                        details_args[0]: line_info[0],
                        details_args[1]: line_info[1],
                        details_args[2]: line_info[2],
                        details_args[3]: line_info[3],
                        details_args[4]: category,
                        details_args[5]: line_info[5],
                        details_args[6]: incompatibility_so_result_list
                    }
                    details.append(entry_information)

        return details

    def json_log_format_processing(self, json_log_filename, temporary_files,
                                   detection_object, execution_results):
        """
        When the cs flag is not specified, the output is standardized in json format.
        param json_log_filename: -> string
            The log name in json format.
        param temporary_files: -> list
            Temporary log files for compatibility, incompatibilities, and errors.
        param detection_object: -> list
            A list of objects to detect.
        param execution_results: -> list
            Execution results, including failed, successful, and error flags.
        return: -> None
        """
        json_arg = 'json'
        java_arg = 'java'
        encod_arg = 'utf-8-sig'

        write_modes = ['a', 'r']

        scanned_execute_summary_data = no().log_normalized_output(json_arg, "", detection_object,
                                                                  execution_results, self.detection_command,
                                                                  self.execution_detection_time, java_arg)
        details_data = self.json_details_format(temporary_files)

        scanned_execute_summary_data["details"] = details_data
        json_log_filename = "{}.json".format(json_log_filename)
        new_json_log_filename = "{}_bak.json".format(json_log_filename)
        with open(new_json_log_filename, write_modes[0], encoding=encod_arg, errors="surrogatepass") as j:
            json.dump(scanned_execute_summary_data, j, ensure_ascii=False, indent=2)
            j.flush()

        update_json_log_filename_command = 'rm -rf {} && mv {} {}'.format(json_log_filename,
                                                                          new_json_log_filename,
                                                                          json_log_filename)
        subprocess.call(update_json_log_filename_command, shell=True)

        return

    def sort_incompatible(self, incompatible_results):
        try:
            new_incompatible_results = []
            if self.class_value != "udf":
                for item in incompatible_results:
                    incompatible_data = [item[0], item[1], item[2], item[3], item[4], item[5]]
                    all_list = list(
                        zip(item[6].split('\n') if "\n" in item[6] else item[6].split(','), item[7].split('\n'),
                            item[8].split('\n'),
                            item[9].split('\n'),
                            item[10].split('\n'), item[11].split('\n'), item[12].split('\n'),
                            item[13].split('\n')))
                    all_list.sort(key=lambda x: x[0])

                    piece_list = list(zip(*all_list))
                    for i in piece_list:
                        incompatible_data.append("\n".join(i))
                    if len(item) > 14:
                        incompatible_data.append(item[14])
                    new_incompatible_results.append(incompatible_data)
            else:
                for item in incompatible_results:
                    incompatible_data = [item[0], item[1], item[2], item[3]]
                    all_list = list(
                        zip(item[4].split(':'), item[6].split('\n'), item[7].split('\n'),
                            item[8].split('\n'), item[9].split('\n')))
                    all_list.sort(key=lambda x: x[0])
                    piece_list = list(zip(*all_list))
                    incompatible_data.append(":".join(piece_list[0]))
                    incompatible_data.append(item[5])
                    for i in piece_list[1:]:
                        incompatible_data.append("\n".join(i))
                    incompatible_data.append(item[10])
                    new_incompatible_results.append(incompatible_data)
            return new_incompatible_results
        except Exception as e:
            MyError().display(MyError().report(e, '', "sort_incompatible", "Incompatible Results sorting failed"))
            return incompatible_results

    def detection_result_log_output(self, json_log_filename, log_type, specify_log_name,
                                    detection_object, execution_results):
        """
        Result log output.
        param json_log_filename: -> string
            The log name in json format.
        param log_type: -> string
            Log save format.
        param specify_log_name: -> None or string
            The log name specified on the command line.
        param detection_object: -> list
            A list of objects to detect.
        param execution_results: -> list
            Execution results, including failed, successful, and error flags.
        return: -> function or None
        """
        types = ['log', 'txt', 'csv', 'json']

        result_log_filename = json_log_filename

        if log_type == types[1]:
            result_file = "{}.{}".format(result_log_filename, types[0])
        else:
            result_file = "{}.{}".format(result_log_filename, log_type)
        self.incompatible_results = self.sort_incompatible(self.incompatible_results)

        if log_type != types[3]:
            temporary_files = [self.incompatible_results, self.non_test_file_results,
                               self.failed_results, self.compatible_results]
        else:
            temporary_files = [self.incompatible_results, self.non_test_file_results,
                               self.failed_results]

        if log_type != types[3]:
            return self.log_output(log_type, result_file, temporary_files,
                                   detection_object, execution_results)
        elif (log_type == types[3] and
              not self.codescan_json):
            return self.json_log_format_processing(json_log_filename, temporary_files,
                                                   detection_object, execution_results)

        return

    def output_detection_dir_results(self, udf_result_dict, mark, so_final_result, log_type, all_child_file={}):
        """
        When the detection object is a directory,
        the output in txt and csv formats is processed separately.
        param udf_result_dict: -> dictionary
            When class udf is specified in csv format, check the level matching result of the result.
        param mark: -> boolean
            Indicates whether to evaluate only.
        param so_final_result: -> dictionary
            So package search method identification.
        param log_type: -> string
            Log save format.
        return: -> None
        """
        complied_arg = "Self-compiled"
        incompatible_so_name = ''
        csv_arg = 'csv'
        json_arg = 'json'

        mark_list = []
        pak_arg_list = []
        version_list = []
        output_data = ["No", "Yes"]
        arg_list = ["mark_list", "version_list", "pak_arg_list"]

        if so_final_result:
            so_final_keys = list(so_final_result.keys())

            for jar_key in so_final_keys:
                line_no = ''
                repo_url = ''
                minversion = ''
                child_file = ''
                flag = False
                so_pkg_list = None

                conclusion_arg = "Open source"

                so_result = self.get_incompatible_so_document({jar_key: so_final_result[jar_key]}, all_child_file)
                incompatible_so_list = so_result["so_file_list"]

                package_value = dp().package_name_processing(jar_key)
                package_name = package_value["name"]
                package_hash = package_value["hash"]
                package_type = df().get_file_precise_type(jar_key)
                jar_key = self.get_zip_path(jar_key)
                if incompatible_so_list:
                    flag = True
                    incompatible_so_name_list = []
                    for so_file in incompatible_so_list:
                        if self.ep_temp_files in so_file:
                            so_file = so_file.replace(self.ep_temp_files, '').lstrip("/").split("/", 1)[-1]
                        else:
                            so_file = so_file.split("/")[-1]
                        so_file = remove_file_path_suffix(so_file)
                        incompatible_so_name_list.append(so_file)

                    if (self.class_value and
                            log_type == csv_arg and
                            self.log_type != json_arg):
                        so_pkg_list = ":".join(incompatible_so_name_list)
                    elif log_type == csv_arg:
                        so_pkg_list = "\n".join(incompatible_so_name_list)
                    else:
                        so_pkg_list = ",".join(incompatible_so_name_list)

                    so_result_data = self.so_result_process(so_result, incompatible_so_name_list)

                    mark_list = so_result_data[arg_list[0]]
                    version_list = so_result_data[arg_list[1]]
                    pak_arg_list = so_result_data[arg_list[2]]
                    line_no = '\n'.join(so_result['location_list'])
                    repo_url = '\n'.join(so_result['repo_url_list'])
                    minversion = '\n'.join(so_result['minversion_list'])
                    child_file = '\n'.join(so_result.get("all_child_file_list", []))

                    if pak_arg_list and not self.class_value:
                        for index in range(len(pak_arg_list)):
                            if not pak_arg_list[index]:
                                incompatible_so_name_list[index] = ''
                        incompatible_so_name = "\n".join(incompatible_so_name_list)
                    else:
                        incompatible_so_name = "\n".join(incompatible_so_name_list)

                if "" in mark_list:
                    conclusion_arg = complied_arg

                self.result_save_csv_format(mark=mark, write_mode='a', package_path=jar_key,
                                            incompatible_pkg=incompatible_so_name,
                                            incompatible_flag=flag, package_name=package_name,
                                            package_hash=package_hash, package_type=package_type,
                                            conclusion_arg=conclusion_arg, pak_arg_list=pak_arg_list,
                                            output_data=output_data, so_pkg_list=so_pkg_list, flag=False,
                                            version_list=version_list, mark_list=mark_list, result_dict=udf_result_dict,
                                            line_no=line_no, repo_url=repo_url, minversion=minversion,
                                            all_child_file=child_file)

        return

    def incompatible_package_handling(self, package, total_failed, failed_list,
                                      so_final_result, log_type, mark, quiet_mark,
                                      json_log_filename, sub_file_count=0, all_child_file={}):
        """
        Dispose of packages that do not meet the requirements.
        param package: -> string
            The absolute path of the package.
        param total_failed: -> int
            The total of all error messages in the detection object.
        param so_final_result: -> dictionary
            So package search method identification.
        param log_type: -> string
            Log save format.
        param mark: -> boolean
            Indicates whether to evaluate only.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        param sub_file_count: -> int
            The total number of all subfiles in the detection object.
        return: -> int
            1: Identification of nonconformity.
        """
        flag = False

        incompatible_pkg = None
        so_pkg_list = None

        line_no = ''
        minversion = ''
        repo_url = ''
        child_file = ''
        incompatible_so_name = ''
        conclusion_arg = "Open source"
        name_arg = "name"
        hash_arg = "hash"
        complied_arg = "Self-compiled"
        write_mode = "a"

        arg_list = ["mark_list", "version_list", "pak_arg_list"]
        output_terms = ["NAME", "LOCATION", "MD5", "COMPATIBILITY", "TYPE",
                        "INCOMPATIBILITY", "CONCLUSION", "UPGRADE",
                        "NAME", "TYPE-SRC", "PACKAGE", "VERSION", "DOWNLOAD"]
        output_data = ["No", "Yes"]
        log_types = ["txt", "csv", "json"]
        so_res_keys = ["so_file_list", 'repo_url_list', 'location_list', 'minversion_list']

        mark_list = []
        pak_arg_list = []
        download_list = []
        version_list = []
        incompatible_so_list = []
        incompatible_so_path_list = []
        current_version_dict = {}
        result_dict = {}

        package_value = dp().package_name_processing(package, self.class_value)
        package_name = package_value[name_arg]
        package_hash = package_value[hash_arg]

        package_type = df().get_file_precise_type(package)

        if so_final_result:
            flag = True

            so_result = self.get_incompatible_so_document(so_final_result, all_child_file)
            current_version_dict = so_result.get('current_version_dict', [])
            incompatible_so_list = so_result[so_res_keys[0]]
            incompatible_so_name_list = []
            for so_file in incompatible_so_list:
                if self.ep_temp_files in so_file:
                    so_file = so_file.replace(self.ep_temp_files, "").replace(package, '').lstrip("/").split("/", 1)[
                        -1]
                else:
                    so_file = so_file.split("/")[-1]
                so_file = remove_file_path_suffix(so_file)
                incompatible_so_name_list.append(so_file)

            incompatible_so_path_list = [self.get_zip_path(so_file) for so_file in incompatible_so_list]
            incompatible_pkg = ";".join(incompatible_so_name_list)

            if (self.class_value and
                    log_type == log_types[1]):
                so_pkg_list = ":".join(incompatible_so_name_list)
            elif log_type == log_types[1]:
                so_pkg_list = "\n".join(incompatible_so_name_list)
            else:
                so_pkg_list = ",".join(incompatible_so_name_list)

            so_result_data = self.so_result_process(so_result, incompatible_so_name_list)
            mark_list = so_result_data[arg_list[0]]
            version_list = so_result_data[arg_list[1]]
            pak_arg_list = so_result_data[arg_list[2]]
            download_list = so_result[so_res_keys[1]]
            repo_url = '\n'.join(so_result[so_res_keys[1]])
            line_no = '\n'.join(so_result[so_res_keys[2]])
            minversion = '\n'.join(so_result[so_res_keys[3]])  # advice
            child_file = '\n'.join(so_result.get("all_child_file_list", []))  # advice
            if pak_arg_list and not self.class_value:
                for index in range(len(pak_arg_list)):
                    if not pak_arg_list[index]:
                        incompatible_so_name_list[index] = ''
                incompatible_so_name = "\n".join(incompatible_so_name_list)
            else:
                incompatible_so_name = "\n".join(incompatible_so_name_list)

            result_dict = self.class_value_output(so_final_result, package)

        if ("" in mark_list or
                not mark_list):
            conclusion_arg = complied_arg

        if quiet_mark:
            output_term = output_terms[:1] + output_terms[2:]

            self.detection_result_stdout(mark=mark, incompatible_flag=flag, package_name=package_name,
                                         package_hash=package_hash, package_type=package_type,
                                         incompatible_pkg=incompatible_pkg, conclusion_arg=conclusion_arg,
                                         output_terms=output_term, output_data=output_data,
                                         incompatible_so_list=incompatible_so_path_list, mark_list=mark_list,
                                         pak_arg_list=pak_arg_list, version_list=version_list, result_dict=result_dict,
                                         package_path=package)

        if (os.path.isdir(package) and
                log_type != log_types[2]):
            self.output_detection_dir_results(result_dict, mark, so_final_result, log_type,
                                              all_child_file=all_child_file)
            return 1

        elif (log_type == log_types[2] and
              not self.codescan_json):
            self.output_detection_dir_results(result_dict, mark, so_final_result, log_types[1])

        if log_type != log_types[2]:
            self.result_save_csv_format(mark=mark, write_mode=write_mode, package_path=package,
                                        incompatible_flag=flag, package_name=package_name,
                                        package_hash=package_hash, package_type=package_type,
                                        incompatible_pkg=incompatible_so_name,
                                        conclusion_arg=conclusion_arg, pak_arg_list=pak_arg_list,
                                        output_data=output_data, so_pkg_list=so_pkg_list, flag=False,
                                        version_list=version_list, mark_list=mark_list, result_dict=result_dict,
                                        line_no=line_no, repo_url=repo_url, minversion=minversion,
                                        all_child_file=child_file)

        elif log_type == log_types[2]:
            self.result_save_json_format(mark=mark, write_mode=write_mode, package_path=package,
                                         incompatible_flag=True, sub_file_count=sub_file_count,
                                         package_hash=package_hash, package_type=package_type,
                                         conclusion_arg=conclusion_arg, output_terms=output_terms,
                                         output_data=output_data, incompatible_so_list=incompatible_so_list,
                                         mark_list=mark_list, pak_arg_list=pak_arg_list, failed_list=failed_list,
                                         version_list=version_list, total_failed=total_failed,
                                         json_log_filename=json_log_filename, download_list=download_list,
                                         current_version_dict=current_version_dict)

        return 1

    def class_value_output(self, jar_so_recommend_dict, package):
        """
        Classify the output results
        param jar_so_recommend_dict: -> dict
            So package search method identification.
        param package: -> string
            The absolute path of the package.
        return: -> dict
            The type of so.
        """
        ep_tmp_mark = '/ep_tmp_2'

        result_dict = dict()

        for path in jar_so_recommend_dict:
            if os.path.isdir(path):
                if jar_so_recommend_dict[path]:
                    if "jar_recomand_data" in jar_so_recommend_dict[path]:
                        result_dict[path] = "J2"
                        continue

                    for so_path in jar_so_recommend_dict[path]:
                        result_dict[so_path] = "J0"
                        if jar_so_recommend_dict[path][so_path] == 0:
                            result_dict[so_path] = "1"
                        if isinstance(jar_so_recommend_dict[path][so_path], dict):
                            result_dict[so_path] = "J5"
                            if jar_so_recommend_dict[path][so_path].get('mark') != -1:
                                result_dict[so_path] = "J2"

            elif os.path.isfile(path):
                if jar_so_recommend_dict[path]:
                    if "jar_recomand_data" in jar_so_recommend_dict[path]:
                        if ep_tmp_mark in path:
                            path = self.get_zip_path(path)
                        result_dict[path] = "J2"
                        continue

                    compatible_list = []
                    for recommend in jar_so_recommend_dict[path].values():
                        if recommend == 0:
                            compatible_list.append(0)
                        elif isinstance(recommend, dict):
                            if recommend.get('mark') == -1:
                                compatible_list.append(1)
                            else:
                                compatible_list.append(2)

                    if ep_tmp_mark in path:
                        path = self.get_zip_path(path)
                    if not any(compatible_list):
                        result_dict[path] = "1"
                    elif compatible_list.count(1) == len(compatible_list) or \
                            compatible_list.count(1) + compatible_list.count(0) == len(compatible_list):
                        result_dict[path] = "J5"
                    elif compatible_list.count(2) + compatible_list.count(0) == len(compatible_list):
                        result_dict[path] = "J2"
                    else:
                        result_dict[path] = "J3"
                else:
                    if ep_tmp_mark in path:
                        path = self.get_zip_path(path)
                    result_dict[path] = "1"

        if os.path.isfile(package):
            zip_package_key_list = list(result_dict.keys())
            zip_package_value_list = list(result_dict.values())
            if not zip_package_value_list:
                result_dict[package] = "1"
            else:
                if package not in zip_package_key_list:
                    if zip_package_value_list.count('J2') == len(zip_package_value_list):
                        result_dict[package] = "J2"
                    elif (zip_package_value_list.count('J3') > 0 or
                          (zip_package_value_list.count('J3') == 0 and
                           "J2" in zip_package_value_list and
                           "J5" in zip_package_value_list)):
                        result_dict[package] = "J3"
                    elif zip_package_value_list.count('J5') == len(zip_package_value_list):
                        result_dict[package] = "J5"
                    elif zip_package_value_list.count('J0') == len(zip_package_value_list):
                        result_dict[package] = "J0"

        if (result_dict and
                self.log_type == 'csv' and
                self.class_value):
            for result_key in result_dict:
                result_dict[result_key] = result_dict[result_key].replace('J', '').replace('3', '5')

        return result_dict

    def is_py_zip(self, file_name):
        """
        Determine whether the file belongs to python
        param file_name: -> string
            The name of the file.
        return: --> bool
        """
        for flag in python_flag:
            if flag.lower() in file_name.lower():
                return True
        return False

    def inspection_result_output(self, package, elf_count, not_arm_count,
                                 log_type, quiet_mark, json_log_filename,
                                 output_mark=None, sub_file_count=0, cs=False, tbv_list=[]):
        """
        Process the file evaluation results, and then format the output.
        param package: -> string
            The absolute path of the compressed package or folder.
        param elf_count: -> int
            The total number of elf files.
        param not_arm_count: -> int
            The total number of non arm files in elf files.
        param log_type: -> string
            Specify the log file format.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        param output_mark: -> None or int
            Screen printout ID.
        param sub_file_count: -> int
            The total number of all subfiles in the detection object.
        return: -> int
            0: can be shared.
            1: cannot be shared.
        """
        write_mode = "a"
        json_arg = "json"
        output_terms = ["NAME", "LOCATION", "MD5", "COMPATIBILITY", "TYPE"]
        output_data1 = ["No", "Yes"]

        package_value = dp().package_name_processing(package)
        package_name = package_value["name"]
        package_hash = package_value["hash"]

        package_type = df().get_file_precise_type(package)
        file_type = get_file_real_type(package)
        if file_type == 'XML 1.0 document' and package_type == 'jar':
            package_type = 'ASCII text'

        package = self.get_zip_path(package)
        # 没有不兼容的so
        if elf_count >= 1 or elf_count == 0 and not_arm_count == 0:

            if not output_mark and quiet_mark:
                output_term = output_terms[:1] + output_terms[2:]
                # 输出兼容信息
                self.detection_result_stdout(incompatible_flag=False, package_name=package_name,
                                             package_hash=package_hash, package_type=package_type,
                                             output_terms=output_term, output_data=output_data1)

            # not_arm_count != 0 情况不存在
            if log_type != json_arg:
                self.result_save_csv_format(incompatible_flag=False, package_name=package_name,
                                            package_path=package, flag=True,
                                            package_hash=package_hash, package_type=package_type,
                                            write_mode=write_mode, output_data=output_data1)
            else:
                if cs is True:
                    self.result_save_json_format(write_mode=write_mode, incompatible_flag=True,
                                                 package_hash=package_hash, json_log_filename=json_log_filename,
                                                 package_type=package_type, output_terms=output_terms,
                                                 output_data=output_data1, package_path=package,
                                                 total_failed=0, incompatible_so_list=[],
                                                 conclusion_arg='', sub_file_count=sub_file_count,
                                                 mark_list=[], pak_arg_list=[], failed_list=[],
                                                 version_list=[], download_list=[])
                else:
                    self.result_save_json_format(write_mode=write_mode, incompatible_flag=False,
                                                 package_hash=package_hash, json_log_filename=json_log_filename,
                                                 package_type=package_type, output_terms=output_terms,
                                                 output_data=output_data1, package_path=package,
                                                 total_failed=0, incompatible_so_list=[],
                                                 conclusion_arg='', sub_file_count=sub_file_count)
                if not self.codescan_json:
                    self.result_save_csv_format(incompatible_flag=False, package_name=package_name,
                                                package_path=package, flag=True,
                                                package_hash=package_hash, package_type=package_type,
                                                write_mode=write_mode, output_data=output_data1)

            return 0

        elif not_arm_count == -1:
            self.failed_files[package] = ""
            self.result_save_fail_format(write_mode=write_mode, txt_arg=log_type, package_path=package,
                                         not_arm_count=not_arm_count, quiet_mark=quiet_mark,
                                         incompatible_flag=False, package_name=package_name,
                                         package_hash=package_hash, package_type=package_type,
                                         output_terms=output_terms, output_data=output_data1,
                                         failed_path=tbv_list)
        elif not_arm_count == -2:
            self.failed_files[package] = ""
            self.result_save_fail_format(write_mode=write_mode, txt_arg=log_type, package_path=package,
                                         not_arm_count=not_arm_count, quiet_mark=quiet_mark,
                                         incompatible_flag=False, package_name=package_name,
                                         package_hash=package_hash, package_type=package_type,
                                         output_terms=output_terms, output_data=output_data1,
                                         failed_path=tbv_list)
        return 1

    def inspection_result_output_cs(self, package, elf_count, not_arm_count,
                                    log_type, quiet_mark, json_log_filename, so_final_result=None, failed_list=None,
                                    total_failed=None, sub_file_count=0, incompatible_flag=False):
        """
        Process the file evaluation results, and then format the output.
        param package: -> string
            The absolute path of the compressed package or folder.
        param elf_count: -> int
            The total number of elf files.
        param not_arm_count: -> int
            The total number of non arm files in elf files.
        param log_type: -> string
            Specify the log file format.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        param output_mark: -> None or int
            Screen printout ID.
        param sub_file_count: -> int
            The total number of all subfiles in the detection object.
        return: -> int
            0: can be shared.
            1: cannot be shared.
        """
        write_mode = "a"
        json_arg = "json"
        output_terms = ["NAME", "LOCATION", "MD5", "COMPATIBILITY", "TYPE"]
        arg_list = ["mark_list", "version_list", "pak_arg_list"]
        so_res_keys = ["so_file_list", 'repo_url_list', 'location_list', 'minversion_list']
        output_data1 = ["No", "Yes"]
        conclusion_arg = "Open source"
        complied_arg = "Self-compiled"
        package_value = dp().package_name_processing(package)
        package_name = package_value["name"]
        package_hash = package_value["hash"]

        mark_list = []
        pak_arg_list = []
        version_list = []
        download_list = []
        incompatible_so_list = []

        package_type = df().get_file_precise_type(package)

        package = self.get_zip_path(package)

        if ("" in mark_list or
                not mark_list):
            conclusion_arg = complied_arg

        if so_final_result:
            so_result = self.get_incompatible_so_document(so_final_result)
            incompatible_so_list = so_result[so_res_keys[0]]
            incompatible_so_name_list = [so_file.split('/')[-1] for so_file in incompatible_so_list]

            so_result_data = self.so_result_process(so_result, incompatible_so_name_list)
            mark_list = so_result_data[arg_list[0]]
            version_list = so_result_data[arg_list[1]]
            pak_arg_list = so_result_data[arg_list[2]]
            download_list = so_result.get('repo_url_list', [])

        if elf_count >= 1 or elf_count == 0 and not_arm_count == 0:
            if elf_count == 0 and log_type == json_arg:

                if incompatible_flag is False:
                    self.result_save_json_format(write_mode=write_mode, incompatible_flag=incompatible_flag,
                                                 package_hash=package_hash, json_log_filename=json_log_filename,
                                                 package_type=package_type, output_terms=output_terms,
                                                 output_data=output_data1, package_path=package,
                                                 total_failed=0, incompatible_so_list=[],
                                                 conclusion_arg='', sub_file_count=sub_file_count)
                else:
                    self.result_save_json_format(write_mode=write_mode, package_path=package,
                                                 incompatible_flag=True, sub_file_count=sub_file_count,
                                                 package_hash=package_hash, package_type=package_type,
                                                 conclusion_arg=conclusion_arg, output_terms=output_terms,
                                                 output_data=output_data1, incompatible_so_list=incompatible_so_list,
                                                 mark_list=mark_list, pak_arg_list=pak_arg_list,
                                                 failed_list=failed_list, download_list=download_list,
                                                 version_list=version_list, total_failed=total_failed,
                                                 json_log_filename=json_log_filename)
            return 0

        elif not_arm_count == -1:
            self.failed_files[package] = ""
            self.result_save_fail_format(write_mode=write_mode, txt_arg=log_type, package_path=package,
                                         not_arm_count=not_arm_count, quiet_mark=quiet_mark,
                                         incompatible_flag=False, package_name=package_name,
                                         package_hash=package_hash, package_type=package_type,
                                         output_terms=output_terms, output_data=output_data1)

        return 1

    def threading_executes_java_pom(self, func, **kwargs):
        """
        Build multithreaded execution methods.
        param args:
            function.
        param kwargs:
            The parameter required by the function.
        return:
            Multithreaded execution results.
        """
        number_arg = kwargs["number"]
        log_type_arg = kwargs["log_type"]
        file_list_arg = kwargs["file_list"]
        mark_arg = kwargs["mark"]
        quiet_mark = kwargs["quiet_mark"]
        json_log_filename = kwargs["json_log_filename"]

        multithread_results = []

        thread_pool = ThreadPoolExecutor(max_workers=number_arg)
        threads = [thread_pool.submit(func, file, number_arg,
                                      log_type_arg, mark_arg, quiet_mark,
                                      json_log_filename)
                   for file in file_list_arg]

        for task in as_completed(threads):
            if type(task.result()) is not list:
                multithread_results.append(task.result())
            else:
                multithread_results += task.result()

        thread_pool.shutdown()

        return multithread_results

    def threading_executes(self, func, **kwargs):
        """
        Build multithreaded execution methods.
        param args:
            function.
        param kwargs:
            The parameter required by the function.
        return:
            Multithreaded execution results.
        """
        number_arg = kwargs["number"]
        log_type_arg = kwargs["log_type"]
        file_list_arg = kwargs["file_list"]
        mark_arg = kwargs["mark"]
        quiet_mark = kwargs["quiet_mark"]
        json_log_filename = kwargs["json_log_filename"]
        parent_path = kwargs["parent_path"]

        multithread_results = []

        thread_pool = ThreadPoolExecutor(max_workers=number_arg)
        threads = [thread_pool.submit(func, file, number_arg,
                                      log_type_arg, mark_arg, quiet_mark,
                                      json_log_filename, parent_path)
                   for file in file_list_arg]

        for task in as_completed(threads):
            if not isinstance(task.result(), list):
                multithread_results.append(task.result())
            else:
                if not multithread_results:
                    multithread_results.append(task.result()[0])
                    multithread_results.append(task.result()[1])
                    multithread_results.append(task.result()[2])
                    multithread_results.append(task.result()[3])
                    if self.class_value == 'xarch':
                        multithread_results.append(task.result()[4])
                else:
                    multithread_results[0] += task.result()[0]
                    multithread_results[1] += task.result()[1]
                    multithread_results[2] += task.result()[2]
                    multithread_results[3] += task.result()[3]
                    if self.class_value == 'xarch':
                        multithread_results[4] += task.result()[4]

        thread_pool.shutdown()

        return multithread_results

    def migrated_thread_execute(self, file_list, number, log_type, mark,
                                quiet_mark, json_log_filename):
        """
        Use multithreading to perform check migration tasks.
        param file_list:
            File list.
        param number:
            Use this value to count the number of threads.
        param log_type:
            Specify the log file format.
        param mark: -> boolean
            Indicates whether to evaluate only.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        """
        multithread_execution_results = self.threading_executes(
            self.all_so_result_process,
            file_list=file_list,
            number=number,
            log_type=log_type,
            mark=mark,
            quiet_mark=quiet_mark,
            json_log_filename=json_log_filename,
            parent_path=None
        )

        return multithread_execution_results

    def perform_detection(self, files_list, number, log_type, mark,
                          quiet_mark, json_log_filename):
        """
        According to the number of CPU, create half of the threads and perform multithreading check.
        param files_list:
            The parameter passed in from the command line.
        param number:
            Use this value to count the number of threads.
        param log_type:
            Specify the log file format.
        param mark: -> boolean
            Indicates whether to evaluate only.
        param quiet_mark: -> boolean
            Whether to execute silently or not.
        param json_log_filename: -> string
            The file name for saving the log in json format.
        return:
            Multithreaded execution results.
        """
        summary_info = []
        lock = [True]
        get_cores_info = "grep 'processor' /proc/cpuinfo | sort -u | wc -l"

        get_cores_num = lc().get_command_result(get_cores_info)
        if get_cores_num:
            thread_num = int(get_cores_num) // 2
        else:
            thread_num = 1

        if thread_num == 0:
            thread_num = 1

        if quiet_mark and mark:
            try:
                _thread.start_new_thread(dl().loading, (lock,))
            except Exception as e:
                MyError().display(MyError().report(e, '', "_thread", "start_new_thread"))

        for obj_path in files_list:
            if os.path.isdir(obj_path):
                file_nu_cmd = "find {} -type f -o -type l | wc -l".format(obj_path)
                ret_code, msg = execute_cmd(file_nu_cmd)
                if ret_code == 0:
                    self.file_num += int(msg)
                else:
                    print(msg)
            else:
                self.file_num += 1

        if not self.quiet_mark:
            try:
                constant.schedule_tag = True
                _thread.start_new_thread(progress_bar, (self.file_num, self.total_queue,
                                                        self.inner_queue, 'java'))
            except Exception as e:
                MyError().display(MyError().report(e, '', "_thread", "start_new_thread"))

        # 如果同时检测多个检测对象，则根据是否指定了进程数去判断是否开启多线程。如果同时检测多个对象，则使用多线程检测，
        # 如果检测一个对象或者检测一个对象并指定了进程数，则使用多进程进行检测
        if len(files_list) <= thread_num:
            summary_info = self.migrated_thread_execute(files_list,
                                                        1,
                                                        log_type,
                                                        mark,
                                                        quiet_mark,
                                                        json_log_filename)

        else:
            new_migrate_list = list(map(lambda x: files_list[x * thread_num:x * thread_num + thread_num],
                                        list(range(math.ceil(len(files_list) / thread_num)))))

            for migrate_files_list in new_migrate_list:
                summary_data = self.migrated_thread_execute(migrate_files_list,
                                                            1 if self.processes_number != 1 else thread_num,
                                                            log_type,
                                                            mark,
                                                            quiet_mark,
                                                            json_log_filename)
                if not summary_info:
                    summary_info = summary_data
                else:
                    summary_info = [data1 + data2 for data1, data2 in zip(summary_info, summary_data)]

        lock[0] = False

        return summary_info

    def teardown_operation(self):
        """
        Delete temporary files after detection is complete.
        return: -> None
        """
        try:
            rtcode, output = execute_cmd("rm -rf {}".format(self.ep_temp_files))
            if rtcode != 0:
                logger.info(output, 'java')
        except Exception:
            print_exc()
        return

    def detection_result_summary_output(self, start_time, quiet_arg, execution_results):
        """
        The result summary output after the evaluation task is executed.
        param start_time: -> string
            Evaluate the start time of task execution.
        param quiet_arg: -> boolean
            The judgment result of whether to execute silently.
        param execution_results: -> list
            A list of summary results after the evaluation task is executed.
        return: -> None
        """
        if quiet_arg and execution_results:
            print(self.isolation)

            summary_output = "Java " + constant.summary_output.format(execution_results[0], execution_results[1],
                                                                      execution_results[2], execution_results[4],
                                                                      execution_results[3], sum(execution_results))
            print(summary_output)

            print(self.isolation)

            end_time = time.time()
            run_time = "Total time elapsed {:.3f} Seconds, and average at {:.3f} seconds of each " \
                       "file. \n".format(end_time - start_time, (end_time - start_time) / sum(execution_results)
                                         if sum(execution_results) else 1)

            print(run_time)

        if execution_results:
            summary_log = constant.summary_output.format(execution_results[0], execution_results[1],
                                                         execution_results[2], execution_results[4],
                                                         execution_results[3], sum(execution_results))
            logger.info(summary_log, 'java')

        return

    def detection_result_summary_output_xarch(self, start_time, quiet_arg, execution_results):
        """
        The result summary output after the evaluation task is executed.
        param start_time: -> string
            Evaluate the start time of task execution.
        param quiet_arg: -> boolean
            The judgment result of whether to execute silently.
        param execution_results: -> list
            A list of summary results after the evaluation task is executed.
        return: -> None
        """
        if quiet_arg and execution_results:
            print(self.isolation)
            end_time = time.time()
            total_num = sum(execution_results)
            summary_output = "Java " + constant.summary_output_xarch.format(execution_results[4], execution_results[3],
                                                                            execution_results[0], execution_results[1],
                                                                            execution_results[2], execution_results[5],
                                                                            total_num)
            print(summary_output)
            print(self.isolation)
            run_time = constant.summary_run_time.format(end_time - start_time, (end_time - start_time) / total_num)
            print(run_time)
        if execution_results:
            total_num = sum(execution_results)
            summary_log = constant.summary_output_xarch.format(execution_results[4], execution_results[3],
                                                               execution_results[0], execution_results[1],
                                                               execution_results[2], execution_results[5],
                                                               total_num)
            logger.info(summary_log, 'java')

    def remove_test_result_list_duplicate_values(self):
        """
        Deduplicate the final detection results.
        return: -> None
        """
        self.incompatible_results = sp().filter_list_duplicate_values(self.incompatible_results)
        self.non_test_file_results = sp().filter_list_duplicate_values(self.non_test_file_results)
        self.failed_results = sp().filter_list_duplicate_values(self.failed_results)
        self.compatible_results = sp().filter_list_duplicate_values(self.compatible_results)
        if self.class_value and self.log_type == 'csv':
            if self.compatible_results:
                for index in range(len(self.compatible_results)):
                    del self.compatible_results[index][0]
                    del self.compatible_results[index][0]

            if self.incompatible_results:
                for index in range(len(self.incompatible_results)):
                    del self.incompatible_results[index][0]
                    del self.incompatible_results[index][0]

        return

    def inner_path_print(self, real_path):
        if self.inner_log:
            print('{} done.'.format(real_path))

    def mount_zip_dir_tree(self, zip_tree_node, migrated_path):
        zip_path = list(zip_tree_node.keys())[0]
        if self.ep_temp_files in zip_path:
            zip_real_path = zip_path.split(self.ep_temp_files)[1].strip('/')
        else:
            zip_real_path = zip_path.split(migrated_path)[1].strip('/')
        path_list = zip_real_path.split('/') if zip_real_path else []
        path_list.insert(0, list(self.root_node.keys())[0].rstrip('/'))
        path_list = [re.sub(r'(\.\w+?)\d{1,2}_\d{1,2}$', '', item) for item in path_list]
        insert_flag = insert_children_into_node(self.root_node, path_list, zip_tree_node)
        if not insert_flag:
            real_path = '/'.join(path_list)
            print('{} mount node failed! please check.'.format(real_path))

    def detection_entrance(self, migrated_list):
        """
        General entry for evaluation tasks.
        param migrated_list: -> list
            Parsing results of command line arguments.
        return: -> None
        """
        try:
            self.number = 2
            start_time = time.time()

            # 获取检测任务执行时间戳【标准版化输出用】
            self.execution_detection_time = lc().get_command_result('date')

            # 判断是否可以链接内网
            self.connect_taobao = ping_website('http://rpm.corp.taobao.com/')

            # 解析命令行参数
            detected_object_list = migrated_list[0]  # 检测对象【即-f/-d后跟的检测对象】
            self.detected_file_path = detected_object_list[0]
            self.engine = migrated_list[1]  # 指定检测引擎
            self.log_type = migrated_list[2]  # 指定检测结果的保存格式
            quiet_arg = migrated_list[3]  # 指定是否静默执行
            self.quiet_mark = quiet_arg
            self.recommend_mark = migrated_list[4]  # 指定是否对在数据库没有匹配到的so进行maven、github仓库推荐
            specify_log_name = migrated_list[5]  # 指定的检测结果保存的文件名
            self.class_value = migrated_list[6]  # 指定的--class后跟参数
            if not self.quiet_mark and migrated_list[10]:
                self.inner_log = True
            self.tree_output = migrated_list[15]
            if self.class_value == 'cs':  # 判断--class udf后面参数是否是cs
                self.codescan_json = True
                self.detected_object = detected_object_list
                if self.tree_output:
                    self.dir_tree_path = dir_tree_save_path_init(migrated_list[16], java_current_path, self.time_str)
            self.binary_check = migrated_list[7]  # 指定是否开启对java、class、pom文件进行解析
            self.detection_command = ' '.join(migrated_list[8])  # 执行检测时，完整的命令行执行命令
            specify_temp_path = migrated_list[9]  # 指定的临时文件保存路径
            if specify_temp_path:  # 如果在--temp后面指定了临时文件保存路径，则对下面的临时文件路径进行修改
                self.ep_temp_files = get_absolute_path_from_specified_path(specify_temp_path,
                                                                           java_current_path,
                                                                           self.time_str)
                self.path_file = "{}/".format(self.ep_temp_files)
                self.result_log_file = "{}/result".format(java_current_path)
                self.not_arm_file = "{}/incompat_arm".format(self.ep_temp_files)
                self.arm_file = "{}/compat_arm".format(self.ep_temp_files)
                self.fail_log = "{}/failure".format(self.ep_temp_files)

            self.processes_number = migrated_list[11]  # 指定的多进程的进程数
            if quiet_arg:
                self.warning_check = migrated_list[13]

            self.warning_tag = migrated_list[13]

            try:
                cpu_nu = mp.cpu_count()
                self.processes_number = self.processes_number if self.processes_number <= cpu_nu else cpu_nu
            except Exception:
                self.processes_number = 1

            # 对结果日志保存的文件名进行初始化处理
            self.json_log_filename = self.define_log_save_filename(specify_log_name, self.log_type)

            # 对检测对象进行检测的入口
            execution_results = self.perform_detection(detected_object_list, self.number, self.log_type,
                                                       self.recommend_mark, quiet_arg, self.json_log_filename)

            # 对收集到的检测结果进行去重操作【包含兼容的结果、不兼容的结果、to be verified结果、failed的结果】
            self.remove_test_result_list_duplicate_values()

            # 根据检测结果在屏幕上打印输出summary详情
            warning = self.so_warning_count + self.other_warning_count
            execution_results.append(warning)
            if self.class_value != 'xarch':
                self.detection_result_summary_output(start_time, quiet_arg, execution_results)
            else:
                self.detection_result_summary_output_xarch(start_time, quiet_arg, execution_results)
            # 根据检测结果和指定的log格式输出检测结果日志
            self.detection_result_log_output(self.json_log_filename, self.log_type, specify_log_name,
                                             detected_object_list, execution_results)
            # 当指定了udf，且没有指定引擎时，把检测结果文件名、不带python关键字但包中包含py文件的非jar压缩包传给python引擎
            return self.csv_log_path, self.compressed_to_python
        except Exception as e:
            print(print_exc())
            MyError().display(MyError().report(e, Exception.__name__, "detection_entrance", 'Exec Error'))
        finally:
            self.teardown_operation()
            if not self.quiet_mark:
                constant.schedule_tag = False
                time.sleep(1)
                progress_bar_stop(self.file_num)
                constant.current_rate = 0
