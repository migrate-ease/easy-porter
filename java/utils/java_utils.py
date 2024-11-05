#!/usr/bin/env python3
# coding=utf-8
from __future__ import print_function

import os
import csv
import json

from concurrent.futures import ThreadPoolExecutor

from tools.constant import constant, jdk_import
from tools.error import MyError
from tools.decompressor import DecompressFiles as df
from tools.utils import *

logger = constant.logger


class DocumentProcessing:
    """
    This is a class that mainly deals with files. It can create files,
    read and write files, obtain file types, obtain file hash values,
    process file names, determine whether a file or folder exists,
    traverse the entire folder to obtain all sub file paths, and so on.
    """

    def file_read_write(self, file_path, mode, log_type, content=None):
        """
        Save the file according to the format type.

        param file_path: -> string
            The absolute path of the file to be opened.
        param mode: -> string
            Read or write or append operations.
        param log_type: -> string
            Set the format type of the saved result file. For example: csv, json, txt.
        param content: -> list or json or string
            Content to be saved.
        return:
            In the read mode, the read content is returned as a list type.
        """
        if log_type == "txt":
            log_name = "{}.log".format(file_path)
            if not os.path.exists(log_name):
                create_log_command = 'touch "{}"'.format(log_name)
                subprocess.call(create_log_command, shell=True)

            try:
                with open(log_name, mode, encoding='utf-8', errors="surrogatepass") as f:

                    if mode == 'r':
                        return [i.strip('\n') for i in f.readlines() if len(i) != 0]
                    f.write(content + '\n')
            except FileNotFoundError as e:
                MyError().display(MyError().report(e, FileNotFoundError.__name__, "open", log_name))
                if mode == 'r':
                    return []

        elif log_type == "csv":
            csv_name = "{}.csv".format(file_path)
            try:
                with open(csv_name, mode, encoding='utf_8_sig', newline="", errors="surrogatepass") as c:
                    f_csv = csv.writer(c)
                    f_csv.writerow(content)
            except FileNotFoundError as e:
                MyError().display(MyError().report(e, FileNotFoundError.__name__, "open", csv_name))

        elif log_type == "json":
            json_name = "{}.json".format(file_path)
            try:
                with open(json_name, mode, encoding='utf-8', errors="surrogatepass") as j:

                    if os.path.getsize("{}.json".format(file_path)) != 0:
                        j.write(',\n')

                    json.dump(content, j, ensure_ascii=False, indent=2)
                    j.flush()
            except FileNotFoundError as e:
                MyError().display(MyError().report(e, FileNotFoundError.__name__, "open", json_name))

        return

    def traverse_folder(self, file_path, save_path_file, class_value=None, real_path=None, ep_temp_files=None):
        """
        Traverse the folder to view all the files in the folder.

        param file_path: -> string
            The absolute path of the folder to be traversed.
        param save_path_file: -> string
            A specific file that saves the absolute path of all files in the folder.
        return: -> number
            0: means success.
            1: means failure.
        """
        if os.path.isdir(file_path):

            for root, dirs, files in os.walk(file_path):
                if class_value == 'cs':
                    dirs[:] = [d for d in dirs if not self.skip_non_detection_dir(root, d, real_path, ep_temp_files)]
                for file in files:
                    doc_path = os.path.join(root, file)

                    self.file_read_write(file_path=save_path_file,
                                         mode="a",
                                         log_type="txt",
                                         content=doc_path)

        else:
            self.file_read_write(file_path=save_path_file,
                                 mode="a",
                                 log_type="txt",
                                 content=file_path)

        return 0

    def skip_non_detection_dir(self, project, detection_dir, real_path, ep_temp_files):
        """
        Skip default directory detection for Mac, Windows, etc
        :param project: parent dir

        :param detection_dir: directory for detection
        :return:
        """
        if detection_dir.lower() in constant.ignored_list:
            warn_path = os.path.join(project, detection_dir)
            if real_path:
                warn_path_real = warn_path.replace(ep_temp_files, os.path.split(real_path)[0])
            logger.info('Warning4 {}.'.format(warn_path_real), 'java')
            return True
        return False

    def get_dir_files(self, dir_path, real_path, ep_temp_files, class_value):
        file_path_list = []
        for root, dirs, files in os.walk(dir_path):
            if class_value == 'cs':
                dirs[:] = [d for d in dirs if not self.skip_non_detection_dir(root, d, real_path, ep_temp_files)]
            for file in files:
                doc_path = os.path.join(root, file)
                file_path_list.append(doc_path)
        return file_path_list

    def get_decompress_file_path(self, file_path):
        """
        Obtain the absolute path of the unzipped file.
        param file_path: -> string
            The absolute path of the file to be extracted.
        return: -> boolean or string
            Returns the results of shell script execution.
        """
        temp_files = os.path.expanduser('~/tmp/easyPorter')
        decompress_path = "{}/ep_tmp".format(temp_files)
        file_extension_args1 = ['so', 'json']

        if (os.path.isdir(file_path) or
                file_extension_args1[0] in file_path.split('.') or
                file_path.split('.')[-1] in file_extension_args1):
            return file_path

        else:
            file_name = file_path[file_path.rfind('/') + 1:]
            cmd = "ls '{}' | grep -w '^{}$'".format(decompress_path, file_name)
            result = LinuxCommandExecute().get_command_result(cmd)

            if not result:
                return False

            decompress_file_name = result.split('\n')[0]
            new_file_path = "{}/{}".format(decompress_path, decompress_file_name)

            if os.path.isdir(new_file_path) and len(result.split('\n')) == 1:
                return new_file_path

            else:
                return False

    def create_csv_log(self, log_file, csv_header_info, log_type):
        """
        Create a csv file and specify the first line information.
        param log_file: -> string
            The path of the log file to be saved.
        param csv_header_info: -> list
            The header information of the csv log file.
        param log_type: -> string
            Specify the log file format. In this case, it should be in csv format.
        return: -> None
        """
        writing_mode = 'a'
        file_type = "csv"

        if log_type == file_type:
            self.file_read_write(log_file, writing_mode, file_type, csv_header_info)

        return

    def get_package_type(self, pck_path):
        """
        Gets the type of the package.
        param pck_path: -> string
            The absolute path of the package.
        return: -> string
            jar_arg1: The package type is jar.
            so_parameter: The package type is so binary.
            compressed_arg: The package type is compressed file.
        """
        jar_arg1 = "jar"
        jar_arg2 = "(jar)"
        so_arg = "so"
        elf_arg = "elf"
        zip_arg = "zip"
        gzip_arg = "gzip"
        compressed_arg = "compressed file"
        so_parameter = "so binary"
        directory_arg = "directory"
        other_file_arg = "other file types"

        if os.path.isfile(pck_path):
            file_type = df().get_file_type(pck_path).split(',')[0]
            if file_type:
                pkg_section_lower = file_type.lower().split(' ')
            else:
                return ''

            trailing_arg = pck_path.split(".")[-1]

            if (jar_arg1 in trailing_arg or
                    jar_arg2 in pkg_section_lower):

                return jar_arg1

            elif (trailing_arg == so_arg or
                  elf_arg in pkg_section_lower):

                return so_parameter

            elif (zip_arg in pkg_section_lower or
                  gzip_arg in pkg_section_lower):

                return compressed_arg

            return other_file_arg

        return directory_arg

    def package_name_processing(self, pck_path, class_value=False):
        """
        Package name processing. To get the so file name with lib and so removed.
        param pck_path: -> string
            The absolute path of the package.
        return: -> dictionary
            hash: Hash value of so package.
            name: The file name after so package processing.
        """

        package_hash = ""
        if not os.path.isdir(pck_path) and not class_value:

            try:
                pck_path.encode('utf-8')
                package_hash = get_file_md5(pck_path)
            except Exception:
                pck_path = pck_path.encode('utf-8', 'ignore').decode('utf-8', 'ignore') + '?'
                package_hash = 'E0000000000000000000000000000001'

        package_name = pck_path.split("/")[-1]
        package_value = {"hash": package_hash, "name": package_name}

        return package_value

    def check_folder_exist(self, folder_path):
        """
        Determine whether the file or folder exists. If it does not exist, create it.
        param folder_path: -> string
            The absolute path of the file or folder.
        return: -> None
        """
        if not os.path.exists(folder_path):
            create_floder_command = "mkdir -p {}".format(folder_path)
            subprocess.call(create_floder_command, shell=True)

        return

    def filter_so_binary_file(self, file_paths, schedule, quiet_mark):
        """
        Filter so files.
        param file_paths: -> str or list
            The file path or list of file paths to be filtered.
        return: -> list
            The filtered so file.
        """
        elf_type_list = ['jnilib', 'Windows lib', 'Windows dll', 'Mac lib', 'lib']
        new_file_paths = []
        for file in file_paths:
            file_type = get_file_type_by_suffix(file)
            file_type_by_cmd = get_file_real_type(file)
            file_type_cmd_lower = file_type_by_cmd.lower()
            if file_type == "ELF" or file_type in elf_type_list or 'elf' in file_type_cmd_lower:
                if not quiet_mark:
                    schedule.put(1)
                new_file_paths.append(file)
        return new_file_paths

    def filter_special_zip_package(self, file_path):
        """
        Filter files of special compression types.
        param file_path: -> string
             Files to be filtered.
        return: -> boolean
        """
        decompress_types = ["tar", "gzip", "jar", "zip", "(jar)"]
        standard_package_suffix = ["tar", "zip", "gz", "gzip", "tgz", "jar"]

        document_extension = file_path.split(".")[-1]
        file_type_lower = file_path.lower().split()
        if ((decompress_types[0] in file_type_lower or
             decompress_types[1] in file_type_lower or
             decompress_types[2] in file_type_lower or
             decompress_types[3] in file_type_lower or
             decompress_types[4] in file_type_lower) and
                document_extension not in standard_package_suffix):
            return True
        return False

    def filter_standard_zip_package(self, file_path):
        """
        Filter files of special compression types.
        param file_path: -> string
             Files to be filtered.
        return: -> boolean
        """
        decompress_types = ["tar", "gzip", "jar", "zip", "(jar)"]
        standard_package_suffix = ["tar", "zip", "gz", "gzip", "tgz", "jar"]

        document_extension = file_path.split(".")[-1]
        file_type = df().get_file_type(file_path)
        if file_type:
            file_type_lower = file_type.lower().split()
            if ((decompress_types[0] in file_type_lower or
                 decompress_types[1] in file_type_lower or
                 decompress_types[2] in file_type_lower or
                 decompress_types[3] in file_type_lower or
                 decompress_types[4] in file_type_lower) and
                    document_extension in standard_package_suffix):
                return True
        return False


class LinuxCommandExecute:
    """
    The class that executes linux commands.
    """

    def get_command_result(self, command):
        """
        Execute the shell command and return the execution result.

        param command: -> string
            The shell command to be executed.
        return: -> string
            Returns the execution result.
        """
        try:
            child = subprocess.Popen("{} 2>&1".format(command),
                                     shell=True,
                                     stdout=subprocess.PIPE,
                                     stdin=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     encoding='GBK')
            child.wait()
            return child.stdout.read().strip('\n')
        except Exception:
            return None


class DynamicLoading:
    """
    This is a class that prompts the waiting process of a class or function.
    """

    def loading(self, lock):
        """
        Dynamic display during waiting.
        param lock: -> list
            Dynamic display wait switch.
        return: -> None
        """
        while lock[0]:
            time.sleep(5)
            print("\rSearching", end="")
            for i in range(6):
                print(".", end='', flush=True)
                time.sleep(1)
        return


class StringProcessing:
    """
    This is a class that handles strings.
    It contains the data you want to extract from the string,
    and you can also classify it.
    """

    def get_so_document(self, package_path, file_path):
        """
        Get all so files in the jar package.
        param package_path: -> list
            The absolute path of the jar package.
        param file_path: -> string
            The absolute path of the extracted jar package.
        return: -> dictionary
            All so packages in the jar package.
        """
        so_documents = []

        package = package_path[0]
        package_name = package.split("/")[-1]

        elf_type_list = ['jnilib', 'Windows lib', 'Windows dll', 'Mac lib', 'lib']

        for files in file_path:
            file_type = get_file_type_by_suffix(files)
            file_type_by_cmd = get_file_real_type(files)
            file_type_lower = file_type_by_cmd.lower()
            tag = check_file(file_type_lower)
            if (file_type == "ELF" or file_type in elf_type_list or 'elf' in file_type_lower or (tag is True and compatible_file not in file_path)) and \
                    not list(filter(lambda x: x.lower() in file_type_lower, compatible_default_list)):
                so_documents.append(files)

        package_so_document = {package_name: so_documents}

        return package_so_document

    def so_document_classification(self, so_documents):
        """
        Sort so packages by package name.
        param so_documents: -> dictionary
            All so filesets in the entire jar package.
        return: -> dictionary
            so_document_dic: A sorted set of so package files.
        """
        parent_project_so = {}
        for so_path in so_documents:
            so_name_group = get_group_name(so_path)
            parent_project = so_path[:so_path.rfind('/')]
            # 查找路径中包含 系统架构的路径
            sys_name = re.findall('|'.join(sys_architecture_list), so_path, re.I)
            if sys_name:
                parent_project = so_path.split(sys_name[0])[0].rstrip('/')
            if parent_project not in parent_project_so:
                parent_project_so[parent_project] = dict()
            if so_name_group not in parent_project_so[parent_project]:
                parent_project_so[parent_project][so_name_group] = []
            parent_project_so[parent_project][so_name_group].append(so_path)

        return parent_project_so

    def get_jar_name(self, jar_file_name):
        """
        Process the jar file name to be recommended and make it a search keyword.
        param name: -> string
            The jar file name to be processed.
        return: -> string
            Processed keywords to be searched
        """
        jar_name = None
        # 去除后缀
        if '.' in jar_file_name:
            jar_name = jar_file_name.split('.')[0]
        # 去除数字及前后_-=
        re_str = "(.*?)[\=\-_\.0-9]*?\..*?"
        result = re.findall(re_str, jar_name)
        if result and result[0]:
            jar_name = result[0]
        return jar_name

    def version_compare(self, so_version, recommend_version):
        """
        The corresponding version of the so file is compared with the warehouse version.
        param so_version: -> string
            so file corresponds to the version.
        param recommend_version: -> string
            The recommended version of the maven repository.
        return: -> boolean
            True:
                Indicates that the warehouse version is greater than
                the corresponding version of the so file.
            False:
                Indicates that the warehouse version is less than or equal
                to the corresponding version of the so file.
        """
        so_version_arg = None
        recommend_version_arg = None

        so_version_list = so_version.split('.')
        recommend_version_list = recommend_version.split('.')

        if len(so_version_list) != len(recommend_version_list):
            length_difference = len(so_version_list) - len(recommend_version_list)

            for i in range(abs(length_difference)):
                if length_difference > 0:
                    recommend_version_list.append('0')

                else:
                    so_version_list.append('0')

        for index in range(len(so_version_list)):
            try:
                so_version_arg = int(so_version_list[index])
                recommend_version_arg = int(recommend_version_list[index])

            except Exception:
                so_version_arg = so_version_list[index].split('-')[0]
                recommend_version_arg = recommend_version_list[index].split('-')[0]

            finally:
                if so_version_arg < recommend_version_arg:
                    return True

                elif so_version_arg > recommend_version_arg:
                    return False
        return False

    def filter_list_duplicate_values(self, filtered_list):
        """
        Deduplicate the values in the list [unable to remove duplicate values by set].
        param filtered_list: -> list
            The list to filter.
        return: -> list
            Filter the processed list.
        """
        set_filter = list(set(map(lambda x: tuple(map(str, x)), filtered_list)))
        new_list = [list(set_arg) for set_arg in set_filter]
        return new_list


class StandardLog(object):

    def execute_log_records(self, log_file_path, file_path):
        """
        During the record detection process, the detection is skipped,
        the decompression fails, and the linux command is executed to display the output log.
        param log_file_path: -> string
            The absolute path of the log file to be recorded.
        param file_path: -> string
            The absolute path of the detection file to be recorded,
            or the Linux command to be executed.
        return: -> None
        """
        write_mode = 'a'
        log_type = 'txt'

        record_info = 'Skipped:{}:Need to be verified.'.format(file_path)
        if log_file_path:
            DocumentProcessing().file_read_write(log_file_path, write_mode,
                                                 log_type, content=record_info)
        return


def java_normalized_output(detection_object, execution_results,
                           detection_command, execution_detection_time, engine, log_mark=False):
    detailed_arg = "Detailed Results as Follows:"
    engine_list = ["java", "python"]
    scanned_format_list = ["Scanned Infos:", "OBJECTS(-f/-d)", "COMMAND",
                           "EXECUTOR(whoami)", "TIME(date)"]
    summary_format_list = ["Summary:", "COMPATIBLE", "INCOMPATIBLE",
                           "TO BE VERIFIED", "OTHERS", "TOTAL"]
    execute_format_list = ["Executed Configuration:", "NODE(uname -n)", "CPU(uname -p)",
                           "OS(lsb_release -d)", "KERNEL(uname -r)"]
    txt_format_list = ["PROJECT", "LOCATION", "NAME", "MD5", "CATEGORY", "TYPE",
                       "INCOMPATIBILITY", "ADVICE", "UPGRADE", "PACKAGE",
                       "VERSION", "FROM", "DOWNLOAD", "ACTION"]

    who_info = LinuxCommandExecute().get_command_result('whoami')
    node_info = LinuxCommandExecute().get_command_result('uname -n')
    cpu_info = LinuxCommandExecute().get_command_result('uname -p')
    os_info = LinuxCommandExecute().get_command_result('lsb_release -d').split(':')[-1].strip(' ')
    kernel_info = LinuxCommandExecute().get_command_result('uname -r')

    detection_object = detection_object if detection_object is not None else ''
    detection_command = detection_command if detection_command is not None else ''
    who_info = who_info if who_info is not None else ''
    execution_detection_time = execution_detection_time if execution_detection_time is not None else ''

    scanned_info = ["", "\n".join(detection_object), detection_command,
                    who_info, execution_detection_time]

    if engine == engine_list[0]:
        summary_format_list = ["Summary:", "COMPATIBLE", "INCOMPATIBLE",
                               "TO BE VERIFIED", "OTHERS", "WARNING", "TOTAL"]
        summary_info = ["", execution_results[0], execution_results[1],
                        execution_results[2], execution_results[3], execution_results[4], sum(execution_results)]
    elif engine == engine_list[1]:
        summary_info = ["", str(execution_results[0]), str(execution_results[1]), str(execution_results[2]),
                        str(execution_results[3]), str(execution_results[4])]
    else:
        summary_info = []

    execute_info = ["", node_info, cpu_info, os_info, kernel_info]

    scanned_format_list = ';'.join(scanned_format_list)
    scanned_info = ';'.join(scanned_info)
    summary_format_list = ';'.join(summary_format_list)
    summary_info = ';'.join([str(summary_data) for summary_data in summary_info])
    execute_format_list = ';'.join(execute_format_list)
    execute_info = ';'.join(execute_info)
    header_info = ';'.join(txt_format_list) + ';\n'
    if log_mark:
        txt_standard_output_header = [scanned_format_list, scanned_info, summary_format_list,
                                      summary_info, execute_format_list, execute_info]
    else:
        txt_standard_output_header = [scanned_format_list, scanned_info, summary_format_list,
                                      summary_info, execute_format_list, execute_info, detailed_arg,
                                      header_info]

    return txt_standard_output_header


def analysis_java_import(file_path):
    import_class_file_name = []
    if file_path.endswith('.class'):
        ret, file_text = decompile_class(file_path)
        if ret:
            import_class_file_name = class_result_resolution(file_text)
        return import_class_file_name

    if file_path.endswith(".java"):
        parse_java_command = "cat {} | grep ^import".format(file_path)
    else:
        parse_java_command = ''

    parse_result = LinuxCommandExecute().get_command_result(parse_java_command)
    if parse_result:
        source_file_parse_result = parse_result.split(';\n')
    else:
        return import_class_file_name

    if source_file_parse_result[0]:
        for class_file in list(set(source_file_parse_result)):
            if (class_file.split(' ')[0] != 'import' or
                    'from' in class_file.split(' ') or
                    '"' in class_file or
                    '@' in class_file):
                continue
            import_data = class_file.split(' ')[-1].rstrip(';').replace('.', '/').strip(' ').strip("'").strip('"')
            if import_data not in import_class_file_name:
                import_class_file_name.append(import_data)

    return import_class_file_name


def get_java_file(document, path_list):
    java_file_arg = "java class data"
    java_source_arg = "java source"
    java_list = []
    if isinstance(path_list, list) and path_list:
        for document in path_list:
            file_type = df().get_file_type(document).split(',')[0]
            file_type_lower = file_type.lower()
            if (java_file_arg in file_type_lower and document.endswith(".class")) or (java_source_arg in file_type_lower and document.endswith(".java")):
                java_list.append(document)
    else:
        file_type = df().get_file_type(document).split(',')[0]
        file_type_lower = file_type.lower()
        if (java_file_arg in file_type_lower and document.endswith(".class")) or (java_source_arg in file_type_lower and document.endswith(".java")):
            java_list.append(document)
    return java_list


def extract_string_with_uppercase(text):
    """Remove Java or class import package class names"""
    try:
        match = re.search('[A-Z]', text)
        if match:
            slicing_data = text[:match.start()]
            if slicing_data.endswith(os.sep):
                slicing_data = slicing_data.rstrip(os.sep)
            return slicing_data
        if text.endswith("/*"):
            text = text.replace("/*", "")
        return text
    except Exception:
        return text


def get_import_data(document, path_list, cfr_jar_path, processes_number=1):
    import_data = list()
    java_list = get_java_file(document, path_list)
    with ThreadPoolExecutor(4) as t:
        result = t.map(analysis_java_import, java_list)
    for item in result:
        if item:
            import_data.extend(list(item))
    import_data = list(map(lambda x: extract_string_with_uppercase(x), import_data))
    import_data = list(filter(lambda x: not [i for i in path_list if x in i], import_data))  # 筛选出非java程序自身的导包
    import_data = [import_file.replace('/', '.') for import_file in import_data]  # 输出导包的格式
    # 筛选出JDK自带的
    import_data = list(set(import_data))
    new_import_data = []
    for item in import_data:

        if item.startswith("java.") or item.startswith("javax.") or item.startswith("sun.") or item in jdk_import\
                or item.startswith("com.sun.") or item.startswith("jdk."):
            continue
        else:
            new_import_data.append(item)
    return new_import_data


def check_file(file_type_by_cmd):
    get_flag = False
    for incompatible_flag in incompatible_default_list:
        if incompatible_flag in file_type_by_cmd.lower():
            get_flag = True
    return get_flag
