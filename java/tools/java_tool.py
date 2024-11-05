#!/usr/bin/env python3
# coding=utf-8
import os.path
import math

import pathlib
import subprocess

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed

from java.utils.java_utils import DocumentProcessing as dp
from java.utils.java_utils import LinuxCommandExecute as lc
from tools.decompressor import DecompressFiles as df

current_path = os.getcwd()


class JavaTool(object):
    """
    This class is mainly used to check the compatibility of packages obtained from
    the warehouse during the SO package recommendation process.
    """

    def __init__(self):
        self.path_file = "{}/".format(current_path.split('java')[0])

    def path_exist(self, file_path):
        """
        Judge whether the entered package or source code path exists.
        """
        for file in file_path:
            path = pathlib.Path(file)
            try:
                assert path.exists()
            except Exception:
                raise RuntimeError("This file path does not exist, please check and re execute!")
            else:
                file_save_path = "{}file_path_{}".format(self.path_file, file.split('/')[-1])
                return dp().traverse_folder(file, file_save_path)

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
        file_type = df().get_file_type(file_path)
        try:
            assert file_type
        except Exception:
            raise RuntimeError("The corresponding type of the file cannot be found!")
        else:
            return (1, file_path) if "aarch64" not in file_type else (0, 0)

    def tar_gz_file_decompress(self, decompress_path, pkg_path):
        """
        Special handling of the tar.gz package. Create a folder with the same name.
        param decompress_path:
            The parent path of the file to be extracted.
        param pkg_path:
            The absolute path of the file to be extracted.
        return:
            The absolute path of the location where the file is unzipped.
        """
        section = pkg_path.split("/")[-1]
        path_section = section.split(".")
        if "tar" in path_section and "gz" in path_section:
            decompress_path = "{}/{}/".format(decompress_path, section.split('.tar')[0])

            if not os.path.exists(decompress_path):
                subprocess.call("mkdir {}".format(decompress_path), shell=True)
            else:
                subprocess.call("rm -rf {} && mkdir {}".format(decompress_path,
                                                               decompress_path), shell=True)

        return decompress_path

    def decompress_package(self, pkg_path):
        """
        Decompress the compressed package.
        param pkg_path: -> string
            The absolute path of the file to be extracted.
        return: -> boolean
            True: means the decompression is successful.
            False: means decompression failed.
        """
        pkg_section_lower = []

        pkg_type = (df().get_file_type(pkg_path)).split(',')[0]
        if pkg_type:
            pkg_section_lower = pkg_type.lower().split(' ')

        if "tar" in pkg_section_lower or "gzip" in pkg_section_lower:
            decompress_file_path = pkg_path[:pkg_path.rfind('/')]
            decompress_path = self.tar_gz_file_decompress(decompress_file_path, pkg_path)
            decompress_command = "tar -xf {} -C {} > /dev/null 2>&1" \
                .format(pkg_path, decompress_path)
            subprocess.call(decompress_command, shell=True)
            return True
        elif "zip" in pkg_section_lower or "(jar)" in pkg_section_lower:
            decompress_file_path = pkg_path[:pkg_path.rfind('.')]
            create_pkg = self.tar_gz_file_decompress(decompress_file_path, pkg_path)

            if not os.path.exists(create_pkg):
                decompress_command = "mkdir {} && unzip -o {} -d {} > /dev/null 2>&1" \
                    .format(create_pkg, pkg_path, create_pkg)
            else:
                decompress_command = "rm -rf {} && mkdir {} && unzip -o {} -d {} > /dev/null 2>&1" \
                    .format(create_pkg, create_pkg, pkg_path, create_pkg)

            subprocess.call(decompress_command, shell=True)
            return True
        else:
            print("Unsupported package, pkg_path: {}".format(pkg_path))
            return False

    def elf_file_check(self, file_path, number, log_type):
        """
        If elf type files meet the requirements of aarch64.
        param file_path:
            The absolute path of the file to be detected.
        param number:
            Specifies the number of threads at the time of detection.
        param log_type:
            Log save format.
        return:
            Returns a dictionary formed by detection results.
        """
        elf_count = 0
        not_arm_count = 0
        incompatible_file_list = []
        file_type_lower = []

        file_type = df().get_file_type(file_path).split(',')[0]
        if file_type:
            file_type_lower = file_type.lower().split(' ')

        if "elf" in file_type_lower:
            check_result, incompatible_file = self.check_aarch64_exist(file_path)
            if check_result == 0:
                elf_count += 1
            else:
                incompatible_file_list.append(incompatible_file)
                not_arm_count += 1
        elif ("zip" in file_type_lower or
              "gzip" in file_type_lower or
              "tar" in file_type_lower or
              "jar" in file_type_lower or
              "(jar)" in file_type_lower):
            self.check_package_compatible(file_path, number, log_type)
        return {"elf_count": elf_count,
                "not_arm_count": not_arm_count,
                "incompatible_file_list": incompatible_file_list}

    def check_package_compatible(self, package_path, number, log_type, github_mark=None):
        """
        Check whether the compressed package meets the migration requirements.
        param package_path:
            The absolute path of the file to be extracted.
        param number:
            Specifies the number of threads at the time of detection.
        param log_type:
            Log save format.
        return:
            The file path after decompression, which can be shared, can not be shared,
        and can not be shared file list.
        """
        elf_values = 0
        not_arm_count = 0
        incompatible_file_list = []

        if not os.path.isdir(package_path):
            self.decompress_package(package_path)
        decompress_file_path = [dp().get_decompress_file_path(package_path)]

        if decompress_file_path[0]:
            decompress_result = self.path_exist(decompress_file_path)
            if decompress_result == 0:
                path_list = dp().file_read_write(
                    "{}file_path_{}".format(self.path_file, decompress_file_path[0].split('/')[-1]),
                    "r",
                    "txt")
                file_path_list = [path for path in path_list if decompress_file_path[0] in path]

                parameter = self.threading_executes(self.elf_file_check, number=number,
                                                    log_type=log_type, file_list=file_path_list)

                for par in parameter:
                    elf_values += par["elf_count"]
                    if par["not_arm_count"] == 1:
                        not_arm_count += 1
                        incompatible_file_list += par["incompatible_file_list"]
                if len(incompatible_file_list) > 0 and elf_values == 0:
                    return self.incompatible_package_handling(decompress_file_path[0])
                else:
                    return self.inspection_result_output(decompress_file_path[0],
                                                         elf_values, not_arm_count, github_mark)
            else:
                return self.inspection_result_output(decompress_file_path[0],
                                                     0, -1, github_mark)
        else:
            return self.inspection_result_output(decompress_file_path[0],
                                                 0, -1, github_mark)

    def incompatible_package_handling(self, files):
        """
        Dispose of packages that do not meet the requirements.
        param files: -> string
            The folder path after the compressed package is extracted.
        return: -> boolean
            False: Identification of nonconformity.
        """
        search_file = lc().get_command_result("ls {} | grep {}"
                                              .format(files[:files.rfind('/')], files.split('/')[-1]))
        if os.path.isdir(files) and len(search_file.split("\n")) > 1:
            subprocess.call("rm -rf {}".format(files), shell=True)

        return False

    def inspection_result_output(self, files, elf_count, not_arm_count, github_mark=None):
        """
        Process the file evaluation results, and then format the output.
        param files: -> string
            The absolute path of the extracted file.
        param elf_count: -> int
            The total number of elf files.
        param not_arm_count: -> int
            The total number of non arm files in elf files.
        return: -> boolean
            True: can be shared.
            False: cannot be shared.
        """
        if not files:
            return False

        search_file = lc().get_command_result("ls {} | grep {}"
                                              .format(files[:files.rfind('/')], files.split('/')[-1]))
        if os.path.isdir(files) and len(search_file.split("\n")) > 1:
            subprocess.call("rm -rf {}".format(files), shell=True)

        if (elf_count >= 1 or elf_count == 0 and
                not_arm_count == 0 and
                not github_mark):
            return True

        return False

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
        multithread_results = []
        thread_pool = ThreadPoolExecutor(max_workers=number_arg)
        threads = [thread_pool.submit(func, file, number_arg, log_type_arg)
                   for file in file_list_arg]
        for task in as_completed(threads):
            multithread_results.append(task.result())
        thread_pool.shutdown()
        return multithread_results

    def migrated_thread_execute(self, file_list, number, log_type, github_mark=None):
        """
        Use multithreading to perform check migration tasks.
        param file_list:
            File list.
        param number:
            Use this value to count the number of threads.
        param log_type:
            Specify the log file format.
        """

        multithread_execution_results = []
        for file in file_list:
            results = self.check_package_compatible(file, number, log_type, github_mark)
            multithread_execution_results.append(results)
        if len(multithread_execution_results) > 0:
            return multithread_execution_results

    def custom_execution(self, files_list, number, log_type, github_mark=None):
        """
        According to the number of CPU, create half of the threads and perform multithreading check.
        param files_list:
            The parameter passed in from the command line.
        param number:
            Use this value to count the number of threads.
        param log_type:
            Specify the log file format.
        return:
            Multithreaded execution results.
        """
        get_cores_info = "grep 'processor' /proc/cpuinfo | sort -u | wc -l"
        get_cores_num = lc().get_command_result(get_cores_info)
        thread_num = int(get_cores_num) // number
        execution_res = []
        if thread_num == 0:
            thread_num = 1
        if len(files_list) <= thread_num:
            execution_res = self.migrated_thread_execute(files_list,
                                                         thread_num,
                                                         log_type,
                                                         github_mark)
        else:
            new_migrate_list = list(map(lambda x: files_list[x * thread_num:x * thread_num + thread_num],
                                        list(range(math.ceil(len(files_list) / thread_num)))))
            for migrate_files_list in new_migrate_list:
                result_list = self.migrated_thread_execute(migrate_files_list,
                                                           thread_num,
                                                           log_type,
                                                           github_mark)
                execution_res += result_list
        return execution_res
