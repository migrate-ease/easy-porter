#!/usr/bin/env python3
# coding=utf-8
import os
import subprocess
import traceback
import fcntl

import magic

from tools.filter_rules import suffix_dict
from tools.utils import find_file_type_by_colon


class DecompressFiles(object):
    def get_command_result(self, command):
        """
        Execute the shell command and return the execution result.
        param command: -> string
            The shell command to be executed.
        return: -> string or None
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

    def execute_cmd(self, cmd):
        """
        Exec linux command and get result.
        param cmd:
            Linux command.
        return:
            code and result.
        """

        returncode, output = subprocess.getstatusoutput(cmd)
        return returncode, output

    def special_archive_filtering(self, engine, document_path):
        """
        Text file processing.
        param engine: -> string
            The engine of the detection function being run.
        param document_path: -> string
            The absolute path of the file to be evaluated.
        return: -> None or string
            None: It is a text file or a special compressed file.
            document_path: It is not a text file or a special compressed file.
        """
        elf_arg = 'elf'
        pkl_arg = 'pkl'
        diy_arg = 'DIY-Thermocam'
        text_arg = 'text'

        java_args = ['java', 'class', 'jar']
        python_args = ['python', 'py', 'pyc']
        special_fields = ['txt', 'json', 'csv', 'js']
        compression_type = ['tar', 'gz', 'gzip', 'zip']
        special_decompress_suffix = ["pptx", "ppt", "rdx", "rds", "npz",
                                     "pyc", "gif", "png", "jpg", "mod",
                                     "dat", "txt", "xml", "sh", "log",
                                     "py", "c", "html", "sql", "pom",
                                     "json", "csv", "dict", "ver", "bin",
                                     "xlsx", "java", "class"]

        document_extension = document_path.split(".")[-1]
        if (engine == python_args[0] and
                document_extension == java_args[2]):
            return

        if (engine.lower() == java_args[0] and
                java_args[0] in special_decompress_suffix):
            special_decompress_suffix.remove(java_args[0])
            special_decompress_suffix.remove(java_args[1])
        elif (engine.lower() == python_args[0] and
              python_args[1] in special_decompress_suffix):
            special_decompress_suffix.remove(python_args[1])
            special_decompress_suffix.remove(python_args[2])

        document_type = self.get_file_type(document_path)
        if document_type:
            document_type_lower = document_type.lower().split(' ')
        else:
            return

        try:
            document_arg = document_path.split(".")[-2]
        except Exception:
            return document_path

        if (elf_arg not in document_type_lower and
                engine.lower() not in document_type_lower and
                text_arg in document_type_lower or
                "{},".format(text_arg) in document_type_lower or
                diy_arg in document_type_lower):

            return

        elif document_extension.lower() in special_decompress_suffix:

            return

        elif (document_arg != compression_type[0] and
              document_arg != compression_type[1] and
              document_extension.lower() == compression_type[1]):

            return document_path

        elif (document_arg == pkl_arg and
              document_extension.lower() == compression_type[2]):

            return

        elif (document_arg in special_fields and
              document_extension.lower() == compression_type[3]):

            return

        return document_path

    def get_file_precise_type(self, pck_path):
        """
        Gets the file type by the path
        param file_path: -> string
            The absolute path of the file.
        return: -> string
            Returns the format of the corresponding file.
        """
        for suffix in suffix_dict:
            if pck_path.endswith(suffix):
                file_type = suffix_dict.get(suffix)
                return file_type
        pck_path = pck_path.replace('$', '\$')
        check_command = 'file "{}"'.format(pck_path)
        res = self.execute_cmd(check_command)
        if res[0] == 0:
            file_type = find_file_type_by_colon(pck_path, res[1])
        else:
            try:
                file_type_str = magic.from_file(pck_path)
                file_type = file_type_str[: file_type_str.find(',')].strip()
            except Exception:
                file_type = 'NULL'

        return file_type

    def get_file_type(self, file_path):
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
            check_type_command = 'file {}'.format(file_path)
            file_type = self.get_command_result(check_type_command)

            return file_type

        try:
            file_type = magic.from_file(file_path)

        except Exception:
            file_type = ''

        return file_type

    def tar_gz_file_decompress(self, pkg_path, zip_unzip_path=None, temporary_file_path=None):
        """
        Special handling of the tar.gz package. Create a folder with the same name.
        param pkg_path:
            The absolute path of the file to be extracted.
        param zip_unzip_path: -> dictionary
            A dictionary formed by the corresponding relationship between the path of
            the decompressed object in the temporary directory and the actual path.
        param temporary_file_path: -> string
            The temporary path where the specified decompressed files are located.
        return:
            result_arg: -> dictionary
                The absolute path of the location where the file is unzipped.
            decompress_command: -> string
                The decompression command to be executed.
            execute_result: -> string
                The result after executing the decompression command.
        """
        execute_result = ''
        decompress_command = ''

        index_repeat_max = 1000
        result_arg = {}
        lock_path = os.path.join(temporary_file_path, "directory.lock")
        try:
            os.makedirs(temporary_file_path, exist_ok=True)
        except Exception:
            traceback.print_exc()
        if not os.path.exists(lock_path):
            open(lock_path, 'a').close()
        # Match the real path of the file by the temporary path.
        if zip_unzip_path:
            zip_paths = list(zip_unzip_path.keys())

            for zip_path in zip_paths:
                if "{}/".format(zip_path) in pkg_path:
                    zip_name = os.path.split(zip_path)[-1]
                    relative_path = pkg_path.split('{}/'.format(temporary_file_path))[-1]
                    suffix_path = relative_path.strip('/').split(zip_name, 1)[-1].strip('/')
                    decompress_path = "{}/{}".format(zip_path, suffix_path)
                    with open(lock_path, 'r') as lock_file:
                        # 获取排他锁
                        fcntl.flock(lock_file, fcntl.LOCK_EX)
                        if not os.path.exists(decompress_path):
                            try:
                                # 如果创建出错，其他进程可能已创建成功，后缀继续进行变更
                                os.makedirs(decompress_path)
                                values = "{}/{}".format(zip_unzip_path[zip_path],
                                                        pkg_path.split('{}/'.format(zip_path))[-1])

                                result_arg["decompress_path"] = decompress_path
                                result_arg["zip_unzip_path"] = values

                                return result_arg, decompress_command, execute_result
                            except Exception:
                                pass
                        for x in range(index_repeat_max):
                            for y in range(index_repeat_max):
                                decompress_path = decompress_path.rstrip("/")
                                decompress_path = "{}{}_{}".format(decompress_path, x, y)
                                if not os.path.exists(decompress_path):
                                    try:
                                        # 如果创建出错，其他进程可能已创建成功，后缀继续进行变更
                                        os.makedirs(decompress_path)
                                    except Exception:
                                        continue
                                    values = (zip_unzip_path[zip_path] +
                                              '/' +
                                              pkg_path.split('{}/'.format(zip_path))[-1])
                                    result_arg["decompress_path"] = decompress_path
                                    result_arg["zip_unzip_path"] = values

                                    return result_arg, execute_result, decompress_command
                        # 释放锁
                        fcntl.flock(lock_file, fcntl.LOCK_UN)

        section = pkg_path.split("/")[-1]

        decompress_path = "{}/{}".format(temporary_file_path, section)

        try:
            with open(lock_path, 'r') as lock_file:
                fcntl.flock(lock_file, fcntl.LOCK_EX)
                flag = False
                if not os.path.exists(decompress_path.rstrip('/')):
                    try:
                        # 如果创建出错，其他进程可能已创建成功，后缀继续进行变更
                        os.makedirs(decompress_path)
                        result_arg["decompress_path"] = decompress_path
                        result_arg["zip_unzip_path"] = pkg_path

                        return result_arg, execute_result, decompress_command
                    except Exception:
                        pass
                for x in range(index_repeat_max):
                    for y in range(index_repeat_max):
                        temporary_file_path = temporary_file_path.rstrip("/")
                        decompress_path = "{}/{}{}_{}".format(temporary_file_path, section, x, y)
                        if not os.path.exists(decompress_path):
                            try:
                                # 如果创建出错，其他进程可能已创建成功，后缀继续进行变更
                                os.makedirs(decompress_path)
                            except Exception:
                                continue
                            flag = True
                            break
                    if flag:
                        break
                fcntl.flock(lock_file, fcntl.LOCK_UN)
        except Exception as e:
            print(e)
        result_arg["decompress_path"] = decompress_path
        result_arg["zip_unzip_path"] = pkg_path

        return result_arg, execute_result, decompress_command

    def decompress_package(self, pkg_path, zip_unzip_path=None, temporary_file_path=None):
        """
        Decompress the compressed package.
        param pkg_path: -> string
            The absolute path of the file to be extracted.
        param zip_unzip_path: -> dictionary
            A dictionary formed by the corresponding relationship between the path of
            the decompressed object in the temporary directory and the actual path.
        param temporary_file_path: -> string
            The temporary path where the specified decompressed files are located.
        return: -> int or dictionary
            decompress_path_result: The decompression information after decompressing the compressed package.
            1: The decompression process is normal and the decompression is successful.
            2: The decompression is successful, but there is an on-screen output after decompression.
            3: If decompression fails, record the information displayed on the screen and return.
        """
        record_info = ''
        decompress_command = ''

        file_extension = pkg_path.split(".")[-1]

        pkg_type = (self.get_file_type(pkg_path)).split(',')[0]
        pkg_section_lower = pkg_type.lower().split(' ')
        decompress_path_result, res, decompress_com = self.tar_gz_file_decompress(pkg_path,
                                                                                  zip_unzip_path,
                                                                                  temporary_file_path)
        if not decompress_path_result:
            mark = 3
            record_info = 'Error:{}:{}.'.format(decompress_com, res.strip('\n'))
            decompress_path_result["record_info"] = record_info
            return mark, decompress_path_result

        decompress_path = decompress_path_result['decompress_path']

        gz_file_name = pkg_path.split('/')[-1]

        if (file_extension == 'tar' or
                (pkg_path.endswith('.tar.gz') and
                 'posix tar' in pkg_type.lower())):

            decompress_command = "tar -xvf '{}' -C '{}' > /dev/null" \
                .format(pkg_path, decompress_path)

        elif "gzip" in pkg_section_lower and "tar" not in pkg_section_lower and ".tar" not in gz_file_name \
                and ".tgz" not in gz_file_name:

            save_file_name = gz_file_name[:gz_file_name.rfind('.')]
            decompress_path = "'{}/{}.txt'".format(decompress_path, save_file_name)
            decompress_command = "gunzip -c '{}' > '{}'".format(pkg_path, decompress_path)

        elif ("tar" in pkg_section_lower or
              "gzip" in pkg_section_lower):
            decompress_command = "tar -zxvf '{}' -C '{}' > /dev/null" \
                .format(pkg_path, decompress_path)

        elif "zip" in pkg_section_lower and (
                gz_file_name.endswith('.egg') or gz_file_name.endswith('.whl') or gz_file_name.endswith('.ear')):
            if not os.path.exists(decompress_path.rstrip('/')):
                decompress_command = "mkdir -p '{}' && unzip -o '{}' -d '{}' > /dev/null" \
                    .format(decompress_path, pkg_path, decompress_path)
            else:
                decompress_command = "rm -rf '{}' && mkdir -p '{}' && unzip -P '' -o '{}' -d '{}' > /dev/null" \
                    .format(decompress_path, decompress_path, pkg_path, decompress_path)

        elif (gz_file_name.endswith('.war') or
              "war" in pkg_section_lower):
            if not os.path.exists(decompress_path.rstrip('/')):
                decompress_command = "mkdir -p '{}' && unzip -o '{}' -d '{}' > /dev/null" \
                    .format(decompress_path, pkg_path, decompress_path)
            else:
                decompress_command = "rm -rf '{}' && mkdir -p '{}' && unzip -P '' -o '{}' -d '{}' > /dev/null" \
                    .format(decompress_path, decompress_path, pkg_path, decompress_path)

        elif ("zip" in pkg_section_lower or
              "(jar)" in pkg_section_lower):

            if not os.path.exists(decompress_path.rstrip('/')):
                decompress_command = "mkdir -p '{}' && unzip -o '{}' -d '{}' > /dev/null 2>&1" \
                    .format(decompress_path, pkg_path, decompress_path)
            else:
                decompress_command = "rm -rf '{}' && mkdir -p '{}' && unzip -P '' -o '{}' -d '{}' > /dev/null 2>&1" \
                    .format(decompress_path, decompress_path, pkg_path, decompress_path)

        elif (gz_file_name.endswith('.bz') or
              "bzip2" in pkg_section_lower):
            if ".tar" in gz_file_name:
                decompress_command = "bunzip2 -c '{}' | tar -C '{}' -xf - > /dev/null".format(pkg_path,
                                                                                              decompress_path)
            else:
                decompress_command = "bzip2 -dk '{}' && mv '{}' '{}' - > /dev/null".format(pkg_path,
                                                                                           pkg_path.replace(".bz2", ''),
                                                                                           decompress_path)
        elif (gz_file_name.endswith('.xz') or "xz" in pkg_section_lower) and ".tar" in gz_file_name:
            decompress_command = "xz -dc '{}' | tar -C '{}' -xf - > /dev/null".format(pkg_path,
                                                                                      decompress_path)

        elif gz_file_name.endswith('.xz') or "xz" in pkg_section_lower:
            decompress_command = "xz -dk '{}' -c > '{}' > /dev/null".format(pkg_path, decompress_path + os.sep +
                                                                            gz_file_name.replace('.xz', ''))

        elif (gz_file_name.endswith('.rpm') or
              "rpm" in pkg_section_lower):
            decompress_command = "rpm2cpio {} | cpio -idmv -D {} > /dev/null".format(pkg_path, decompress_path)

        elif (gz_file_name.endswith('.deb') or
              "deb" in pkg_section_lower):
            decompress_command = "dpkg-deb -x {} {} > /dev/null".format(pkg_path, decompress_path)

        elif gz_file_name.endswith('.lzma') or "lzma" in pkg_section_lower:
            if '.tar' in gz_file_name:
                decompress_command = "tar --lzma -xf '{}' - C '{}'  > /dev/null".format(pkg_path, decompress_path)
            else:
                decompress_command = "unlzma -c '{}' > '{}' > /dev/null".format(pkg_path, decompress_path)

        if decompress_command:
            rt_code, execute_result = self.execute_cmd(decompress_command)

            if rt_code != 0:
                decompress_command = decompress_command.split(" ")[0]
                check_command = 'type {}'.format(decompress_command.strip("'").strip('"'))
                type_rtcode, stdout = self.execute_cmd(check_command)
                if "decompression OK" in execute_result:
                    # IO
                    mark = 2
                    record_info = 'IO {}:{}.'.format(decompress_command, execute_result.strip('\n'))
                elif 'error' in execute_result.lower() or 'failed' in execute_result.lower():
                    # Error
                    mark = 3
                    record_info = 'Error {}:{}.'.format(decompress_command, execute_result.strip('\n'))
                elif type_rtcode != 0 or 'not found' in stdout:
                    # Missing command
                    mark = 5
                    record_info = 'Missing command:{}:{}.'.format(decompress_command, execute_result.strip('\n'))
                else:
                    mark = 1
            else:
                mark = 1
        else:
            # Skipped
            mark = 4
            record_info = 'Skipped {}:Need to be verified.'.format(pkg_path)
        # 解压成功，给解压后目录添加权限
        if mark in [1, 2]:
            command_r = 'chmod -R 700 {}'.format(decompress_path)
            rtcode, stdout = self.execute_cmd(command_r)
            if rtcode != 0:
                record_info += stdout.strip('\n')
        decompress_path_result["record_info"] = record_info
        return mark, decompress_path_result
