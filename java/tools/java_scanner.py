#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/1/31 13:35
# file: java_scanner.py
import copy
import subprocess
import os
import xml.etree.ElementTree as et

from java.utils.java_utils import LinuxCommandExecute
from java.utils.java_utils import DocumentProcessing as dp
from tools.decompressor import DecompressFiles as df
from tools.utils import decompile_class, class_result_resolution


class ScanSoDependencies(object):

    def get_jar_so_relation(self, jar_so_list):
        """
        Output the dependent so in the jar package according jar_so_list
        param jar_so_list: -> dict
            List of so contained in jar package.
        return: -> dict
            The type of so.
        """
        depenc_path_list = []
        depenc_name_list = []

        for jar_dict in jar_so_list:
            for jar_name in jar_dict:
                if jar_dict[jar_name]:
                    for so_path in jar_dict[jar_name]:
                        code, result_list_ldd = self.get_so_dependencies_by_ldd(so_path)
                        if code == 1:
                            result_list = self.get_so_dependencies_by_objdump(so_path)
                            depenc_name_list += result_list
                        else:
                            depenc_path_list += result_list_ldd

        new_jar_so_list = []

        for jar_dict in jar_so_list:
            temp_dict = dict()
            for jar_name in jar_dict:
                if jar_name not in temp_dict:
                    temp_dict[jar_name] = list()
                if jar_dict[jar_name]:
                    for so_path in jar_dict[jar_name]:
                        so_name = os.path.split(so_path)[-1]
                        # 1. 判断so是否在depenc_path_list 2. 判断so是否在depenc_name_list
                        if so_path in depenc_path_list or so_name in depenc_name_list:
                            temp_dict[jar_name].append(so_path)

            new_jar_so_list.append(temp_dict)

        return new_jar_so_list

    def get_so_dependencies_by_objdump(self, so_path):
        """
        Use objdump to obtain the dependency of so
        param so_path: -> string
            The absolute path of so file.
        return: result_list -> list
            List of dependent file names of so file.
        """
        result_list = []
        # 获取so 依赖列表
        command = "objdump -x {} | grep NEEDED".format(so_path)
        result = LinuxCommandExecute().get_command_result(command)
        # 获取结果中的NEEDED 依赖
        if result:
            line_list = result.split('\n')
            for line_content in line_list:
                result_list.append(line_content.split(' ')[-1])

        return result_list

    def get_so_dependencies_by_ldd(self, so_path):
        """
        Use ldd to obtain the dependency of so
        param so_path: -> string
            The absolute path of so file.
        return: result_list -> list
            List of dependent file path of so file.
        """
        result_list = []
        # 获取so 依赖列表
        command = "ldd {}".format(so_path)
        result = LinuxCommandExecute().get_command_result(command)
        # 获取结果中的NEEDED 依赖
        if result:
            line_list = result.split('\n')
            for line_content in line_list:
                if "not a dynamic executable" in line_content:
                    return 1, []
                if "=>" in line_content:
                    lib_so_path_content = line_content.split('=>')[-1]
                    if "not found" in lib_so_path_content:
                        continue
                    if 'lib' in lib_so_path_content or 'lib64' in lib_so_path_content:
                        continue
                    else:
                        lib_so_path = lib_so_path_content.split(' ')[0]
                        result_list.append(lib_so_path)

        return 2, result_list


class PomFileProcessing(object):
    def __init__(self):
        self.jar_path = ''
        self.mavem_url = "https://repo1.maven.org/maven2/"
        self.pom_json_parse_result = {}

    def pom_file_filter(self, document):
        """
        Filter all paths, find files with specific endings and save them.
        param document: -> string
            Files to be filtered.
        return: -> list or None
            Returns the filtered pom file.
        """
        pom_file_arg = ['pom', 'pom.xml']

        pom_mark = document.split('.')[-1].lower()

        if (pom_mark == pom_file_arg[0] or
                document.lower().find(pom_file_arg[1], -8) != -1):
            return document
        return

    def class_file_filter(self, document):
        """
        Filter all paths, find files with specific endings and save them.
        param document: -> string
            Files to be filtered.
        return: -> string or None
            Identification of test results.
        """
        class_arg = 'class'
        java_arg = 'java'
        source_arg = 'source'
        java_file_arg = "java class data"
        java_source_arg = "java source"

        file_extension = document.split('.')[-1]
        file_type = df().get_file_type(document).split(',')[0]
        file_type_lower = file_type.lower()

        if (java_file_arg in file_type_lower
                and file_extension == class_arg):
            return class_arg
        elif (java_source_arg in file_type_lower
              and file_extension == java_arg):
            return source_arg
        else:
            return None

    def java_source_class_file_parser(self, mark, java_file_path):
        """
        Parse java source files or class files.
        param mark: -> string
            Whether the partition java file ends with class or java.
        param java_file_path: -> string
            The absolute path of the java file.
        param cfr_jar_path: -> string
            The path to the cfr dependent file.
        return: -> list
            import_class_file_name
                A collection of jar packages that are dependent on the java file.
        """
        import_class_file_name = []

        if mark == "class":
            ret, file_text = decompile_class(java_file_path)
            if ret:
                import_class_file_name = class_result_resolution(file_text)
            return import_class_file_name

        parse_java_command = "cat {} | grep ^import".format(java_file_path)

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
                import_class_file_name.append(class_file.split(' ')[-1].rstrip(';').replace('.', '/').
                                              strip(' ').strip("'").strip('"'))

        return import_class_file_name

    def java_import_processing(self, import_file_names):
        """
        Process the filtered import file to form a condition that matches
        the pom filtering result.
        param import_file_names: -> list
            There is no matching imported data in the current java file.
        return: -> list
            List of processed results.
        """
        new_import_file_name = []

        for import_file in import_file_names:
            file_process_result = import_file[:import_file.rfind('/')].replace('/', '.')
            new_import_file_name.append(file_process_result)

        return new_import_file_name

    def java_file_import_filter(self, java_file, number, log_type, java_files, quiet_mark,
                                file_list=None, json_log_filename=None):
        """
        Obtain the imported data in the java file,
        and filter the Java file based on the imported data.
        param java_file: -> string
            A java file, including files with suffixes java and class.
        param number: -> int
            The specified number of threads.
        param log_type: -> string
            The specified result save format type.
        param java_files: -> list
            All java file, including files with suffixes java and class.
        param quiet_mark: -> string
            The path to the cfr dependent file.
        param file_list: -> None
        param json_log_filename: -> None
        return: -> list
            There is no matching imported data in the current java file.
        """
        no_search_import_class_file_name = []

        file_suffix = java_file.split('.')[-1]

        import_class_file_name = self.java_source_class_file_parser(file_suffix, java_file)

        if import_class_file_name:
            file_names = copy.copy(import_class_file_name)

            for class_file_name in import_class_file_name:

                stop_mark = True
                index_arg = 0
                while stop_mark:
                    java_file_count = len(java_files) - 1

                    if "{}.".format(class_file_name) in java_files[index_arg]:
                        file_names.remove(class_file_name)
                        stop_mark = False

                    if index_arg < java_file_count:
                        index_arg += 1
                    else:
                        stop_mark = False

            no_search_import_class_file_name += file_names

        if no_search_import_class_file_name:
            no_search_import_class_file_name = self.java_import_processing(list(set(no_search_import_class_file_name)))

        return list(set(no_search_import_class_file_name))

    def pom_dict_data_parser(self, json_data):
        """
        Parse the pom file in json format to obtain the required value.
        param pom_file_json_path: -> string
            The absolute path of the pom file converted to json format.
        return: -> dictionary
            JSON format pom file parsing result.
        """
        parent_groupid = None
        parent_artifactid = None
        parent_version = None
        properties = None
        dependencies = None
        dependency_management = None
        dependency_value = None
        dependency_management_value = None

        if json_data:
            project_dic = json_data
        else:
            return

        if project_dic:
            try:
                parent_artifactid = project_dic["artifactId"]
            except Exception:
                return

            try:
                parent_groupid = project_dic["groupId"]
            except Exception:
                parent_groupid = None

            try:
                properties = project_dic["properties"]
            except Exception:
                properties = None

            try:
                parent_version = project_dic["version"]

                if "$" in parent_version:
                    parent_version = self.pom_version_processing(parent_version, properties)
            except Exception:
                parent_version = None

            try:
                dependencies = project_dic["dependencies"]
            except Exception:
                dependencies = None
            finally:

                try:
                    dependency_management = project_dic["dependencyManagement"]
                except Exception:
                    dependency_management = None

        if dependencies:
            try:
                dependency_value = dependencies["dependency"]
            except Exception:
                dependency_value = None

        if dependency_management:
            try:
                dependency_management_value = dependency_management["dependencies"]["dependency"]
            except Exception:
                dependency_management_value = None

        parse_result = {
            "parent_groupid": parent_groupid,
            "parent_artifactid": parent_artifactid,
            "parent_version": parent_version,
            "properties": properties,
            "dependencies": dependency_value,
            "dependency_management": dependency_management_value
        }

        return parse_result

    def get_dependency_jar_line_no(self, pom_files, group_id, artifact_id):
        """
        Get the line number of the dependency in the pom file in the pom file.
        param pom_files: -> string
            The absolute path of the pom file to be parsed.
        param group_id: -> string
            Dependent group id value.
        param artifact_id: -> string
            Dependent artifact id value.
        return: ->None or list
            Matched line number.
        """
        line_no_list = []
        search_artifact_id_line_no_command = "grep -n '<artifactId>{}</artifactId>' {}".format(artifact_id, pom_files)
        search_group_id_line_no_command = "grep -n '<groupId>{}</groupId>' {}".format(group_id, pom_files)
        search_artifact_result = df().get_command_result(search_artifact_id_line_no_command).split('\n')
        search_group_result = df().get_command_result(search_group_id_line_no_command).split('\n')

        if (not search_artifact_result or
                not search_group_result or
                len(search_artifact_result) == 0):
            return line_no_list

        # Locate the line number in the pom file according to the two dependent label information
        # [artifactId and groupId]. The row number here is the row where the groupId is located.
        elif len(search_artifact_result) > 1:
            artifact_id_line_no_list = [result.split(':')[0] for result in search_artifact_result]
            for line_no in artifact_id_line_no_list:
                for group_result in search_group_result:
                    group_line_no = group_result.split(':')[0]
                    if not line_no:
                        continue
                    if str(int(line_no) - 1) == group_line_no:
                        line_no_list.append(group_line_no)
                        break
        else:
            line_no_list.append(str(int(search_artifact_result[0].split(':')[0]) - 1))

        return line_no_list

    def dependency_data_processing(self, dependency_data, properties_data, pom_files):
        """
        Dependency data handling in pom files.
        param dependency_data: -> dictionary
            The jar package is dependent on the pom file to be processed.
        param properties_data: -> dictionary
            The dependent version in the pom file to be used.
        param pom_files: -> string
            The absolute path of the pom file to be parsed.
        return: -> dictionary
            The processed pom depends on the jar package information.
        """
        dependency_result_dict = {}

        parent_args = ['@project.groupId@', '@project.artifactId@', '@project.version@',
                       'parent_groupid', 'parent_artifactid', 'parent_version']
        dependency_keys = ["groupId", "artifactId", "version", "line_no"]

        if dependency_data:
            if type(dependency_data) is dict:
                dependency_data = [dependency_data]

            for values in dependency_data:
                group_id = values[dependency_keys[0]]
                artifact_id = values[dependency_keys[1]]

                line_no = self.get_dependency_jar_line_no(pom_files, group_id, artifact_id)

                if group_id == parent_args[0]:
                    group_id = self.pom_json_parse_result[parent_args[3]]

                if artifact_id == parent_args[1]:
                    artifact_id = self.pom_json_parse_result[parent_args[4]]

                # Get the version from the value of dependency. If version is a regular expression,
                # find out the value of version according to the regular expression.
                # If version does not exist, it will be assigned a value of None.
                try:
                    version = values[dependency_keys[2]]
                    if version == parent_args[2]:
                        version = self.pom_json_parse_result[parent_args[5]]
                except Exception:
                    version = None

                if not version:
                    version = None

                elif "$" in version:
                    version = self.pom_version_processing(version, properties_data)

                dependency_result_dict_key = "{}/{}".format(group_id, artifact_id)

                try:
                    dependency_dict_check = dependency_result_dict[dependency_result_dict_key]
                except Exception:
                    dependency_dict_check = None

                if not dependency_dict_check or \
                        (dependency_dict_check and
                         dependency_result_dict[dependency_result_dict_key][dependency_keys[0]] != group_id):
                    versions = [version] if type(version) is not list else version

                else:
                    versions = dependency_result_dict[dependency_result_dict_key][dependency_keys[2]] + [version] if type(version) is not list else version

                dependency_result_dict[dependency_result_dict_key] = {dependency_keys[0]: group_id,
                                                                      dependency_keys[1]: artifact_id,
                                                                      dependency_keys[2]: list(set(versions)),
                                                                      dependency_keys[3]: line_no}

        return dependency_result_dict

    def search_dependent_jar_version(self, properties_key):
        """
        Search for version numbers of dependencies in the same instrumented object.
        param properties_key: -> string
            The version that the jar package depends on, which is a regular expression.
        return: -> None or string
            Returns the version number matched by the regular expression.
        """
        search_result = []
        dependent_pom_file = ''

        search_dir = dp().get_decompress_file_path(self.jar_path)
        files = properties_key[:properties_key.rfind('.')]

        if search_dir:
            search_command = "find {} -name {}".format(search_dir, files)
            search_result = LinuxCommandExecute().get_command_result(search_command).split('\n')

        if search_result:
            for res in search_result:
                if "META-INF" in res or "maven" in res:
                    dependent_pom_file = "{}/pom.xml".format(res)
                    break

        if os.path.exists(dependent_pom_file):
            json_data = self.pom_file_convert_dict_format(dependent_pom_file)
            pom_json_parse_result = self.pom_dict_data_parser(json_data)

            try:
                dependent_version = pom_json_parse_result["parent_version"]
            except Exception:
                dependent_version = ""

        else:
            return None

        if dependent_version:
            if "$" not in dependent_version:

                return dependent_version

            else:

                return None
        else:
            return None

    def pom_version_processing(self, version, properties):
        """
        The version of the dependent jar package and the processing of
        the scene with regular expressions.
        param version: -> string
            The version of the dependent jar package, with a regular expression.
        param properties:  -> dictionary
            A dictionary of properties in the pom file.
        return: -> string or None
            Results that match or do not match in the attribute.
        """
        properties_key = version.strip("${}")
        if properties:
            try:
                version = properties[properties_key]
            except Exception:

                version = None
        else:

            version = None

        return version

    def xml_to_dict(self, root_node):
        """
        Convert xml format to alphabetic format.
        param root_node: -> object
            Get the object of the root directory.
        return -> string and dictionary
            The result of parsing the xml format into a dictionary.
        """
        if not isinstance(root_node, et.Element):
            raise Exception("node format error.")

        if len(root_node) == 0:
            return root_node.tag, root_node.text

        json_data = {}

        for child in root_node:
            key, val = self.xml_to_dict(child)

            key_tag = key.split('}')[-1]
            if key_tag in json_data:

                if isinstance(json_data[key_tag], list):
                    json_data[key_tag].append(val)

                else:
                    temp = json_data[key_tag]
                    json_data[key_tag] = [temp, val]
            else:
                json_data[key_tag] = val

        return root_node.tag, json_data

    def pom_encoding_format_conversion(self, pom_file_path):
        """
        For the pom file that reports an error when parsing,
        convert the encoding format of the first line of xml.
        param pom_file_path: -> string
            The path to the pom file.
        return: -> None
        """
        with open(pom_file_path, 'r+', encoding='GBK', errors="surrogatepass") as f:
            date_source = f.readlines()

        subprocess.call('rm -rf {}'.format(pom_file_path), shell=True)

        with open(pom_file_path, 'a', encoding='utf-8', errors="surrogatepass") as a:
            for line_date in date_source:
                if '<?xml version="' in line_date:
                    a.write(line_date.replace(line_date, '<?xml version="1.0" encoding="utf-8" ?>'))
                else:
                    a.write(line_date)

        return

    def pom_file_convert_dict_format(self, pom_file_path):
        """
        Convert pom in xml format to dict format with hierarchical format.
        param pom_file_path: -> string
            The absolute path to the pom file.
        return: -> string
            The absolute path of the pom file converted to json format.
        """
        if os.path.getsize(pom_file_path) == 0:
            return

        try:
            et_tree = et.parse(pom_file_path)
        except Exception:
            self.pom_encoding_format_conversion(pom_file_path)
            try:
                et_tree = et.parse(pom_file_path)
            except Exception:
                return

        root_node = et_tree.getroot()
        tag, data = self.xml_to_dict(root_node)

        return data

    def pom_parsed_result_processing(self, dependencies_parse_result, dependency_management_parse_result):
        """
        Merge the dictionary formed by the pom parsing result.
        param dependencies_parse_result: -> dictionary
            Dependency resolution results in the pom file.
        param dependency_management_parse_result: -> dictionary
            The result of dependency management analysis in the pom file.
        return: -> dictionary
            The result of merging the dependency analysis result and
            the dependency management analysis result.
        """
        key_arg = "version"
        dependencies_keys = []
        dependency_management_keys = []

        if dependencies_parse_result and not dependency_management_parse_result:
            return dependencies_parse_result

        elif not dependencies_parse_result and dependency_management_parse_result:
            return dependency_management_parse_result

        else:
            if dependencies_parse_result:
                dependencies_keys = list(dependencies_parse_result.keys())

            if dependency_management_parse_result:
                dependency_management_keys = list(dependency_management_parse_result.keys())

            if len(dependencies_keys) >= len(dependency_management_keys):
                for key in dependency_management_keys:
                    try:
                        versions = dependencies_parse_result[key][key_arg] + dependency_management_parse_result[key][
                            key_arg]
                        dependencies_parse_result[key][key_arg] = list(set(versions))
                    except Exception:
                        dependencies_parse_result[key] = dependency_management_parse_result[key]

                return dependencies_parse_result

            else:
                for key in dependencies_keys:
                    try:
                        versions = dependency_management_parse_result[key][key_arg] + dependencies_parse_result[key][
                            key_arg]
                        dependency_management_parse_result[key][key_arg] = list(set(versions))
                    except Exception:
                        dependency_management_parse_result[key] = dependencies_parse_result[key]

                return dependency_management_parse_result

    def summarize_final_pom_parse_results(self, jar_paths, pom_files):
        """
        Summarize the pom file analysis results.
        param jar_paths: -> string
            The corresponding jar package absolute path where the pom file to be parsed exists.
        param pom_files: -> string
            The absolute path of the pom file to be parsed.
        return: -> dictionary
            The result after the pom file is parsed.
        """
        self.jar_path = jar_paths
        json_data = self.pom_file_convert_dict_format(pom_files)
        self.pom_json_parse_result = self.pom_dict_data_parser(json_data)

        if not self.pom_json_parse_result:
            return {}

        properties_data = self.pom_json_parse_result["properties"]
        dependencies_data = self.pom_json_parse_result["dependencies"]
        dependency_management_data = self.pom_json_parse_result["dependency_management"]

        dependencies_data_parse_result = self.dependency_data_processing(dependencies_data,
                                                                         properties_data,
                                                                         pom_files)

        dependency_management_data_parse_result = self.dependency_data_processing(dependency_management_data,
                                                                                  properties_data,
                                                                                  pom_files)

        final_pom_parse_result = self.pom_parsed_result_processing(dependencies_data_parse_result,
                                                                   dependency_management_data_parse_result)

        return final_pom_parse_result
