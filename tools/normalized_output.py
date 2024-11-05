#!/usr/bin/env python
# -*- coding: utf-8 -*-
import csv
import subprocess

from tools.utils import compared_version
from tools.filter_rules import python_library_dict


class NormalizedOutput(object):

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

    def log_normalized_output(self, log_type, log_file_path, detection_object, execution_results,
                              detection_command, execution_detection_time, engine, log_mark=False):
        """
        Standardize the output of log files in different formats.
        param log_type: -> string
            Log save format.
        param log_file_path: -> string
            The target file to save when the results are summarized and output.
        param detection_object: -> list
            A list of objects to detect.
        param execution_results: -> list
            Execution results, including failed, successful, and error flags.
        param detection_command: -> list
            Full command when performing instrumentation.
        param execution_detection_time: -> string
            Startup time when instrumentation is performed.
        param engine: -> string
            The engine that performs the detection.
        param log_mark: -> boolean
            Whether to enable monitoring logs.
        return: -> None or dictionary
            scanned_execute_summary_data:
                Standardized output header information in json format.
        """
        write_modes = "a"
        encod_arg = "utf-8-sig"
        detailed_arg = "Detailed Results as Follows:"
        engine_list = ["java", "python"]
        specify_log_type = ["txt", "csv", "json"]
        scanned_format_list = ["Scanned Infos:", "OBJECTS(-f/-d)", "COMMAND",
                               "EXECUTOR(whoami)", "TIME(date)"]
        summary_format_list = ["Summary:", "COMPATIBLE", "INCOMPATIBLE",
                               "TO BE VERIFIED", "OTHERS", "WARNING", "TOTAL"]
        execute_format_list = ["Executed Configuration:", "NODE(uname -n)", "CPU(uname -p)",
                               "OS(lsb_release -d)", "KERNEL(uname -r)"]
        txt_format_list = ["PROJECT", "LOCATION", "NAME", "MD5", "CATEGORY", "TYPE",
                           "INCOMPATIBILITY", "ADVICE", "UPGRADE", "PACKAGE",
                           "VERSION", "FROM", "DOWNLOAD", "ACTION"]
        json_format_list = ["objects", "command", "executor", "time", "node", "arch", "os",
                            "kernel", "branch", "commit", "errors", "summary", "compatible",
                            "incompatible", "to_be_verified", "others", "warning", "total"]

        who_info = self.get_command_result('whoami')
        node_info = self.get_command_result('uname -n')
        cpu_info = self.get_command_result('uname -p')
        os_info = self.get_command_result('lsb_release -d').split(':')[-1].strip(' ').strip('\t')
        kernel_info = self.get_command_result('uname -r')

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
            summary_info = ["", execution_results[0], execution_results[1], execution_results[2],
                            execution_results[3], execution_results[4], execution_results[5]]
        else:
            summary_info = []

        execute_info = ["", node_info, cpu_info, os_info, kernel_info]

        if log_type == specify_log_type[0]:
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
            with open(log_file_path, write_modes, encoding=encod_arg, errors="surrogatepass") as log:
                log.write(';\n'.join(txt_standard_output_header))

        elif log_type == specify_log_type[1]:
            csv_standard_output_header = [scanned_format_list, scanned_info, summary_format_list,
                                          summary_info, execute_format_list, execute_info, [detailed_arg]]
            with open(log_file_path, write_modes, encoding=encod_arg, errors="surrogatepass") as log:
                f_csv = csv.writer(log)

                for output_header in csv_standard_output_header:
                    f_csv.writerow(output_header)
        else:
            if engine == "java":
                scanned_execute_summary_data = {
                    json_format_list[0]: "\n".join(detection_object),
                    json_format_list[1]: detection_command,
                    json_format_list[2]: who_info,
                    json_format_list[3]: execution_detection_time,
                    json_format_list[4]: node_info,
                    json_format_list[5]: cpu_info,
                    json_format_list[6]: os_info.strip('\t'),
                    json_format_list[7]: kernel_info,
                    json_format_list[8]: '',
                    json_format_list[9]: '',
                    json_format_list[10]: [],
                    json_format_list[11]: {
                        json_format_list[12]: execution_results[0],
                        json_format_list[13]: execution_results[1],
                        json_format_list[14]: execution_results[2],
                        json_format_list[15]: execution_results[3],
                        json_format_list[16]: execution_results[4],
                        json_format_list[17]: sum(execution_results),
                    }
                }
            else:
                scanned_execute_summary_data = {
                    json_format_list[0]: "\n".join(detection_object),
                    json_format_list[1]: detection_command,
                    json_format_list[2]: who_info,
                    json_format_list[3]: execution_detection_time,
                    json_format_list[4]: node_info,
                    json_format_list[5]: cpu_info,
                    json_format_list[6]: os_info.strip('\t'),
                    json_format_list[7]: kernel_info,
                    json_format_list[8]: '',
                    json_format_list[9]: '',
                    json_format_list[10]: [],
                    json_format_list[11]: {
                        json_format_list[12]: summary_info[1],
                        json_format_list[13]: summary_info[2],
                        json_format_list[14]: summary_info[3],
                        json_format_list[15]: summary_info[4],
                        json_format_list[16]: summary_info[5],
                        json_format_list[17]: summary_info[6]
                    }
                }
            return scanned_execute_summary_data

        return

    def get_xarch_header(self, detection_object, execution_results, detection_command, execution_detection_time):
        scanned_format_list = ["Scanned Infos:", "OBJECTS(-f/-d)", "COMMAND",
                               "EXECUTOR(whoami)", "TIME(date)"]
        summary_format_list = ["Summary:", "NOARCH", "AARCH64", "x86_64", "UNCERTAIN", "FAILED", "WARNING", "TOTAL"]
        execute_format_list = ["Executed Configuration:", "NODE(uname -n)", "CPU(uname -p)", "OS(lsb_release -d)",
                               "KERNEL(uname -r)"]
        detailed_arg = "Detailed Results as Follows:"
        who_info = NormalizedOutput().get_command_result('whoami')
        node_info = NormalizedOutput().get_command_result('uname -n')
        cpu_info = NormalizedOutput().get_command_result('uname -p')
        os_info = NormalizedOutput().get_command_result('lsb_release -d').split(':')[-1].strip(' ')
        kernel_info = NormalizedOutput().get_command_result('uname -r')
        scanned_info = ["", "\n".join(detection_object), detection_command,
                        who_info, execution_detection_time]
        summary_info = ["", str(execution_results[2]), str(execution_results[1]), str(execution_results[0]),
                        str(execution_results[3]), str(execution_results[4]), str(execution_results[5]),
                        str(sum(execution_results))]
        execute_info = ["", node_info, cpu_info, os_info, kernel_info]

        return [scanned_format_list, scanned_info, summary_format_list,
                summary_info, execute_format_list, execute_info, [detailed_arg]]

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

    def get_action_str(self, advice_level, minversion, version, pip_install_name, engine):
        """
        Generate action string
        param advice_level: -> int
            The level of recommended advice.
        param minversion: -> string
            The minversion of recommended jar package.
        param version: -> string
            The version of recommended jar package.
        param engine: -> string
            The engine of easyPorter.
        return: -> string or None
            Returns the classification and strings of advice
        """
        if pip_install_name in python_library_dict:
            pip_install_name = python_library_dict.get(pip_install_name)
        if pip_install_name == 'scikit_learn':
            if compared_version(version, '0.23.1') == 1:
                pip_install_name = "scikit_learn.libs"
            else:
                pip_install_name = "sklearn"
        elif pip_install_name == 'Pillow':
            if compared_version(version, '7.0.0') == 1 or compared_version(version, '8.4.0') != 0:
                pip_install_name = "Pillow.libs"
            else:
                pip_install_name = "PIL"
        action_dict = {
            'python': {
                'Y': [
                    'Update the version of python dependencies with command of pip or pip3 install '
                    '{} >= {}".'.format(pip_install_name, minversion),
                    'Update the version of python dependencies with command of pip or pip3 install '
                    '{} == {}".'.format(pip_install_name, version),
                    'Update the file with the DOWNLOAD.',
                    'Update the file with the recompiled one on aarch64.',
                ],
                'N': 'Check if it is used in your references and if yes recompiled one on aarch64.'
            }
        }
        action = ''
        if advice_level != '':
            if pip_install_name:
                action = action_dict[engine]['Y'][advice_level]
            else:
                action = action_dict[engine]['N']

        return action
