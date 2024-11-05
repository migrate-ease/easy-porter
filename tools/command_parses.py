#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys

from tools.constant import ep_version


class CommandParse(object):

    def usage(self):
        """
        Parameter description when using the tool.
        """
        print(r"""
                      ____            _            
  ___  __ _ ___ _   _|  _ \ ___  _ __| |_ ___ _ __ 
 / _ \/ _` / __| | | | |_) / _ \| '__| __/ _ \ '__|
|  __/ (_| \__ \ |_| |  __/ (_) | |  | ||  __/ |   
 \___|\__,_|___/\__, |_|   \___/|_|   \__\___|_|   
                |___/                           
Usage: easyPorter [-h] [-v] [-q] [-b] [-w]
            [-f FILE]
            [-d DIR]
            [-t TYPE]
            [-e ENGINE]
            [-o DIR]
            [-n NUM_THREADS]
            [--class udf|cs|xarch]
            [--temp DIR]
            [--log DIR]
Options:
[-h | --help]                    : Display this information.
[-v | --version]                 : Show the current version.
[-e | --engine] <java | python>  : Specify detection engine according to the language of files input.
[-f | --file] <arg>              : Input a file to be detected.
[-d | --directory] <arg>         : Input a directory to be detected.
[-t | --type] <txt | csv | json> : Specify the type of output, and txt in default.
[-b | --binary]                  : Disable source files (.java/.class) scanning in java, and enabled default.
[-q | --quiet]                   : Disable the output on screen, which is enabled in default.
[-o | --output] <arg>            : Output the result as <arg> in type specified, and ignored as 'result_$date' in default.
[-w]                             : Disable all warnings to incompatible output.
[-n] <arg>                       : Specify the number of threads as <arg>, which must be less than cores number on your platform.
[--class] <udf | cs | xarch>     : Categorize the results according to the <udf>, <codescan> and <xarch> formats.
[--log] <arg>                    : Specify the temporary directory where log files are kept, and '~/log/easyPorter' in default."
[--temp] <arg>                   : Specify the temporary directory where intermediate files are kept, and '~/tmp/easyPorter' in default.
[--check] <env | app>            : Check current environment with 'env' (OS/kernel/JDK/GCC/Python etc.) and the app configurations using its name (hadoop/spark/hive/flink etc.).
[--tree] <arg>                   : Output the directory tree as <arg>, and ignored as 'tree_$date.json' in default."
""")

    def command_parameter_parse(self):
        """
        This function is used to receive input parameters when executing python files.
        return:
            temp_args_list: the absolute path list(list).
            engine_lower: the scripting language of file path(java/python).
            log_type_lower: the type of output log(txt/json/csv).
            output: Whether to print log during detection(bool).
            recommend: Recommended or not(bool).
        """
        output = True
        binary_check = False
        warning_check = False
        inner_log = False
        temp_path = None
        path_para = None
        result_path = None
        result_path_index = 0
        process_number = 1
        check_type = None
        log_save_path = None
        tree_dir = False
        json_save_path = None

        input_args = sys.argv[1:]

        if not input_args or '-h' in input_args or '--help' in input_args:
            self.usage()
            sys.exit()

        if '-v' in input_args or '--version' in input_args:
            if input_args == ['-v'] or input_args == ['--version']:
                print(ep_version)
                sys.exit()
            else:
                print('Error: Use [-v/--version]')
                self.usage()
                sys.exit()

        temp_args_list = sys.argv[1:]
        engine_lower = ''
        log_type_lower = ''
        class_udf_lower = None

        integrality = False
        check_env_flag = False
        if '--check' in input_args:
            check_env_flag = True

        for parameter in ['-f', '--file', '-d', '--directory']:
            if parameter in input_args:
                integrality = True

        if not integrality and not check_env_flag:
            print('Error: Parameters {} must be set correctly. \n'.format(['-f', '--file', '-d', '--directory']))
            self.usage()
            sys.exit()

        for index, parameter in enumerate(input_args):
            # 判断参数后是否有值，有值时下标重新赋值0，跳过非参数
            if result_path_index > 0:
                result_path_index = 0
                continue
            if parameter in ['-q', '--quiet', '-b', '--binary', '-g']:

                if parameter == '-q' or parameter == '--quiet':
                    output = False

                elif parameter == '-b' or parameter == '--binary':
                    binary_check = True

                elif parameter == '-g':
                    inner_log = True

                temp_args_list.remove(parameter)

            elif parameter == "-w":
                warning_check = True
                temp_args_list.remove(parameter)

            elif parameter in ['-e', '--engine', '-t', '--type', '--class']:

                if (index + 1) >= len(input_args):
                    print('Error: Please specify correct options after [{}]. \n'.format(parameter))
                    self.usage()
                    sys.exit()

                if parameter in ['-e', '--engine']:
                    check_flag = input_args[index + 1]
                    engine_lower = check_flag.lower()

                    if engine_lower not in ['python', 'java']:
                        print('Error: "{}" is NOT supported after [-e/--engine], please recheck your input.\n'.format(
                            check_flag))
                        self.usage()
                        sys.exit()

                    temp_args_list.remove(check_flag)

                elif parameter in ['-t', '--type']:
                    log_type = input_args[index + 1]
                    log_type_lower = log_type.lower()

                    if log_type_lower not in ['txt', 'csv', 'json']:
                        print('Error: "{}" is NOT supported after [-t/--type], please recheck your input. \n'.format(
                            log_type))
                        self.usage()
                        sys.exit()

                    temp_args_list.remove(log_type)

                else:
                    class_udf = input_args[index + 1]
                    class_udf_lower = class_udf.lower()
                    if class_udf_lower not in ['udf', 'cs', 'xarch']:
                        print('Error: "{}" is NOT supported after [--class], please recheck your input. \n'.format(
                            class_udf))
                        self.usage()
                        sys.exit()

                    temp_args_list.remove(class_udf)

                temp_args_list.remove(parameter)

            elif parameter in ['-o', '--output']:
                result_path_index = index + 1
                if result_path_index >= len(input_args):
                    print('Error: Please specify a name without suffixies to be saved after [-o/--output] '
                          'instead of NULL.\n')
                    self.usage()
                    sys.exit()

                result_path = input_args[index + 1]
                if result_path.startswith('-'):
                    print('Error: Please specify a name without suffixies to be saved after [-o/--output] '
                          'instead of NULL.\n')
                    self.usage()
                    sys.exit()

                temp_args_list.remove(parameter)
                temp_args_list.remove(result_path)

            elif parameter in ['-f', '--file']:

                if index + 1 >= len(input_args):
                    print('Error: Please specify a file name after [-f/--file] instead of NULL.\n')
                    self.usage()
                    sys.exit()

                other_list = input_args[index + 1:]

                if not other_list:
                    self.usage()
                    sys.exit()

                path_para = parameter
                temp_args_list.remove(parameter)

            elif parameter in ['-d', '--directory']:

                if index + 1 >= len(input_args):
                    print('Error: Please specify a directory after [-d/--directory] instead of NULL. \n')
                    self.usage()
                    sys.exit()

                other_list = input_args[index + 1:]

                if not other_list:
                    self.usage()
                    sys.exit()

                path_para = parameter
                temp_args_list.remove(parameter)

            elif parameter == '--temp':
                result_path_index = index + 1
                if result_path_index >= len(input_args):
                    print('Error: Please specify a directory path to save intermediate temporary files in '
                          'scanning after [--temp] instead of NULL.\n')
                    self.usage()
                    sys.exit()

                specified_temp_path = input_args[index + 1]
                if specified_temp_path.startswith('-'):
                    print('Error: Please specify a directory path to save intermediate temporary files in '
                          'scanning after [--temp] instead of NULL.\n')
                    self.usage()
                    sys.exit()

                temp_path = input_args[result_path_index]

                temp_args_list.remove(parameter)
                temp_args_list.remove(specified_temp_path)

            elif parameter == '-n':
                result_path_index = index + 1
                if result_path_index >= len(input_args):
                    print('Error: Please specify a valid process number after [-n] in the '
                          'range of [1, $nproc].\n')
                    self.usage()
                    sys.exit()

                specify_processes_param = input_args[index + 1]
                try:
                    specify_processes_number = int(specify_processes_param)
                except Exception:
                    print('Error: Please specify a valid process number after [-n] in the '
                          'range of [1, $nproc].\n')
                    self.usage()
                    sys.exit()

                if specify_processes_number <= 0 or specify_processes_number >= 64 or not specify_processes_number:
                    print('Error: Please specify a valid process number after [-n] in the '
                          'range of [1, $nproc].\n')
                    self.usage()
                    sys.exit()

                process_number = specify_processes_number

                temp_args_list.remove(parameter)
                temp_args_list.remove(specify_processes_param)

            elif parameter == '--check':
                result_path_index = index + 1
                if result_path_index >= len(input_args):
                    print('Error: Please specify a detection type after [--check] in [env | app | hadoop...] .\n')
                    self.usage()
                    sys.exit()

                check_type = input_args[index + 1]
                if not check_type:
                    print('Error: Please specify a detection type after [--check] in [env | app | hadoop...] .\n')
                    self.usage()
                    sys.exit()
                temp_args_list.remove(parameter)
                temp_args_list.remove(check_type)

            elif parameter == '--log':
                result_path_index = index + 1
                if result_path_index >= len(input_args):
                    print('Error: Please specify a directory path to save log files in '
                          'scanning after [--log] instead of NULL.\n')
                    self.usage()
                    sys.exit()

                log_save_path = input_args[index + 1]
                if not log_save_path:
                    print('Error: Please specify a directory path to save log files in '
                          'scanning after [--log] instead of NULL.\n')
                    self.usage()
                    sys.exit()
                temp_args_list.remove(parameter)
                temp_args_list.remove(log_save_path)

            elif parameter == '--tree':
                tree_dir = True
                result_path_index = index + 1
                if result_path_index >= len(input_args):
                    print('Error: Please specify a directory or file path to save directory tree files in '
                          'scanning after [--tree] instead of NULL.\n')
                    self.usage()
                    sys.exit()

                json_save_path = input_args[index + 1]
                if not json_save_path:
                    print('Error: Please specify a directory or file path to save directory tree files in '
                          'scanning after [--tree] instead of NULL.\n')
                    self.usage()
                    sys.exit()
                temp_args_list.remove(parameter)
                temp_args_list.remove(json_save_path)

            else:
                if parameter == '--e':
                    print('Error: Please use [-e/--engine] instead of invalid "--e" option.\n')
                    self.usage()
                    sys.exit()

                if parameter.startswith('-'):
                    print('Error: "{}" is NOT a valid option, please recheck your input. \n'.format(parameter))
                    self.usage()
                    sys.exit()

                if parameter.lower() not in ['txt', 'csv', 'json', 'python', 'java', 'udf', 'cs', 'xarch']:

                    if not path_para:
                        print("Error: Please specify a file name or directory path after "
                              "['-f'/'--file'/'-d'/'--directory']. \n")
                        self.usage()
                        sys.exit()

                    if not os.path.exists(parameter) and not os.path.lexists(parameter):
                        print('Error: Unrecognized options of [{}], you can refer '
                              'to the help information or manual.'.format(parameter))
                        self.usage()
                        sys.exit()

                    if path_para in ['-f', '--file']:
                        if os.path.isdir(parameter):
                            print('Error: Please specify a file name after [-f/--file] instead of directory.')
                            self.usage()
                            sys.exit()

                    elif path_para in ['-d', '--directory']:
                        if os.path.isfile(parameter):
                            print('Error: Please specify a directory after [-d/--directory] instead of file name.')
                            self.usage()
                            sys.exit()

                    else:
                        print('Error: Unrecognized options of [{}], you can refer '
                              'to the help information or manual.'.format(parameter))
                        self.usage()
                        sys.exit()

                continue

        if not temp_args_list and not check_env_flag:
            print('Error: Please specify valid options.')
            self.usage()
            sys.exit()

        temp_args_list = list(set(temp_args_list))

        # xarch 时不允许不指定引擎
        if class_udf_lower == 'xarch':
            if not engine_lower:
                print('Error: Please specify an engine after [-e] when using "--class xarch".\n')
                self.usage()
                sys.exit()

            if log_type_lower != 'csv':
                if log_type_lower == '':
                    print('Warnning: Now easyPorter is being executed and output in [--class xarch] format of '
                          '[-t/--type csv] in default. \n')
                    log_type_lower = 'csv'
                else:
                    print('Error: Please specify "csv" after [-t/--type] and combine with option of [--class xarch].\n')
                    self.usage()
                    sys.exit()

        elif class_udf_lower == 'cs':
            if not engine_lower:
                print('Error: Please specify an engine after [-e] when using "--class cs".\n')
                self.usage()
                sys.exit()

            if log_type_lower != 'json':
                if log_type_lower == '':
                    print('Warnning: Now easyPorter is being executed and output in [--class cs] format of '
                          '[-t/--type json] in default.\n')
                    log_type_lower = 'json'
                else:
                    print('Error: Please specify "json" after [-t/--type] and combine with option of [--class cs].\n')
                    self.usage()
                    sys.exit()

        elif class_udf_lower == 'udf':
            if log_type_lower != 'csv':
                if log_type_lower == '':
                    print('Warnning: Now easyPorter is being executed and output in [--class udf] format of '
                          '[-t/--type csv] in default.\n')
                    log_type_lower = 'csv'
                else:
                    print('Error: Please specify "csv" after [-t/--type] and combine with option of [--class udf].\n')
                    self.usage()
                    sys.exit()
            if engine_lower:
                print("Error: Don't specify an engine after [-e] when using '--class udf'\n")
                self.usage()
                sys.exit()

        if '--tree' in input_args and class_udf_lower != 'cs':
            print('Error: Please specify [--class cs] and combine with option of [--tree].\n')
            self.usage()
            sys.exit()

        if log_type_lower == '':
            log_type_lower = 'txt'

        temp_list = [temp_args_list, engine_lower, log_type_lower, output, None, result_path,
                     class_udf_lower, binary_check, sys.argv, temp_path, inner_log, process_number,
                     check_type, warning_check, log_save_path, tree_dir, json_save_path]

        return temp_list
