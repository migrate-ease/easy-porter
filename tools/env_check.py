#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/7/6 14:48
# file: feature.py
import subprocess


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
                         stderr=subprocess.STDOUT)
    p.wait()
    stdout, stderr = p.communicate()
    ret_msg = stdout.decode('utf-8', 'ignore') if stdout else ''
    return p.returncode, ret_msg


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
    try:
        for i in range(len(list1)) if len(list1) < len(list2) else range(len(list2)):
            if int(list1[i]) == int(list2[i]):
                pass
            elif int(list1[i]) < int(list2[i]):
                return -1
            else:
                return 1
        if len(list1) == len(list2):
            return 0
        elif len(list1) < len(list2):
            return -1
        else:
            return 1
    except Exception:
        return 1


class EngineFeature(object):

    def __init__(self):
        self.os_dict = {
            'name': '',
            'version': 'NULL',
            'advice': 'Alibaba Cloud Linux 3 (Soaring Falcon) is recommended for better performance and support.',
        }
        self.kernel_dict = {
            'name': '',
            'version': 'NULL',
            'advice': 'Kernel >=5.10.84 is recommended for better performance and support.',
        }
        self.jdk_dict = {
            'name': '',
            'version': 'NULL',
            'advice': 'OpenJDK >=1.8.0_372 is recommended for better performance and support.',
        }
        self.gcc_dict = {
            'name': '',
            'version': 'NULL',
            'advice': 'GCC >=10.2.1 is recommended for better performance and support.',
        }
        self.python_dict = {
            'name': '',
            'version': 'NULL',
            'advice': 'Python3 >=3.6.8 is recommended for better performance and support.',
        }
        self.mvn_dict = {
            'name': 'Maven',
            'version': 'NULL',
            'advice': 'Maven >=3.9.1 is recommended for better performance and support.',
        }
        self.glibc_dict = {
            'name': 'GLIBC',
            'version': 'NULL',
            'advice': 'GLIBC >=2.32 is recommended for better performance and support.',
        }
        self.hadoop_dict = {
            'name': 'hadoop',
            'version': 'NULL',
            'advice': 'Hadoop >=3.3 is recommended for better performance and support.',
        }
        self.spark_dict = {
            'name': 'spark',
            'version': 'NULL',
            'advice': 'Spark >=3.3 is recommended for better performance and support.',
        }
        self.hive_dict = {
            'name': 'hive',
            'version': 'NULL',
            'advice': 'Hive >=3.0 is recommended for better performance and support.',
        }
        self.flink_dict = {
            'name': 'flink',
            'version': 'NULL',
            'advice': 'Flink >=1.14 is recommended for better performance and support.',
        }
        self.elasticsearch_dict = {
            'name': 'elasticsearch',
            'version': 'NULL',
            'advice': 'Elasticsearch >=7.1.12 is recommended for better performance and support.',
        }
        self.specify_dict = {
            'name': '',
            'version': 'NULL',
            'advice': '',
        }

    def get_os_config(self):
        cmd = """grep -E '^NAME=' /etc/os-release | awk 'BEGIN{FS="^NAME="}{print $2}' | sed 's/"//g'"""
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower():
            self.os_dict['name'] = result.strip()
        cmd = """grep -E '^VERSION=' /etc/os-release | awk 'BEGIN{FS="^VERSION="}{print $2}' | sed 's/"//g'"""
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.os_dict['version'] = result.strip()

    def get_kernel_config(self):
        cmd = "cat /proc/version | awk '{print $1 $3}'"
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.kernel_dict['name'] = result.strip()
        cmd = "cat /proc/version | awk '{print $3}'"
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.kernel_dict['version'] = result.strip()

    def get_jdk_config(self):
        cmd = """java -version 2>&1 | awk -F '"' '/Runtime|runtime/ {print $1}' | awk '{print $1}'"""
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.jdk_dict['name'] = result.strip()

        cmd = """java -version 2>&1 | awk -F '"' '/version/ {print $2}'"""
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.jdk_dict['version'] = result.strip()

    def get_gcc_config(self):
        cmd = """gcc --version | head -n1 | awk '{print $2}' | sed 's/(//g' | sed 's/)//g'"""
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.gcc_dict['name'] = result.strip()

        cmd = "gcc --version | head -n1 |awk '{print $3}'"
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.gcc_dict['version'] = result.strip()

    def get_python_config(self):
        python_cmd = 'python'
        for python_flag in ['python', 'python3', 'python2']:
            ret, msg = execute_cmd('type {}'.format(python_flag))
            if 'not found' in msg or 'type:' in msg:
                continue
            python_cmd = python_flag
            break
        cmd = '''{} -c "import sys; print('Python2' if sys.version_info[0] == 2 else 'Python3')"'''.format(python_cmd)
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.python_dict['name'] = result.strip()

        cmd2 = "{} --version 2>&1 | awk '{{print $2}}'".format(python_cmd)
        ret2, result2 = execute_cmd(cmd2)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.python_dict['version'] = result2.strip()

    def get_mvn_version(self):
        cmd = "mvn -version | grep 'Apache Maven' | awk '{print $3}'"
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.mvn_dict['version'] = result.strip()

    def get_glibc_version(self):
        cmd = "ldd --version | head -n1 | awk '{print $NF}'"
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.glibc_dict['version'] = result.strip()

    def get_hadoop_version(self):
        cmd = "hadoop version | grep Hadoop | awk '{print $2}'"
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.hadoop_dict['version'] = result.strip()

        if self.hadoop_dict['version'] != 'NULL':
            if compared_version(self.hadoop_dict['version'], '3.3') != -1:
                self.hadoop_dict['advice'] = 'OK'

    def get_spark_version(self):
        cmd = "spark-submit --version | grep version | awk '{print $NF}'"
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.spark_dict['version'] = result.strip()

        if self.spark_dict['version'] != 'NULL':
            if compared_version(self.spark_dict['version'], '3.3') != -1:
                self.spark_dict['advice'] = 'OK'

    def get_hive_version(self):
        cmd = "hive --version | head -n1 | awk '{print $NF}'"
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.hive_dict['version'] = result.strip()

        if self.hive_dict['version'] != 'NULL':
            if compared_version(self.hive_dict['version'], '3.0') != -1:
                self.hive_dict['advice'] = 'OK'

    def get_flink_version(self):
        cmd = "flink --version | grep 'Flink' | awk '{print $NF}'"
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.flink_dict['version'] = result.strip()

        if self.flink_dict['version'] != 'NULL':
            if compared_version(self.flink_dict['version'], '1.14') != -1:
                self.flink_dict['advice'] = 'OK'

    def get_elasticsearch_version(self):
        self.elasticsearch_dict['name'] = 'elasticsearch'
        cmd = "elasticsearch --version | awk '{print $2}'"
        ret, result = execute_cmd(cmd)
        if 'command not found' not in result.lower() and 'error' not in result.lower() and '/bin/sh' not in result.lower():
            self.elasticsearch_dict['version'] = result.strip()

        if self.elasticsearch_dict['version'] != 'NULL':
            if compared_version(self.elasticsearch_dict['version'], '7.1.12') != -1:
                self.elasticsearch_dict['advice'] = 'OK'

    def check_env_config(self):
        self.get_python_config()
        self.get_gcc_config()
        self.get_os_config()
        self.get_kernel_config()
        self.get_jdk_config()
        self.get_mvn_version()
        self.get_glibc_version()
        if self.mvn_dict['version'] != 'NULL':
            if compared_version(self.mvn_dict['version'], '3.9.1') != -1:
                self.mvn_dict['advice'] = 'OK'

        if self.python_dict['version'] != 'NULL':
            if self.python_dict['name'] == 'Python2':
                if compared_version(self.python_dict['version'], '2.7.17') == -1:
                    self.python_dict['advice'] = 'Python2 >=2.7.17 is recommended for better performance and support.'
                else:
                    self.python_dict['advice'] = 'OK'
            if self.python_dict['name'] == 'Python3':
                if compared_version(self.python_dict['version'], '3.6.8') != -1:
                    self.python_dict['advice'] = 'OK'

        if self.gcc_dict['version'] != 'NULL':
            if compared_version(self.gcc_dict['version'], '10.2.1') != -1:
                self.gcc_dict['advice'] = 'OK'

        if self.os_dict['version'] != 'NULL':
            if 'Soaring Falcon' in self.os_dict['version']:
                if int(self.os_dict['version'].split(' ')[0]) >= 3:
                    self.os_dict['advice'] = 'OK'

        if self.kernel_dict['version'] != 'NULL':
            if compared_version(self.kernel_dict['version'], '5.10.84') != -1:
                self.kernel_dict['advice'] = 'OK'
        else:
            self.kernel_dict['advice'] = 'Kernel >=5.10.84 is recommended for better performance and support.'

        if self.jdk_dict['version'] != 'NULL':
            if compared_version(self.jdk_dict['version'], '1.8.0_372'.replace('_', '.')) != -1:
                self.jdk_dict['advice'] = 'OK'

        if self.glibc_dict['version'] != 'NULL':
            if compared_version(self.glibc_dict['version'], '2.32') != -1:
                self.glibc_dict['advice'] = 'OK'

    def check_app_config(self):
        self.get_hadoop_version()
        self.get_spark_version()
        self.get_hive_version()
        self.get_flink_version()
        self.get_elasticsearch_version()

    def check_specific_config(self, app_name):
        app_name = app_name.lower()
        if app_name == 'hadoop':
            self.get_hadoop_version()
        elif app_name == 'spark':
            self.get_spark_version()
        elif app_name == 'hive':
            self.get_hive_version()
        elif app_name == 'flink':
            self.get_flink_version()
        elif app_name == 'elasticsearch':
            self.get_elasticsearch_version()
        else:
            self.specify_dict['name'] = app_name
            self.specify_dict['version'] = 'NULL'
            self.specify_dict['advice'] = '{} has not been installed.'.format(app_name)

    def check_usage(self, check_type):
        check_type = check_type.lower()
        print("{0:<20}|{1:<20}|{2}".format('TERMS', 'VERSION', 'ADVICE'))
        if check_type == 'env':
            check_list = [self.os_dict, self.kernel_dict, self.jdk_dict, self.gcc_dict, self.python_dict,
                          self.mvn_dict, self.glibc_dict]
        elif check_type == 'app':
            check_list = [self.hadoop_dict, self.spark_dict, self.hive_dict, self.flink_dict,
                          self.elasticsearch_dict]
        else:
            app_dict = {
                'hadoop': self.hadoop_dict,
                'spark': self.spark_dict,
                'hive': self.hive_dict,
                'flink': self.flink_dict,
                'elasticsearch': self.elasticsearch_dict,
            }
            check_list = [app_dict.get(check_type, self.specify_dict)]

        for info_dict in check_list:
            print("{0:<20}|{1:<20}|{2}".format(info_dict.get('name', ''),
                                               info_dict.get('version', ''),
                                               info_dict.get('advice', '')))
