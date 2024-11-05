#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/7/31 14:29
# file: constant.py
import os


class Constant(object):
    """
    Common constant
    """

    def __init__(self):
        self.udf_log_path = os.path.expanduser('~/log/easyPorter/')
        self.path_keyword = ['^arm.{0,18}$', '^win.{0,18}$', '^x86.{0,18}$', '^linux.{0,18}$', '^freebsd.{0,18}$',
                             '^darwin.{0,18}$', '^sunos.{0,18}$', '^openbsd.{0,18}$']
        self.zip_arg = ['(jar)', 'jar', 'gzip', 'zip', 'gz', 'tar', 'bz', 'xz',
                        'rpm', 'whl', 'egg', 'deb', 'ear', 'bzip2', 'lzma', 'war']

        self.jdk_import = ["org.ietf.jgss", "lzma.sdk.lzma"]
        self.schedule_tag = True
        self.current_rate = 0
        self.standard_text = "\rProgress: [{}] {} [{}/{}] "
        self.arm_architecture = ['/aarch64/', '/arm64/', '/arm/', "/linux/", '/arm32/', '/[^/]*?arm/']
        self.other_architecture = ["intel", "x86" "x86_64", "i386", "amd", "amd64", "power", "ppcle", "alpha",
                                   "ppc64le", "arm64", "linux", "arm", "arm32", "armhf", "armv6", "armv7",
                                   "s390x", "android-arm", 'aix-ppc64', 'aix-ppc', "ppc64", 'ppc', 'win32-x86-64',
                                   'linux-x86', 'linux-ppc64', 'w32ce-arm', 'linux-x86-64', 'darwin', 'linux-ppc64le',
                                   'linux-arm', 'freebsd-x86', 'sunos-sparc', 'freebsd-x86-64', 'sunos-x86',
                                   'win32-x86', 'sunos-x86-64', 'openbsd-x86-64', 'openbsd-x86', 'sunos-sparcv9',
                                   'android-aarch64', 'mac', 'osx', 'aix', 'sunos', 'unixwindows']
        self.sys_architecture_list_java = ['^windows.{0,18}$', '^linux.{0,18}$', 'osx.{0,18}$', '^openbsd.{0,18}$',
                                           '^mac.{0,18}$', '^solaris.{0,18}$', '^aix.{0,18}$', '^macosx.{0,18}$',
                                           '^freebsd.{0,18}$', '^sunos.{0,18}$', '^darwin.{0,18}$',
                                           '^unixwindows.{0,18}$', '^intel.{0,18}$', '^i386.{0,18}$',
                                           '^i686.{0,18}$', '^alpha.{0,18}$', '^power.{0,18}$', '^hpux.{0,18}$',
                                           '^ppc64.{0,18}$', '^ppc.{0,18}$', 'w32ce.{0,18}?/', 'win32.{0,18}?/',
                                           '^android.{0,18}$', '^win.{0,18}$']

        self.version = """easyPorter (Yitian Optimal Development Assistant) 1.3.0 20240130
Copyright (C) 2023 Alibaba T-head, Inc.
This is LICENSED software. For more information, refer to Alibaba Cloud Yitian Community."""
        self.sys_list = ["armhf", "arm", "i686", "x86_64", "linux", "solaris", "macosx", "aix", "freebsd",
                         "ppc64le", "ppc32le", "hpux", "power", "alpha", "intel", "ia", "sparc", "ppc",
                         "x86", 'amd', "aarch", "osx"]
        self.elf_suffix_list = ['.dll', '.lib', '.dylib', '.jnilib', '.LIB', '.DLL', '.framework', '.so', '.SO', '.bin']
        self.sys_architecture_list = ['windows.{0,18}?/', 'linux.{0,18}?/', 'osx.{0,18}?/', 'openbsd.{0,18}?/',
                                      'mac.{0,18}?/', 'solaris.{0,18}/', 'aix.{0,18}?/', 'macosx.{0,18}?/',
                                      'freebsd.{0,18}?/', 'sunos.{0,18}?/', 'darwin.{0,18}?/',
                                      'unixwindows.{0,18}?/', 'intel.{0,18}?\/', 'i386.{0,18}?/', 'i686.{0,18}?/',
                                      'alpha.{0,18}?/', 'power.{0,18}?/', 'hpux.{0,18}?/', 'ppc64.{0,18}?/',
                                      'ppc.{0,18}?/', 'w32ce.{0,18}?/', 'win32.{0,18}?/', '^android.{0,18}$',
                                      '^win.{0,18}$']
        self.architecture_priority = ['/aarch64/', '/linux-aarch64/', '/arm64/', '/arm/', '/arm32/',
                                      '/[^/]*?arm/']
        self.summary_output = "Summary COMPATIBLE({});INCOMPATIBLE({});TO BE VERIFIED({});" \
                              "WARNING({});FAILURE({});TOTAL({})."
        self.summary_output_xarch = "Summary FAILED({});UNCERTAIN({});X86_64({});AARCH64({});NOARCH({});" \
                                    "WARNING({});TOTAL({})."
        self.summary_run_time = "Total time elapsed {:.3f} Seconds, and average at {:.3f} seconds of each file."
        self.logger = None
        self.broken_file_md5 = 'E0000000000000000000000000000001'
        self.ignored_list = ['_macosx', '.git', '.svn', '.hg', '.idea', '.vscode', '__pycache__',
                             '.vagrant', '.win', '.aone', 'windows', 'windows32', 'windows64', '__macosx']
        self.confirmed_list = ['.DS_Store', '._.DS_Store']
        self.elf_type_list = ['jnilib', 'Windows lib', 'Windows dll', 'Mac lib', 'lib']
        self.py_type_list = ['.pyi', '.pyd', '.pyz', '.pyw', 'pyo', '.ipynb', '.pyc']
        self.version_key_list = ['implementation-version', 'specification-version', 'bundle-version']
        self.suffix_dict = {
            'txt': '.log',
            'csv': '.csv',
            'json': '.json',
        }
        self.isolation = "\n----------------------------------------------------------------------" \
                         "----------------------------------------------------------------------"
        self.broken_link = "broken symbolic link"
        self.skip_list = ['jnilib', 'Windows lib', 'Windows dll', 'Mac lib']
        self.stop_flag = 'stop'
        self.progress_engine = 'java'
        self.loop_list = ["       ",
                          " /     ",
                          " /\\    ",
                          " /\\/   ",
                          " /\\/\\  ",
                          " /\\/\\/ ",
                          "       ",
                          " \\     ",
                          " \\/    ",
                          " \\/\\   ",
                          " \\/\\/  ",
                          " \\/\\/\\ "]


constant = Constant()
udf_log_path = constant.udf_log_path
path_keyword = constant.path_keyword
zip_arg = constant.zip_arg
jdk_import = constant.jdk_import
schedule_tag = constant.schedule_tag
ep_version = constant.version
sys_list = constant.sys_list
elf_suffix_list = constant.elf_suffix_list
sys_architecture_list = constant.sys_architecture_list
architecture_priority = constant.architecture_priority
arm_architecture = constant.arm_architecture
sys_architecture_list_java = constant.sys_architecture_list_java
other_architecture = constant.other_architecture
summary_output = constant.summary_output
version_key_list = constant.version_key_list
