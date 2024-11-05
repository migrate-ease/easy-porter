#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from tools.initializer import paras_list
from tools.env_check import EngineFeature
from java.engine import JavaEngine
from python.engine import PythonEngine


def main(paras_list):
    public_csv_path = None
    verify_zip_list = []

    if paras_list[12]:
        ef = EngineFeature()
        # env / app check
        if paras_list[12] == 'env':
            ef.check_env_config()
            ef.check_usage('env')
        elif paras_list[12] == 'app':
            ef.check_app_config()
            ef.check_usage('app')
        else:
            ef.check_specific_config(paras_list[12])
            ef.check_usage(paras_list[12])
        return 0

    # java engine
    if paras_list[1] == 'java':
        je = JavaEngine()
        je.java_pump(paras_list)

    # python engine
    elif paras_list[1] == 'python':
        pe = PythonEngine()
        pe.python_pump(paras_list, public_csv_path, verify_zip_list)

    # java and python engine
    elif not paras_list[1]:
        je = JavaEngine()
        pe = PythonEngine()
        public_csv_path, verify_zip_list = je.java_pump(paras_list)
        pe.python_pump(paras_list, public_csv_path, verify_zip_list)

    return 0


if __name__ == '__main__':
    main(paras_list)
