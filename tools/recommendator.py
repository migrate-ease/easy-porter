#!/usr/bin/env python3
# coding=utf-8


class Recommend(object):
    def recommend_by_so(self, sql_so, mysql, so_name, all_one_mark=True):
        """
        Recommend the corresponding version through so.
        param sql_so: -> string
            The sql statement to be executed.
        param mysql: -> function
            The linked database object created.
        param so_name: -> string
            The name of the so to be searched.
        param all_one_mark: -> boolean
            Whether to query all results or a single data result.
        return: -> tuple
            so file recommendation results.
        """
        if all_one_mark:
            so_info = mysql.search_one(sql_so, (so_name,))
        else:
            so_info = mysql.search_all(sql_so, (so_name,))

        return so_info

    def get_recommended_keyword(self, name):
        """
        Process the so file name to be recommended and make it a search keyword.
        param name: -> string
            The so file name to be processed.
        return: -> string
            Processed keywords to be searched.
        """
        lib_arg = "lib"
        judgment_field = ["_linux", "_x86", "_amd"]

        so_name = name.split(".so")[0]
        if so_name[:3] == lib_arg:
            file_name = so_name[3:]
        else:
            file_name = so_name

        for field in judgment_field:
            if field in file_name:
                return file_name.split(field)[0]

        return file_name

    def check_type_src(self, type_mark):
        """
        Get the so package search source.
        param type_mark: -> number
            Search method identification of so package.
        return: from_flag -> string
            maven_arg: It comes from Maven warehouse.
            github_arg: It comes from github warehouse.
            "": No source.
        """
        from_flag = ''

        if type_mark == 0:
            from_flag = "Maven"
        elif type_mark == 1:
            from_flag = "Github"
        elif type_mark == 2:
            from_flag = "Yum"
        elif type_mark == 3:
            from_flag = "Alibaba"
        elif type_mark == 4:
            from_flag = "Huawei"
        else:
            from_flag = ""

        return from_flag
