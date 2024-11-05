#!/usr/bin/env python3
# coding=utf-8
import os.path
import sys
import time
import json
import subprocess
import urllib.request
import requests

from lxml.html import etree
from java.tools.java_tool import JavaTool as yt
from java.utils.java_utils import DocumentProcessing as dp
from java.utils.java_utils import StringProcessing as sp

current_path = os.getcwd()


class RecommendedTools(object):
    """
    This is a class that searches Maven warehouse or github according to
    incompatible so packages and automatically recommends the corresponding version.
    It can be used alone or with the migration evaluation tool.
    """

    def __init__(self):
        self.maven_rest_api = "https://search.maven.org/solrsearch/select?"
        self.maven_url = "https://repo1.maven.org/maven2/"
        self.github_api = "https://api.github.com/search/repositories?sort=stars&order=desc&wt=json&q="
        self.github_url = "https://github.com/"

        self.time_str = time.strftime('%Y%m%d%H%M%S', time.localtime(int(round(time.time() * 1000)) / 1000))
        temp_files = os.path.expanduser('~/tmp/easyPorter')
        self.ep_temp_files = '{}/ep_tmp_{}'.format(temp_files, self.time_str)
        self.path = "{}/".format(current_path)
        self.file_download_path = "{}/download_file".format(self.ep_temp_files)
        self.not_arm_file = "{}incompat_arm".format(self.ep_temp_files)
        self.arm_file = "{}compat_arm".format(self.ep_temp_files)
        self.fail_log = "{}failure".format(self.ep_temp_files)

    def usage(self):
        """
        Parameter description when using the tools.

        return: -> None
        """
        print("Usage: ./maven_data_check.py [-h] [-k | -u arg] [-t arg]\n"
              "Options and arguments: \n"
              "-h   : Print this help message and exit (also --help)\n"
              "-k   : Keywords to search, "
              "it is suggested that the keywords should be limited to 5.\n"
              "-u   : The url of the maven source, "
              "please specify the url to be used to include various versions. \n"
              "-t   : Specifies the type of log file to save. "
              "Must be used in conjunction with -k/-u Currently, \n"
              "       txt and csv and json formats are supported.\n")
        return

    def parse_parameters(self):
        """
        This function is used to receive input parameters when executing python files.

        param argv: -> string
            argv: This parameter is used to receive input parameters.
        return: -> dictionary
            Returns the absolute path list.
        """
        input_arg1 = sys.argv[1:]

        legal_parameters = ['-k', '-u']
        help_parameters = ['-h', 'help']

        if not sys.argv[1:]:
            self.usage()
            sys.exit()

        input_parameters = sys.argv[1:][0]
        if ('-t' in input_arg1 and
                input_parameters not in legal_parameters):
            self.usage()
            sys.exit()

        else:
            for parameter in input_arg1:
                index = input_arg1.index(parameter)
                file_list = input_arg1[index + 1:]
                if (parameter in help_parameters or
                        parameter not in legal_parameters):
                    self.usage()

                elif parameter in legal_parameters[:1]:
                    try:
                        assert len(file_list) != 0
                    except Exception:
                        self.usage()
                    return {"identification": 0, "key_list": file_list}

                else:
                    try:
                        assert len(file_list) != 0
                    except Exception:
                        self.usage()
                    self.check_url(file_list)
                    return {"identification": 1, "key_list": file_list}
                sys.exit()

    def check_url(self, url_list):
        """
        Check whether the URL meets the requirements.
        Please specify the url to be used to include various versions.

        param url_list: -> list
            List of URLs entered on the command line.
        return: -> None
        """
        str_list = ['', '/']
        for link in url_list:
            url_age = link.split('maven2')[-1]

            if url_age in str_list:
                print("Please specify the detection directory after the URL. \n"
                      "And please specify the url to be used to include various versions. \n"
                      "example：https://repo1.maven.org/maven2/HTTPClient/HTTPClient/")
                sys.exit()
        return

    def search_rules(self, rows, str_type, identification, key_list):
        """
        Parse command line input parameters.

        param rows: -> number
            Controls the number of entries displayed per page.
        param str_type: -> string
            Control the display format after the request is returned.
        param identification: -> number
            Identify whether to search by keyword or request by url.
        param key_list: -> list
            The parameters on the command line.
        return: -> dictionary
            parameter_dictionary:
                identification: Identify whether to search by keyword or request by url.
                search_list: List of processed request links.
                log_type: The specified log file format.
        """
        str_arg = '-t'
        search_list = []
        file_types = ['txt', 'csv', 'json']

        if str_arg not in key_list:
            if identification == 0:
                search_list.extend("{}q={}&rows={}&wt={}"
                                   .format(self.maven_rest_api, key, rows, str_type) for key in key_list)

            else:
                search_list.extend(iter(key_list))

            parameter_dictionary = {"keys_list": key_list,
                                    "identification": identification,
                                    "search_list": search_list,
                                    "log_type": file_types[0]}
            return parameter_dictionary

        elif str_arg in key_list:
            if (key_list[-1] not in file_types or
                    key_list[key_list.index(str_arg) + 1] not in file_types):
                self.usage()
                sys.exit()

            else:
                log_type = key_list[key_list.index(str_arg) + 1]
                new_key_list = key_list[:key_list.index(str_arg)]
                if identification == 0:
                    search_list.extend("{}q={}&rows={}&wt={}"
                                       .format(self.maven_rest_api, key, rows, str_type) for key in new_key_list)

                else:
                    search_list.extend(iter(new_key_list))

                parameter_dictionary = {"keys_list": new_key_list,
                                        "identification": identification,
                                        "search_list": search_list,
                                        "log_type": log_type}
                return parameter_dictionary

    def search_package(self, rows, str_type):
        """
        Process the command for keyword query.

        param rows: -> number
            Number of entries displayed per page in html query.
        param str_type: -> string
            Display text type in html query.
        return: -> dictionary
            search_parameter:
                Returns the concatenated query url.
        """
        parameter = self.parse_parameters()
        search_parameter = self.search_rules(rows, str_type,
                                             parameter["identification"], parameter["key_list"])
        return search_parameter

    def get_response(self, request_link):
        """
        Get Request Address Response

        param request_link: -> string
            The url to be requested.
        return
            function:
                The interface returns the json format or html results of the interface.
            False:
                Interface request failure identification.
        """
        try:
            response = requests.get(request_link, timeout=3.0)
            time.sleep(5)

            if response.status_code == 200:

                return response.json() if ("wt=json" in request_link.split("&")) \
                    else response.content.decode('utf-8')

            else:
                print("\nThe URL request response code is not 200, "
                      "please check and re execute!")

                dp().file_read_write(self.fail_log, 'a', 'txt',
                                     "URL           : {} \n"
                                     "Response_code : {} \n \n".format(request_link, response.status_code))
                return False
        except Exception:
            return False

    def parse_response_html(self, url):
        """
        Parse the html format file returned by the url request.

        param url: -> string
            The url to be requested.
        return:
            html_parameter: -> dictionary
                Returns the download path list of the compressed package file.
            False: -> boolean
                The identifier when the interface request is lost or the returned result is empty.
        """
        version_list = []
        download_file_paths = []
        keyword_list = ["javadoc", "sources", "linux32", "test",
                        "linux64", "osx", "win64", "tests", "config"]
        package_type = ['gz', 'zip', 'jar', 'aar']

        deal_url = self.path.split('/')[-1].split('.')

        if not deal_url[0]:
            html_response = self.get_response(url)

            if not html_response:
                return False

            html_parser = etree.HTML(html_response,
                                     parser=etree.HTMLParser(encoding="utf-8"))
            html_parser_res = html_parser.xpath('//body/main/pre/a/@title')

            for parser_result in html_parser_res:
                parser_arg1 = parser_result.split('.')
                parser_arg2 = parser_result.strip('/')
                parser_arg3 = parser_result.split('/')[-1].split('.')[-1]
                parser_arg4 = parser_result.split('/')[-1].split('-')[-1].split(".")[0]

                if ('' not in parser_arg1 and
                        'xml' not in parser_arg1):
                    version_list.append(url.rstrip('/') + '/' + parser_arg2)

                if (parser_arg3 in package_type and
                        parser_arg4 not in keyword_list):
                    download_file_paths.append(url.rstrip('/') + '/' + parser_arg2)

            version_list.sort()

            html_parameter = {"version_list": version_list,
                              "download_file_path_list": download_file_paths}
            return html_parameter

    def maven_response_whether_empty(self, res):
        """
        Check if the maven API response is empty.
        param res: -> dictionary
            The maven warehouse API response data.
        return: -> list
            specified_data:
                Get the maven warehouse interface to respond to the specified data.
        """
        specified_data = []
        specified_keys = ['response', 'docs']

        if res:
            docs = res[specified_keys[0]][specified_keys[1]]

            return docs

        return specified_data

    def maven_response_parse(self, specified_version, docs):
        """
        The maven warehouse interface responds to specified data analysis.
        param specified_version: -> string
            Version corresponding to so package.
        param docs: -> list
            The maven warehouse interface responds to specified data.
        return: -> list

        """
        version_list = []
        specified_keys = ['p', 'jar', 'versionCount', 'latestVersion']

        for doc in docs:

            if (doc[specified_keys[0]] == specified_keys[1] and
                    doc[specified_keys[3]] > str(specified_version)):
                version_list.append(int(doc[specified_keys[2]]))

        return list(set(version_list))

    def check_version_total_size(self, size, set_size=10):
        """
        Check the number of versions, filter and save
        the total number of versions that meet the number requirements.
        param set_size: -> int
            Set the comparison value.
        param size: -> int
            The total number of actual versions.
        return: -> int
            Returns data that meets the comparison criteria.
        """
        if size <= set_size:
            return size

    def maven_response_get_max_version(self, version_list):
        """
        Based on the total number of versions collected,
        find the maximum value in the total number of versions.
        param version_list: -> list
            A list of version counts.
        return: -> int
            Maximum number of versions.
        """
        versions = list(filter(self.check_version_total_size, version_list))

        if versions:
            max_version = max(versions)

        else:
            max_version = max(version_list)

        return max_version

    def parse_response_json(self, request_link, specified_version):
        """
        Receive the response result dimension json type data, parse it,
        and obtain the url to be executed
        param request_link: -> string
            URL to be requested
        param specified_version: -> string
            Version corresponding to so package.
        return:
            sub_file_paths: -> dictionary
                All sub file paths in the current folder.
        """
        version_arg = "versionCount"
        path_list = []
        sub_file_paths = {}

        responses = self.get_response(request_link)
        docs = self.maven_response_whether_empty(responses)

        if not docs:
            return sub_file_paths

        version_list = self.maven_response_parse(specified_version, docs)

        if not version_list:
            return sub_file_paths

        max_version = self.maven_response_get_max_version(version_list)

        doc = list(filter(lambda x: x[version_arg] == max_version, docs))

        doc_id = doc[0]["id"]
        doc_arg1 = doc_id[:doc_id.rfind(":")].replace(".", "/")
        doc_arg2 = doc_id[doc_id.rfind(":"):].replace(":", "/")
        path = "{}{}".format(doc_arg1, doc_arg2)
        path_list.append("{}/".format(os.path.join(self.maven_url, path)))

        for path in path_list:
            key_names = path.split('maven2')[-1]
            parse_result = self.parse_response_html(path)
            if parse_result:
                sub_file_paths[key_names] = parse_result

        return sub_file_paths

    def create_folder_path(self, download_url, split_identification):
        """
        Create a save path for the download file.

        param download_url: -> string
            The url of the download file.
        param split_identification: -> string
            Identification of string slicing.
        return:
            new_folder_path: -> string
                Returns the absolute path to save the downloaded file.
        """
        folder_path = "/".join(download_url.split(split_identification)[-1].split("/")[:-1])
        new_folder_path = "{}{}/".format(self.file_download_path, folder_path)

        if not os.path.exists(new_folder_path):
            os.makedirs(new_folder_path)

        return new_folder_path

    def download_file(self, download_url, split_identification):
        """
        Download the file to the specified folder according to the path.

        param download_url: -> string
            The url of the file to be downloaded.
        param split_identification: -> string
            Identification of string slicing.
        return: -> boolean
            True: means success.
            False: means failure.
        """
        url_arg = download_url.split('/')[-1]
        file_path = "{}{}".format(self.file_download_path,
                                  download_url.split(split_identification)[-1])

        if not os.path.isfile(file_path):
            create_file_path = self.create_folder_path(download_url, split_identification)
            save_file_path = "{}{}".format(create_file_path, url_arg)

            try:
                urllib.request.urlretrieve(download_url, save_file_path)
            except Exception:
                return False

            return True

    def detect(self, version_path, log_type, github_mark=None):
        """
        Judge to evaluate. And execute corresponding operations.

        param version_path: -> string
            The absolute path of the downloaded package.
        param log_type: -> string
            When evaluating, specify the type of log file to save.
        return: -> list
            List of test result identifiers.
        """
        results = yt().custom_execution([version_path], 4, log_type, github_mark)
        return results

    def github_get_package(self, key):
        """
        Use the keyword to search the rest api of github,
        and obtain the download path of each version from the interface response data.

        param key: -> string
            Keywords to be searched.
        return:
            github_parameter: -> dictionary
                Returns a dictionary consisting of an identifier and
            a list of download addresses.
        """
        version_list = []

        mark_arg0 = 0
        mark_arg1 = 1
        tag_arg = "tag"
        version_arg = "versions"
        tag_key = "tag_name"
        items_key = "items"
        size_key = "size"
        full_key = "full_name"
        html_key = "html_url"
        releases_key = "releases_url"
        special_arg1 = "{"
        special_arg2 = "]"
        url_arg1 = "/archive/refs/tags/"
        url_arg2 = "/archive/refs/heads/master.zip"

        url_result = self.get_response("{}{}".format(self.github_api, key))

        if url_result:
            items = url_result[items_key]
            for item in items[:1]:  # 此处GitHub取值逻辑还没给，先默认为第一个

                if item[size_key] != mark_arg0:
                    name = item[full_key]
                    releases_url = item[releases_key].split(special_arg1)[0]
                    html_url = item[html_key]
                    releases_result = self.get_response(releases_url)

                    if releases_result:
                        if releases_result[1] != special_arg2:
                            for res in json.loads(releases_result):
                                version_list.append("{}{}{}{}.zip"
                                                    .format(self.github_url, name, url_arg1, res[tag_key]))
                            version_list.sort()

                        else:
                            version_list = ["{}{}{}".format(self.github_url, name, url_arg2)]

                        github_parameter = {tag_arg: mark_arg0,
                                            version_arg: version_list,
                                            html_key: html_url}

                        return github_parameter

        github_parameter = {tag_arg: mark_arg1,
                            version_arg: mark_arg1,
                            html_key: ""}

        return github_parameter

    def github_file_deal(self, paths, split_identification, log_type):
        """
        Process the files downloaded from github.

        param paths: -> list
            List of download paths of files on github.
        param split_identification: -> string
            Identification of string slicing.
        param log_type: -> string
            When evaluating, specify the type of log file to save.
        """
        for index in range(len(paths)):
            path_arg = paths[index].split(split_identification)[-1]
            pk_path = "{}{}".format(self.file_download_path, path_arg)
            res = self.download_file(paths[index], split_identification)

            if res:
                val = self.evaluation_result_processing(pk_path, log_type, "g")
                if val:
                    break

    def evaluation_result_processing(self, package_path, log_type, github_mark=None):
        """
        Process the scanning results of the evaluation tools.
        param package_path: -> string
            The path to save the downloaded compressed package.
        param log_type: -> string
            When evaluating, specify the type of log file to save.
        param github_mark: -> string
            The identification of the result obtained from the github warehouse.
        return: -> boolean
            mark_true: means that the minimum version meeting the requirements was found.
            mark_false: means that no compliant version was found.
        """
        mark_true = True
        mark_false = False
        shell_arg = "rm -rf"

        result = self.detect(package_path, log_type, github_mark)

        if (mark_true in result and
                mark_false not in result):

            subprocess.call("{} {}".format(shell_arg, package_path), shell=True)

            return mark_true

        else:
            subprocess.call("{} {}".format(shell_arg, package_path), shell=True)
            return mark_false

    def minimum_version_recommendation(self, parameter, log_type, split_identification, specified_version):
        """
        It is recommended that the minimum version that meets the evaluation migration.

        param parameter: -> dictionary
            Key value pair type parameter.
        param log_type: -> string
            When evaluating, specify the type of log file to save.
        param split_identification: -> string
            Identification of string slicing.
        param specified_version: -> string
            Version corresponding to so package.
        return:
            version_number: -> string
                Successfully recommended version.
            False: -> boolean
                The identity of the referral failure.
        """
        version_key = "version_list"
        path_key = "download_file_path_list"
        version_arg = "Version"
        result_arg = "Result"
        result_parameter = "This version does not contain jar class files."

        version_comparison_results = True

        for version_file in parameter[version_key]:  # 此处调节测试数据大小。
            version_number = version_file.split('/')[-1]

            if type(specified_version) is str:
                version_comparison_results = sp().version_compare(specified_version, str(version_number))

            if not version_comparison_results:
                return False

            parameter = self.parse_response_html("{}/".format(version_file))

            if not parameter:
                return False

            download_file_list = parameter[path_key]

            if len(download_file_list) > 0:
                package_path = "{}{}".format(self.file_download_path,
                                             download_file_list[0].split(split_identification)[-1])
                for download in download_file_list:
                    self.download_file(download, split_identification)
                val = self.evaluation_result_processing(package_path, log_type)

                if val:
                    return version_number
            else:
                print("{}: {} \n"
                      "{}: {} \n "
                      .format(version_arg, version_file.split(split_identification)[-1],
                              result_arg, result_parameter))
        return False

    def maven_search_key_check(self, urls, search_key, log_type, specified_version):
        """
        Search for relevant installation packages through keywords,
        download them, and use migration tools to detect them.

        param urls: -> list
            The list of urls formed by the search keywords passed in from the command line.
        param search_keys: -> list
            List of keywords to search.
        param log_type: -> string
            When evaluating, specify the type of log file to save.
        param specified_version: -> string
            Version corresponding to so package.
        return:
            parameter: -> dictionary
                The dictionary contains search source tags and minimum versions.
        """
        split_arg1 = "maven2"

        for index in range(len(urls)):
            result = self.parse_response_json(urls[index], specified_version)

            if result:
                keys = list(result.keys())
                version_result = self.minimum_version_recommendation(result[keys[0]],
                                                                     log_type,
                                                                     split_arg1,
                                                                     specified_version)

                if version_result:
                    parameter = {"mark": 0, "version": version_result}

                    return parameter
            try:
                parameter = self.github_search_key_check(search_key[index], log_type)
            except Exception:
                parameter = {"mark": -1, "version": ''}

            return parameter

    def github_search_key_check(self, search_key, log_type):
        """
        Search keywords in the github repository to obtain the corresponding url.
        param search_key: -> string
            The keyword to search for.
        param log_type: -> string
            When evaluating, specify the type of log file to save.
        return: -> dictionary
            result:
                github repository search results.
        """
        digit_one = 1
        tag_key = "tag"
        html_key = "html_url"

        dictionaries = self.github_get_package(search_key)
        tag_value = dictionaries[tag_key]

        if tag_value == digit_one:
            result = {"mark": -1, "version": ""}
        else:
            # self.github_file_deal(versions_value, split_arg2, log_type)
            result = {"mark": 1, "version": dictionaries[html_key]}

        return result

    def maven_source_check(self, urls, log_type):
        """
        The corresponding data is crawled according to the url of the command line.

        param urls: -> list
            The list of urls formed by the search keywords passed in from the command line.
        param log_type: -> string
            When evaluating, specify the type of log file to save.
        return： -> string
            The minimum version number that matches.
        """
        split_arg = "maven2"
        recommendation_result = None

        for link in urls:
            parameter_dictionary = self.parse_response_html(link)

            if parameter_dictionary:
                recommendation_result = self.minimum_version_recommendation(parameter_dictionary,
                                                                            log_type,
                                                                            split_arg,
                                                                            0)

        return recommendation_result

    def self_recommended(self, rows, str_type, identification, keys, log_type, specified_version):
        """
        When an incompatible package is detected by the evaluation tools,
        you can call this method to search the maven warehouse.
        If the maven warehouse does not exist, you can enter github to search.

        param rows: -> number
            Set the number of Maven warehouse rest api response results.
        param str_type: -> string
            Set the return format of Maven warehouse rest api response data.
        param identification: -> number
            Identify whether to search by keyword or request by url.
        param keys: -> list
            List of keywords to search.
        param log_type: -> string
            Set the format type of the saved result file. For example: csv, json, txt.
        param specified_version: -> string
            Version corresponding to so package.
        return: -> function
            Call the recommended method function.
        """
        result_data = self.search_rules(rows, str_type, identification, keys)

        search_arg = result_data["search_list"]
        keys_arg = result_data["keys_list"]
        mark_arg = result_data["identification"]

        log_arg = log_type

        return self.recommended_method(mark_arg, search_arg, keys_arg,
                                       log_arg, specified_version)

    def recommended_method(self, mark, url_list, key_list, log_mode, specified_version):
        """
        This function is used to distinguish whether to search by keyword or
        go directly to the Maven warehouse to find the corresponding package according
        to the url of the Maven warehouse.

        param mark: -> number
            Identify whether to search by keyword or request by url.
        param url_list: -> list
            List of urls to search.
        param key_list: -> list
            List of keywords to search.
        param log_mode: -> string
             Set the format type of the saved result file. For example: csv, json, txt.
        param specified_version: -> string
            Version corresponding to so package.
        return: -> function
            Keyword search function.
        """
        if mark == 0:
            return self.maven_search_key_check(url_list, key_list,
                                               log_mode, specified_version)

        else:
            return self.maven_source_check(url_list, log_mode)


def main():
    """
    Execution function.
    """
    csv_arg = 'csv'
    csv_header_info = ["NAME", "MD5", "COMPATIBILITY", "TYPE", "INCOMPATIBILITY", "CONCLUSION",
                       "UPGRADE", "NAME", "TYPE-SRC", "PACKAGE", "VERSION"]

    start_time = time.time()

    tool = RecommendedTools()

    parameters = tool.search_package(10, "json")
    log_arg = parameters["log_type"]
    search_arg = parameters["search_list"]
    keys_arg = parameters["keys_list"]
    mark_arg = parameters["identification"]

    init_command = "rm -rf {}".format(tool.ep_temp_files)

    subprocess.call(init_command, shell=True)

    if log_arg == csv_arg:
        dp().create_csv_log(tool.arm_file, csv_header_info[:4], log_arg)
        dp().create_csv_log(tool.not_arm_file, csv_header_info, log_arg)

    tool.recommended_method(mark_arg, search_arg, keys_arg, log_arg, 0)

    end_time = time.time()
    run_time = "Running time: {:.3f} Seconds \n ".format(end_time - start_time)

    return run_time


if __name__ == '__main__':
    print(main())
