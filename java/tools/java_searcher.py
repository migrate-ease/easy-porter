#!/usr/bin/env python
# -*- coding: utf-8 -*-
# time: 2023/2/24 17:24
import json

from tools.request_util import MyRequests


class RepositorySearch:

    def __init__(self):
        self.base_url = 'https://central.sonatype.com/v1/browse'
        self.versions_url = "https://central.sonatype.com/v1/browse/component_versions"
        self.repo_base_url = "https://repo1.maven.org/maven2/"
        self.request = MyRequests()
        self.components_info = []
        self.component_list = []
        self.db_path = None

    def get_name_components(self, search):
        name_space, jar_name = None, None
        data = {'searchTerm': search, 'size': 100, 'filter': []}
        data_palyload = json.dumps(data)
        headers = {
            "content-type": "application/json",
        }
        result = self.request.post(self.base_url, data_palyload, headers=headers)
        if result:
            components = result.get('components', [])
            if components:
                components = sorted(components, key=lambda x: x['dependencyOfCount'], reverse=True)
                name_space = components[0].get('namespace', 0)
                jar_name = components[0].get('name', 0)
        return name_space, jar_name

    def get_component_versions(self, data, name_space, jar_name):
        pageCount = data.get('pageCount', 0)
        pageSize = data.get('pageSize', 0)
        size = pageCount * pageSize
        result = self.get_versions_data(name_space, jar_name, size)
        if result:
            components = result.get('components', [])
            if components:
                self.components_info = sorted(components, key=lambda x: x['dependencyOfCount'], reverse=True)

    def get_versions_data(self, name_space, jar_name, size=10):
        if size > 50:
            size = 50
        data = {
            "sortField": "normalizedVersion",
            "sortDirection": "desc",
            "page": 0,
            "size": size,
            "filter":
                [
                    "namespace:{}".format(name_space),
                    "name:{}".format(jar_name)
                ]
        }
        headers = {
            "content-type": "application/json",

        }
        data_palyload = json.dumps(data)
        result = self.request.post(self.versions_url, data_palyload, headers=headers)
        return result

    def get_snippets(self, name_space, jar_name, version):
        snippet = "<dependency>\n" + \
                  "    <groupId>{}</groupId>\n" + \
                  "    <artifactId>{}</artifactId>\n" + \
                  "    <version>{}</version>\n" + \
                  "</dependency>"
        snippet = snippet.format(name_space, jar_name, version)
        return snippet

    def get_downlod_url(self, name_space, name, version):
        if '.' in name_space:
            temp_url = name_space.replace('.', '/')
            repo_url = self.repo_base_url + temp_url + '/' + name + '/' + version + '/' + name + '-' + version + '.jar'
        else:
            repo_url = self.repo_base_url + name_space + '/' + name + '/' + version + '/' + name + '-' + version + '.jar'
        return repo_url

    def exec_search(self, db_path, search):
        self.db_path = db_path
        name_space, jar_name = self.get_name_components(search)
        data = self.get_versions_data(name_space, jar_name)
        if data:
            self.get_component_versions(data, name_space, jar_name)
            if self.components_info:
                pakage_url = self.components_info[0].get("id", '')
                usages = self.components_info[0].get("dependencyOfCount", 0)
                version = self.components_info[0].get("version", '')
                description = self.components_info[0].get("description", '')
                repo_url = self.get_downlod_url(name_space, jar_name, version)
                snippet = self.get_snippets(name_space, jar_name, version)
                result = [jar_name, version, usages, pakage_url, repo_url, snippet, description]
                return True, result
        return False, []
