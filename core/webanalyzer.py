#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time

import urllib3
import hashlib
import logging
import requests
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from .utils import update
from .condition import Condition

__all__ = ["WebAnalyzer"]

urllib3.disable_warnings()
logger = logging.getLogger('webanalyzer')

RULES = {}
RULE_TYPES = set()
DEFAULT_RULE_DIR = os.path.join(os.getcwd(), "rules")
REPOSITORY = "webanalyzer/rules"


class WebAnalyzer(object):
    def __init__(self):
        self.aggression = False
        self.url = None
        self.timeout = 30
        self.allow_redirect = True
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15'
        }
        self.proxies = None
        self.max_threads = 20
        self.rule_dir = DEFAULT_RULE_DIR

        self._req_sent = 0
        self._targets = {}
        self._cond_parser = Condition()

    def update_rules(self) -> bool:
        return update(REPOSITORY, self.rule_dir)

    @staticmethod
    def list_rules():
        return RULES

    def reload_rules(self) -> int:
        global RULES, RULE_TYPES
        new_rules = {}
        new_rule_types = set()
        for root, dirs, files in os.walk(self.rule_dir):
            for file in files:
                path = os.path.join(root, file)
                if not path.endswith('.json'):
                    continue

                if root[len(self.rule_dir):].replace("\\", "/").strip("/"):
                    rule_type = root[len(self.rule_dir):].replace("\\", "/").strip("/").split("/")[0]
                else:
                    rule_type = "unknown"
                new_rule_types.add(rule_type)

                with open(path, encoding="utf-8") as fd:
                    try:
                        data = json.load(fd)
                        for match in data['matches']:
                            if 'regexp' in match:
                                match['regexp'] = re.compile(match['regexp'], re.I)

                            if 'certainty' not in match:
                                match['certainty'] = 100

                        data['origin'] = rule_type
                        key = '%s_%s' % (rule_type, data['name'])  # 用于去重
                        new_rules[key] = data
                    except Exception as e:
                        logger.error('parse %s failed, error: %s' % (path, e))

        RULES = new_rules
        RULE_TYPES = new_rule_types
        return len(RULES)

    def set_proxy(self, proxy: str) -> bool:
        if proxy:
            self.proxies = {"https": proxy, "http": proxy}
            return True
        return False

    def _request(self, url: str) -> dict:
        """
        发送请求，缓存各项响应信息到self._targets并返回响应信息
        :param url:
        :return:
        """
        try:
            self._req_sent += 1
            logger.debug("send request to %s" % url)
            rp = requests.get(url, headers=self.headers, proxies=self.proxies, verify=False, timeout=self.timeout,
                              allow_redirects=self.allow_redirect)
        except Exception as e:
            logger.error("request error: %s" % str(e))
            return None

        script = []
        meta = {}

        p = BeautifulSoup(rp.text, "html5lib")

        for data in p.find_all("script"):
            script_src = data.get("src")
            if script_src:
                script.append(script_src)

        for data in p.find_all("meta"):
            meta_name = data.get("name")
            meta_content = data.get("content", "")
            if meta_name:
                meta[meta_name] = meta_content

        title = p.find("title")
        if title:
            title = title.text
        else:
            title = ""

        raw_headers = '\n'.join('{}: {}'.format(k, v) for k, v in rp.headers.items())
        self._targets[url] = {
            "url": url,
            "body": rp.text,
            "headers": rp.headers,
            "status": rp.status_code,
            "script": script,
            "meta": meta,
            "title": title,
            "cookies": rp.cookies,
            "raw_cookies": rp.headers.get("set-cookie", ""),
            "raw_response": raw_headers + rp.text,
            "raw_headers": raw_headers,
            "md5": hashlib.md5(rp.content).hexdigest(),
        }

        return self._targets[url]

    def _check_match(self, match: dict, aggression: bool = False) -> (bool, str, str):
        s = {'regexp', 'text', 'md5', 'status'}  # 如果增加新的检测方式，需要修改这里
        if not s.intersection(list(match.keys())):
            return False, None, None

        target = self._targets[self.url]
        if 'url' in match:
            full_url = urllib.parse.urljoin(self.url, match['url'])
            if match['url'] == '/':  # 优化处理
                pass
            elif full_url in self._targets:
                target = self._targets[full_url]
            elif aggression:
                target = self._request(full_url)
            else:
                # logger.debug("match has url(%s) field, but aggression is false" % match['url'])
                return False, None, None

        if not target:
            return False, None, None

        # parse search
        search_context = target['body']
        if 'search' in match:
            if match['search'] == 'all':
                search_context = target['raw_response']
            elif match['search'] == 'headers':
                search_context = target['raw_headers']
            elif match['search'] == 'script':
                search_context = target['script']
            elif match['search'] == 'title':
                search_context = target['title']
            elif match['search'] == 'cookies':
                search_context = target['raw_cookies']
            elif match['search'].endswith(']'):
                for i in ('headers', 'meta', 'cookies'):
                    if not match['search'].startswith('%s[' % i):
                        continue

                    key = match['search'][len('%s[' % i):-1]
                    if key not in target[i]:
                        return False, None, None
                    search_context = target[i][key]


        version = match.get('version', None)
        detail = None
        for key in list(match.keys()):
            if key == 'status':
                if match['status'] != target['status']:
                    return False, None, None
                else:
                    detail = 'response status of %s match %s' % (target['url'], match['status'])

            if key == 'md5':
                if target['md5'] != match['md5']:
                    return False, None, None
                else:
                    detail = 'md5 of body of %s match %s' % (target['url'], match['md5'])

            if key == 'text':
                search_contexts = search_context
                if isinstance(search_context, str):
                    search_contexts = [search_context]

                for search_context in search_contexts:
                    if match[key] not in search_context:
                        continue
                    detail = 'text "%s" in %s of %s' % (match[key], match['search'], target['url']) if 'search' in match \
                        else 'text "%s" in body of %s' % (match[key], target['url'])
                    break
                else:
                    return False, None, None

            if key == 'regexp':
                search_contexts = search_context
                if isinstance(search_context, str):
                    search_contexts = [search_context]

                for search_context in search_contexts:
                    result = match[key].search(search_context)
                    if not result:
                        continue

                    if 'version' in result.groupdict():
                        version = result.group('version')
                    elif 'offset' in match:
                        if len(result.groups()) > match['offset']:
                            version = result.groups()[match['offset']]
                        else:
                            _version = ''.join([m for m in result.groups() if m])
                            if _version:
                                version = _version

                    detail = 'regex "%s" match %s of %s' % (match[key].pattern, match['search'], target['url']) if 'search' in match \
                        else 'regex "%s" match body of %s' % (match[key].pattern, target['url'])
                    break
                else:
                    return False, None, None

        return True, version, detail

    def _check_rule(self, rule: dict) -> dict:
        matches = rule['matches']

        cond_map = {}
        result = {
            'name': rule['name']
        }

        for index, match in enumerate(matches):
            aggression = False
            if self.aggression == 2:
                aggression = True
            elif self.aggression == 1 and rule['origin'] == 'custom':
                aggression = True

            is_match, version, detail = self._check_match(match, aggression=aggression)
            if is_match:
                cond_map[str(index)] = True
                if version:
                    result['version'] = version
                if detail:
                    result['detail'] = detail
            else:
                cond_map[str(index)] = False

        result['origin'] = rule['origin']

        # default OR
        if 'condition' not in rule:
            if any(cond_map.values()):
                return result
            return

        if self._cond_parser.parse(rule['condition'], cond_map):
            return result

    def test_rule(self, url: str, rule_path: str) -> dict:
        if not os.path.exists(rule_path):
            logger.warning("%s does not exists, exit" % os.path.abspath(rule_path))
            return

        self.url = url
        self._request(self.url)

        with open(rule_path) as fd:
            rule = json.load(fd)

            if len(rule['matches']) == 0:
                logger.info("matches empty, return")
                return

            rule['origin'] = 'test'

            for match in rule['matches']:
                if 'regexp' in match:
                    match['regexp'] = re.compile(match['regexp'], re.I)

                if 'certainty' not in match:
                    match['certainty'] = 100

            return self._check_rule(rule)

    def start(self, url: str, reload: bool = True):
        logger.debug("process %s" % url)
        self.url = url
        self._req_sent = 0
        pool = ThreadPoolExecutor(max_workers=self.max_threads)
        future_list = []
        results = []
        implies = set()
        excludes = set()

        try:
            if not self._request(url):
                logger.info("request %s failed" % url)
                return

            self._request(urllib.parse.urljoin(url, '/favicon.ico'))

            if reload:
                self.reload_rules()

            def callback(future):
                future_list.remove(future)

                e = future.exception()
                if e:
                    logger.error("check rule error: %s" % e)
                    return

                r = future.result()
                if r:
                    if 'implies' in rule:
                        if isinstance(rule['implies'], str):
                            implies.add(rule['implies'])
                        else:
                            implies.update(rule['implies'])

                    if 'excludes' in rule:
                        if isinstance(rule['excludes'], str):
                            excludes.add(rule['excludes'])
                        else:
                            excludes.update(rule['excludes'])

                    if r['name'] in excludes:
                        return
                    results.append(r)

            for name, rule in RULES.items():
                future = pool.submit(self._check_rule, rule)
                future_list.append(future)
                future.add_done_callback(callback)
                if len(future_list) > self.max_threads + 32:
                    time.sleep(0.2)
            pool.shutdown(wait=True)

        except KeyboardInterrupt:
            logger.info("User abort...")
            pool.shutdown(wait=True)


        for imply in implies:
            _result = {
                'name': imply,
                "origin": 'implies'
            }

            for rule_type in RULE_TYPES:
                rule_name = '%s_%s' % (rule_type, imply)

                rule = RULES.get(rule_name)
                if not rule:
                    continue

                if 'excludes' in rule:
                    if isinstance(rule['excludes'], str):
                        excludes.add(rule['excludes'])
                    else:
                        excludes.update(rule['excludes'])

            if _result['name'] in excludes:
                continue
            results.append(_result)

        logger.debug("Done. %d requests had sent" % self._req_sent)
        return results
