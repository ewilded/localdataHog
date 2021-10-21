#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import shutil
import sys
import math
import datetime
import argparse
import uuid
import hashlib
import os
import platform
import re
import json
import stat
import subprocess

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"
regexes = dict()
filter_regexes = dict()

def main():
    parser = argparse.ArgumentParser(description='Find secrets in data')
    parser.add_argument("--regex", dest="do_regex", action="store_true", help="Enable regex checks (default)")
    parser.add_argument("--noregex", dest="do_regex", action="store_false", help="Disable regex checks")
    parser.add_argument("--rules", dest="rules", help="Ignore default regexes and source from json list file")
    parser.add_argument("--entropy", dest="do_entropy", action="store_true", help="Entropy checks (default)")
    parser.add_argument("--noentropy", dest="do_entropy", action="store_false", help="Disable entropy checks")
    parser.add_argument('-i', '--include_paths', type=argparse.FileType('r'), metavar='INCLUDE_PATHS_FILE',
                        help='File with regular expressions (one per line), at least one of which must match a Git '
                             'object path in order for it to be scanned; lines starting with "#" are treated as '
                             'comments and are ignored. If empty or not provided (default), all Git object paths are '
                             'included unless otherwise excluded via the --exclude_paths option.')
    parser.add_argument('-x', '--exclude_paths', type=argparse.FileType('r'), metavar='EXCLUDE_PATHS_FILE',
                        help='File with regular expressions (one per line), none of which may match a Git object path '
                             'in order for it to be scanned; lines starting with "#" are treated as comments and are '
                             'ignored. If empty or not provided (default), no Git object paths are excluded unless '
                             'effectively excluded via the --include_paths option.')

    parser.add_argument('path', type=str, help='Path for secret searching')
    parser.set_defaults(do_regex=True)
    parser.set_defaults(do_entropy=True)
    parser.set_defaults(rules={})

    args = parser.parse_args()
    rulefile = os.path.join(os.path.dirname(os.path.abspath(__file__)),"regexes.json")
    filterfile = os.path.join(os.path.dirname(os.path.abspath(__file__)),"filter_regexes.json")
    if args.rules and os.path.isfile(args.rules):
        rulefule = args.rules

    rules = {}
    filter_rules = {}

    try:
        with open(rulefile, "r") as ruleFile:
            rules = json.loads(ruleFile.read())
            for rule in rules:
                rules[rule] = re.compile(rules[rule])
    except (IOError, ValueError) as e:
        raise("Error reading rules file")
    for regex in rules:
        regexes[regex] = rules[regex]

    try:
        with open(filterfile, "r") as filterFile:
            filter_rules = json.loads(filterFile.read())
            for filter_rule in filter_rules:
                filter_rules[filter_rule] = re.compile(filter_rules[filter_rule])

    except (IOError, ValueError) as e:
        raise("Error reading filter rules file")
    for filter_regex in filter_rules:
        filter_regexes[filter_regex] = re.compile(filter_rules[filter_regex])

    do_entropy = args.do_entropy
    do_regex = args.do_regex

    # read & compile path inclusion/exclusion patterns
    path_inclusions = []
    path_exclusions = []
    if args.include_paths:
        for pattern in set(l[:-1].lstrip() for l in args.include_paths):
            if pattern and not pattern.startswith('#'):
                path_inclusions.append(re.compile(pattern))
    if args.exclude_paths:
        for pattern in set(l[:-1].lstrip() for l in args.exclude_paths):
            if pattern and not pattern.startswith('#'):
                path_exclusions.append(re.compile(pattern))
    find_strings(args.path, args.do_regex, do_entropy, path_inclusions=path_inclusions, path_exclusions=path_exclusions)
    sys.exit(0)

def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def report_results(path, f):
    # for if the result does not match any of the filter_rules, simply print it to stdout
    for string_found in f:
        string_filtered = False
        for filter_regex in filter_regexes:
            if filter_regexes[filter_regex].match(string_found):
                string_filtered = True
                break
        if string_filtered == False:
            if(len(string_found)>100):
                string_found=string_found[:100]
            print(path+":"+string_found)
    #bcolors.OKGREEN, string_found, bcolors.ENDC)

def find_entropy(strings_output, file_path): # so, this identifies base64 and hex high entropy strings, this should be used in conjunction with 'strings' output to be more efficient
    strings_found = []
    lines = strings_output.split("\n")
    for line in lines:
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5:
                    strings_found.append(string)
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    strings_found.append(string)
    if len(strings_found) > 0:
        report_results(file_path, list(set(strings_found)))

def regex_check(strings_output, file_path, custom_regexes={}):
    if custom_regexes:
        secret_regexes = custom_regexes
    else:
        secret_regexes = regexes
    regex_matches = []
    for key in secret_regexes:
        strings_found = secret_regexes[key].findall(strings_output)
        report_results(file_path, list(set(strings_found)))

def path_included(path, include_patterns=None, exclude_patterns=None):
    if include_patterns and not any(p.match(path) for p in include_patterns):
        return False
    if exclude_patterns and any(p.match(path) for p in exclude_patterns):
        return False
    return True

def find_strings(path, do_regex=True, do_entropy=True, custom_regexes={},path_inclusions=None, path_exclusions=None):
    # 1. find ALL files
    # 2. iterate the results and skip the files that should not be included as per include/exclude args
    # 3. obtain strings output
    # 4. process the strings (regex_check + find_entropy) output for each invdividual file, if stuff is found, print it right away to stdout AND the log file
    while path.endswith('/') or path.endswith('\\'):
            path = path[:-1] # remove any trailing slashes, cmd.exe /c dir /s /b doesn't like them
    if path == '' and platform.system() == 'Linux':
        path = '/'
    windows_dir = ['cmd', '/c', 'dir', '/s', '/b', path]
    windows_findstr = ['findstr', '/R', '.']
    linux_find = ['find', path]
    linux_strings = ['strings']
    strings_command = ''
    find_command = ''
    if platform.system() == 'Windows':
        strings_command = windows_findstr
        find_command = windows_dir
    else:
        strings_command = linux_strings
        find_command = linux_find
    find_result = subprocess.run(find_command, stdout=subprocess.PIPE)
    for file in find_result.stdout.decode('utf-8').strip().split("\n"):
        file = file.strip()
        if file == '' or not path_included(file, path_inclusions, path_exclusions) or os.path.isdir(file):
            continue
        full_strings_command = strings_command + [file]
        strings_result = subprocess.run(full_strings_command, stdout=subprocess.PIPE)   # add support for windows widechar strings here (if file is of PE executable type, run "strings -e l file" instead or of "strings file" or in addition - running ASCII strings on execs by default produces lots of high entropy strings that are not passwords)
        strings_output = strings_result.stdout.decode('utf-8').strip()
        if do_regex:
            regex_check(strings_output, file)
        if do_entropy:
            find_entropy(strings_output, file)

if __name__ == "__main__":
    main()
