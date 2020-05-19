# localdataHog
String-based secret-searching tool (high entropy and regexes) based on truffleHog.

# About

This code is entirely based on https://github.com/dxa4481/truffleHog. 

The main difference is that whereas truffleHog was built with git repositories in mind, this tool is an attempt of applying truffleHog approach (potential secret searching leveraging both regular expressions and entropy calculation) against any data (although for it to be effective, data should not be encoded nor compressed).

The tool simply iterates over all files from the given path (`find path`), runs `strings` on each one and then runs regex and entropy checks against each string. Then reports caught strings per file.

# Usage:
Simply run

`python3 localdataHog.py /target/directory | tee hog.log`

in order to get the results printed both to the standard output and saved into a log file hog.log.


Two modes of secret search are supported (both are enabled by default):

`--regex` 	Checks each of the strings against a set of regular expressions. By default it takes ones defined in regexes.json, which can be used as a template for customisation. Use `--rules` in order to provide an alternative JSON file with own regular expressions. In order to disable this mode, use `--noregex`.

`--entropy`	Reports strings with high entropy. Use `--noentropy` to disable this mode.
	
For cleaner results, you might consider splitting the work into phases, whereas you run regex check and entropy check separately:

`python3 --noentropy localdataHog.py /target/directory | tee regexhog.log`

`python3 --noregex localdataHog.py /target/directory | tee entropyhog.log`

Also, you can skip results (common false positives) by defining regexes in `filter_regexes.json`.


