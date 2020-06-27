[![Build Status](https://travis-ci.com/jspeed-meyers/pypi-scan.svg?branch=master)](https://travis-ci.com/jspeed-meyers/pypi-scan)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/d1731169a12d42da81da02b249ca069c)](https://www.codacy.com/manual/jmeyers/pypi-scan?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=jspeed-meyers/pypi-scan&amp;utm_campaign=Badge_Grade)
[![codecov](https://codecov.io/gh/jspeed-meyers/pypi-scan/branch/master/graph/badge.svg)](https://codecov.io/gh/jspeed-meyers/pypi-scan)
[![Requirements Status](https://requires.io/github/jspeed-meyers/pypi-scan/requirements.svg?branch=master)](https://requires.io/github/jspeed-meyers/pypi-scan/requirements/?branch=master)
[![Python 3.7](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![Python 3.8](https://img.shields.io/badge/python-3.8-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![GitHub license](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/jspeed-meyers/pypi-scan/blob/master/LICENSE)

# pypi-scan
Scan pypi for typosquatting

Have you ever wanted to see if other packages are typosquatting your pypi package or
any pypi package of interest? Have you ever wanted to check the most downloaded packages
on pypi for potential typosquatters? What about create a list of potential typosquatting names for a package you maintain so that you can go claim those names yourself on pypi? You can do all of these actions with pypi-scan.

Pypi (the Python Package Index) is a repository for Python packages. It's like a store
where anybody with an internet connection can download (for free) Python packages.
Typosquatting is a practice in which someone chooses a package name that is similar to
an existing package and places a malicious package in this deceptively titled namespace.
Imagine you want to download the package 'numpy' but you mistype that name and spell
'nunpy' instead. You then download a malicious package. Of course, not all packages with
similar names are malicious, but some might be.

To determine if a package is a potential typosquatter, pypi-scan employs [Levenshtein distance](https://en.wikipedia.org/wiki/Levenshtein_distance),
which is, roughly speaking, a measure of how many edits are required to transform one string of
characters into another. The default edit distance is one.

## Usage
(Requires an internet connection.)

List potential typosquatters on a specific package (e.g. numpy):
```
>>> python main.py -m numpy
Checking numpy for typosquatting candidates.
0: bumpy
1: dumpy
2: gnumpy
...
```
Timing info: ~10 seconds


List potential typosquatters on top packages:
```
>>> python main.py -o top-mods
Number of top packages to examine: 43
urllib3 : ['urllib4', 'urllib5']
botocore : ['kotocore']
...
```
Timing info: ~15 seconds

Advanced usage includes use of several switches:
```
# Search top 100 pypi packages, if the package name is of at least length
# 4 and for all typosquatters within an edit distance of two. See the help
# section below for further explanation of switches.
>>> python main.py -o top-mods -e 2 -n 100 -l 4
...
```
Timing info: ~20 seconds

List potential names that typosquatters might choose for a particular package.
A user could then defensively register these names on pypi. This functionality uses
QWERTY distance, not Levenshtein distance. QWERTY distance measures distances by
the distance between keys on a computer keyboard.
```
>>> python main.py -o defend-name -m pandas
Here is a list of similar names--measured by keyboard distance--to "pandas":
0: pabdas
1: panfas
2: pansas
...(output shortened)
```
Timing info: ~1 second

Alternatively, to build and run a container via Docker:
```
docker build -t pypi-scan .
# To open bash shell inside container
docker run -it test_app bash
```
All commands can then be run from the command line inside the container.

## Installation

Download to your local machine via git:
```
git clone https://github.com/jspeed-meyers/pypi-scan
```

After navigating to folder that contains main.py, ensure dependencies are
installed and then run tests:
```
cd pypiscan/pypiscan
pip install -r requirements.txt
python -m unittest
```

## Help

Get help on command line options by navigating to folder that contains main.py
and running this command:
```
>>> python main.py -h
usage: main.py [-h] [-o {mod-squatters,top-mods,defend-name}] [-m MODULE_NAME]
               [-e EDIT_DISTANCE] [-n NUMBER_PACKAGES] [-l LEN_PACKAGE_NAME]
               [-s]

optional arguments:
  -h, --help            show this help message and exit
  -o {mod-squatters,top-mods,defend-name}, --operation {mod-squatters,top-mods,defend-name}
                        Specify operation to perform. (default: mod-squatters)
  -m MODULE_NAME, --module_name MODULE_NAME
                        Module name to check for typosquatters. (default:
                        None)
  -e EDIT_DISTANCE, --edit_distance EDIT_DISTANCE
                        Maximum edit distance to check. (default: 1)
  -n NUMBER_PACKAGES, --number_packages NUMBER_PACKAGES
                        Specify number of top packages to scan (default: 50)
  -l LEN_PACKAGE_NAME, --len_package_name LEN_PACKAGE_NAME
                        Specify minimum length of package name (default: 5)
  -s, --stored_json     Use a stored top package list (default: False)
```
NOTE: This command line interface is under development and could have changed.

More coming soon...
