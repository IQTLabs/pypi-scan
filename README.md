[![Build Status](https://travis-ci.com/jspeed-meyers/pypi-scan.svg?branch=master)](https://travis-ci.com/jspeed-meyers/pypi-scan)
[![codecov](https://codecov.io/gh/jspeed-meyers/pypi-scan/branch/master/graph/badge.svg)](https://codecov.io/gh/jspeed-meyers/pypi-scan)
[![GitHub license](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/jspeed-meyers/pypi-scan/blob/master/LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# pypi-scan
Scan pypi for typosquatting

Have you ever wanted to see if other packages are typosquatting your pypi package or
any pypi package of interest? Have you ever wanted to check the most downloaded packages
on pypi for potential typosquatters? What about create a list of potential typosquatting names for a package you maintain so that you can go claim those names yourself on pypi? You can do both of these actions with pypi-scan.

Pypi (the Python Package Index) is a repository for Python packages. It's like a store
where anybody with an internet connection can download (for free) Python packages.
Typosquatting is a practice in which someone chooses a package name that is similar to
an existing package and places a malicious package in this deceptively titled namespace.
Imagine you want to download the package 'numpy' but you mistype that name and spell
'nunpy' instead. You then download a malicious package. Of course, not all packages with
similar names are malicious, but some might be. 

## Usage

List potential typosquatters on numpy:
```
>>> python main.py -m numpy
Checking numpy for typosquatting candidates.
0: bumpy
1: dumpy
2: gnumpy
...(outputed shortened)
```

List potential typosquatters on top packages:
```
>>> python main.py -o top-mods
Number of top packages to examine: 43
urllib3 : ['urllib4', 'urllib5']
botocore : ['kotocore']
...(output shortened)
```

Advanced usage includes use of several switches:
```
# Search top 100 pypi packages, if the package name is of at least length
# 4 and for all typosquatters within an edit distance of two. See the help
# section below for further explanation of switches.
>>> python main.py -o top-mods -e 2 -n 100 -l 4
```

## Installation

Download to your local machine via git:
```
git clone https://github.com/jspeed-meyers/pypi-scan
```

Navigate to folder that contains main.py:
```
cd pypiscan/pypiscan
```

After navigating to folder that contains main.py, ensure dependencies are
installed and then run tests:
```
pip install -r requirements.txt
python -m unittest
```

## Help

Get help on command line options by navigating to folder that contains main.py
and running this command:
```
>>> python main.py -h
usage: main.py [-h] [-o {mod-squatters,top-mods}] [-m MODULE_NAME]
               [-e EDIT_DISTANCE] [-n NUMBER_PACKAGES] [-l LEN_PACKAGE_NAME]
               [-s]

optional arguments:
  -h, --help            show this help message and exit
  -o {mod-squatters,top-mods}, --operation {mod-squatters,top-mods}
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
