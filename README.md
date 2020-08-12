[![Build Status](https://travis-ci.com/jspeed-meyers/pypi-scan.svg?branch=master)](https://travis-ci.com/jspeed-meyers/pypi-scan)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/d1731169a12d42da81da02b249ca069c)](https://www.codacy.com/manual/jmeyers/pypi-scan?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=jspeed-meyers/pypi-scan&amp;utm_campaign=Badge_Grade)
[![codecov](https://codecov.io/gh/jspeed-meyers/pypi-scan/branch/master/graph/badge.svg)](https://codecov.io/gh/jspeed-meyers/pypi-scan)
[![Requirements Status](https://requires.io/github/jspeed-meyers/pypi-scan/requirements.svg?branch=master)](https://requires.io/github/jspeed-meyers/pypi-scan/requirements/?branch=master)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/4133/badge)](https://bestpractices.coreinfrastructure.org/projects/4133)
[![Documentation Status](https://readthedocs.org/projects/pypi-scan/badge/?version=latest)](https://pypi-scan.readthedocs.io/en/latest/?badge=latest)
[![Python 3.7](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![Python 3.8](https://img.shields.io/badge/python-3.8-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# pypi-scan
Scan PyPI for typosquatting

There are four anti-typosquatting functionalities in pypi-scan:

-  Check if there are potential typosquatters on a package you care about.
-  Check if there are potential typosquatters on the most downloaded PyPI packages.
-  Check if packages newly added to PyPI are potential typosquatters.
-  Create list of package names that a typosquatter might use.

PyPI (the Python Package Index) is a repository for Python packages. It's like
a store where anybody with an internet connection can download (for free) Python
packages. Typosquatting is a practice in which someone chooses a package name
that is similar to an existing package and places a malicious package in this
deceptively titled namespace. Imagine you want to download the package 'numpy'
but you mistype that name and spell 'nunpy' instead. You then download a
malicious package. Of course, not all packages with similar names are malicious,
but some might be.

To determine if a package is a potential typosquatter, pypi-scan employs
[Levenshtein distance](https://en.wikipedia.org/wiki/Levenshtein_distance),
which is, roughly speaking, a measure of how many edits are required to
transform one string of characters into another. The default edit distance
is one. pypi-scan also checks for "confusion attacks," e.g. switching the
order of words around a dash or underscore. Imagine confusing python-nmap
with nmap-python. Finally, when scanning the most downloaded packages,
pypi-scan checks PyPI package metadata to check if there are identical
fields between the real package and the potential typosquatter; any
packages with identical fields, which could indicate an attempt to confuse
an unsuspecting user, are outputted in red characters.

pypi-scan has been to used to identify and report these packages:
- pandar (which was squatting on pandas) Removed from PyPI.
- prompt-tool-kit (which is squatting on prompt-toolkit) Reported to maintainer.
- requestsaa (which is squatting on requests) Reported to maintainer.

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
Note I: This command generates a .json report file in the 'results' directory.
Note II: Users can whitelist known good packages by adding package names in
whitelist.txt; there should be one package name per line.

Advanced usage includes use of several switches:
```
# Search top 100 pypi packages, if the package name is of at least length
# 4 and for all typosquatters within an edit distance of two. See the help
# section below for further explanation of switches.
>>> python main.py -o top-mods -e 2 -n 100 -l 4
...
```
Timing info: ~20 seconds

List packages recently added to PyPI and any other packages that these new
packages might be typosquatting. This functionality is new and still
under development.
```
>>> python main.py -o recent-scan
...
```

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
NOTE: One colleague has asked me if registering similar namespaces as a defensive
protection against typosquatting is ethical. My own review of Pypi suggests the practice
is common among top-downloaded packages. But is it ethical? I'm not sure.

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
usage: main.py [-h] [-o {mod-squatters,top-mods,defend-name,scan-recent}]
               [-m MODULE_NAME] [-e EDIT_DISTANCE] [-n NUMBER_PACKAGES]
               [-l LEN_PACKAGE_NAME] [-s] [--save]

optional arguments:
  -h, --help            show this help message and exit
  -o {mod-squatters,top-mods,defend-name,scan-recent}, --operation {mod-squatters,top-mods,defend-name,scan-recent}
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
  --save                When using scan-recent, save newly created package
                        list (default: False)
```
NOTE: This command line interface is under development and could have changed.

## Contributing

Pull requests are welcome! Also, you can open issues or submit bugs and
security issues in the Github issue tracker. If you submit new functionality,
please add corresponding tests.

## Needed Improvements and Potential Extensions

- Check for forms of typosquatting other than "fat finger" attacks (open-cv
  vs. open-vc) and and order attacks (open-cv vs. cv-open). For instance,
  what about when there are real words that are joined and the attackers
  add a dash or underscore (coolpkg vs. cool-pkg)?
- Is there a way to use visualization to explore for typosquatting attacks?
- How should package metadata be used to search for potential typosquatters?
  The current version uses metadata crudely: pypi-scan simply changes the
  coloring of outputted text when a package has any identical metadata to
  the real package. There are likely improvements to be made.
- Should pypi-scan try to find attacks other than typosquatting? What types
  of attacks? How?

Again, issues, comments, discussion, and questions are welcome!

More coming soon...
