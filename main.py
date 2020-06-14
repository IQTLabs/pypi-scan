"""
Check top pypi packages for typosquatting

This programs checks the top packages (the default is the top 50)
for typosquatting, i.e. instances of other packages
that are intentionally named such that common mis-typings of the
original package could result in typing this other package name.
Mis-typing distance is measured via levenshtein distance, a measure
of "edit" distance. The default configuration identifies a package
as a potential typosquatter if its edit distance is less than 1 compared
to one of the top packages. Additionally, there is a whitelist capability
to exclude packages that are known good. Note: Only packages whose names
are at least as long a specified minimum are analyzed.
"""
# TODO: Do initial whitelist scan

import collections
import os
import time

import json
import urllib.request

from bs4 import BeautifulSoup
import Levenshtein
import requests
import jsontree

# Key constants
TOP_N = 50  # number of top packages to examine
MAX_DISTANCE = 1  # Edit distance threshold to determine typosquatting status
MIN_LEN_PACKAGE_NAME = 5  # Minimum length of package name to be included for analysis


def getAllPackages(page="https://pypi.org/simple/"):
    """ Download simple list of pypi package names

	pypi.org/simple conveniently lists all the names of current
	packages. This function scrapes that listing and then places
	the package names in a python list structure.

	OUPUT:
	package_names: a list of package names on pypi
	"""

    # Retrieve package name listing data from pypy
    pypi_package_page = requests.get(page)

    # Convert html to easily digestible format
    soup = BeautifulSoup(pypi_package_page.text, "html.parser")

    # Store package names in list
    package_names = []
    for elem in soup.find_all("a"):  # Find all <a> tags
        package_names.append(elem.string)  # Get string inside a tag

    # Return timestamp and package name list
    return package_names


def getTopPackages(top_n=TOP_N, stored=False):
    """ Identify top packages by download count on pypi

	A friendly person has already provided an occasionally
	updated JSON feed to enable this program to build a list
	of the top pypi packages by download count. The default
	does a fresh pull of this feed. If the user wants to use
	a stored list, that is possible if the user sets the stored
	flag to true.

	INPUTS:
	--top_n: the number of top packages to retrieve
	--stored: whether to use the stored package list

	OUTPUTS:
	--top_packages: dict with top packages
	"""

    if stored:  # Get stored data
        with open("top_packages_may_2020.json", "r") as f:
            data = json.load(f)
    else:  # Get json data for top pypi packages from website
        top_packages_url = (
            "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json"
        )
        with urllib.request.urlopen(top_packages_url) as url:  # nosec
            data = json.loads(url.read().decode())

    # Make JSON data easy to navigate
    json_data = jsontree.jsontree(data)

    # Place top_n packages in dict, where key is package
    # name and value is rank
    top_packages = {}
    for i in range(0, top_n):
        package_info = json_data.rows[i]
        package_name = package_info["project"]
        top_packages[package_name] = i + 1

    return top_packages


def filterByPackageNameLen(package_list, min_len=MIN_LEN_PACKAGE_NAME):
    """
	Filter out package names whose length in characters is
	greater than a specified minimum length

	INPUTS:
	--package_list: a list of package names
	--min_len: a specific minimum length of characters

	OUTPUTS:
	--filtered_package_list: filtered list of package names
	"""

    # Loop thru packages and add package if name's
    # length is greater than or equal to specified min length
    filtered_package_list = []
    for package in package_list:
        if len(package) >= min_len:
            filtered_package_list.append(package)

    return filtered_package_list


def distanceCalculations(top_package, all_packages, max_distance=MAX_DISTANCE):
    """ Find all packages within a defined edit distance

	INPUTS:
	--top_package: package name to perform comparison
	--all_packages: list of all package names
	--max_distance: the maximum distance that justifies reporting

	OUTPUTS:
	--close_package_names: list of potential typosquatters
	"""

    # Empty list to store similar package names
    close_package_names = []

    # Loop thru all package names
    for package in all_packages:

        # Skip if the package IS the same as top_package
        if package == top_package:
            continue

        # Calculate distance
        distance = Levenshtein.distance(top_package, package)

        # If distance is sufficiently close, add to list
        if distance <= max_distance:
            close_package_names.append(package)

    return close_package_names


def createSuspiciousPackageDict(all_packages, top_packages):
    """ Examine all top packages for typosquatters

	Loop through all top packages and check for instances of
	typosquatting.

	INPUTS:
	--all_packages: list of all package names
	--top_package: package name to perform comparison

	OUTPUTS:
	--suspicious_packages: an ordered dict of the top packages (key)
	and potential typosquatters (value)
	"""
    suspicious_packages = collections.OrderedDict()

    for top_package in top_packages:
        close_packages = distanceCalculations(top_package, all_packages)
        suspicious_packages[top_package] = close_packages

    return suspicious_packages


def storeSquattingCandidates(squat_candidates):
    """ Persist results of squatting candidate search

	Dump typosquatter candidate list to a json file. Store
	with time-stamped file name to results folder.

	INPUT:
	--squat_candidates: A dic of the top packages and their
	potential typosquatters
	"""

    timestamp = time.strftime("%d-%b-%Y-%H-%M-%S", time.localtime())
    full_file_name = timestamp + "-record" + ".json"
    file_name = os.path.join("results", full_file_name)
    with open(file_name, "w") as path:
        json.dump(squat_candidates, path)


def whitelist(squat_candidates, whitelist_filename="whitelist.txt"):
    """ Remove whitelisted packages from typosquat candidate list

	Using packages listed in the whitelist_filename file, remove all
	potential typosquatters that are found in the whitelist, a list of
	known good packages.

	INPUT:
	--squat_candidates: dict of packages and potential typosquatters
	--whitelist_filename: file location for whitelist

	OUPUT:
	--dict of packages and post-whitelist potential typosquatters
	"""

    # Create whitelist
    whitelist = []
    with open(whitelist_filename, "r") as file:
        for line in file:
            # Strip out end of line character
            whitelist.append(line.strip("\n"))

        # Remove packages contained in whitelist from dict of
        # top packages (keys) and potential typosquatters (values)
    for pkg in squat_candidates:  # loop thru pkg's
        new_squat_candidates = []
        for candidate in squat_candidates[pkg]:
            # Only keep candidates NOT on whitelist
            if candidate not in whitelist:
                new_squat_candidates.append(candidate)
        # Update typosquat candidate list
        squat_candidates[pkg] = new_squat_candidates

    return squat_candidates


if __name__ == "__main__":

    package_names = getAllPackages()
    top_packages = getTopPackages()
    filtered_package_list = filterByPackageNameLen(top_packages)
    squat_candidates = createSuspiciousPackageDict(package_names, filtered_package_list)
    whitelist_candidates = whitelist(squat_candidates)
    storeSquattingCandidates(whitelist_candidates)

    # Print all top packages and potential typosquatters
    print("Number of top packages to examine: " + str(len(squat_candidates)))
    cnt_potential_squatters = 0
    for i in whitelist_candidates:
        print(i, ": ", whitelist_candidates[i])
        cnt_potential_squatters += len(whitelist_candidates[i])
    print("Number of potential typosquatters: " + str(cnt_potential_squatters))
