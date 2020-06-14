"""
Check top pypi packages for typosquatting

This programs checks the top packages (the default is the top 50)
for typosquatting, i.e. instances of other packages that are intentionally
named such that common mis-typings of the original package could result in
typing this other package name. Mis-typing distance is measured via
levenshtein distance, a measure of "edit" distance. The default configuration
identifies a package as a potential typosquatter if its edit distance is less
than or equal a specified value (default is 1 ) compared to one of the top
packages. Additionally, there is a whitelist capability to exclude packages
that are known good. Note: Only packages whose names are at least as long a
specified minimum are analyzed.
"""

import collections
import os
import time

import json
import Levenshtein

from filters import filterByPackageNameLen, distanceCalculations, whitelist
from scrapers import getAllPackages, getTopPackages

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
