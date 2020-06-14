"""
Utility functions that perform actions related to typosquatting

These are the important misfits. They don't fit in elsewhere but these
functions need to be in a module somewhere.
"""

import collections
import os
import time

import json

from filters import distanceCalculations

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
