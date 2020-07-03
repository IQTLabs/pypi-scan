"""Perform actions related to typosquatting.

These are the important misfits. They don't fit in elsewhere but these
functions need to be in a module somewhere.
"""

import collections
import glob
import json
import os
import time
from time import gmtime, strftime, time

from mrs_spellings import MrsWord

import constants
from filters import distance_calculations

MAX_DISTANCE = constants.MAX_DISTANCE


def create_suspicious_package_dict(
    all_packages, top_packages, max_distance=MAX_DISTANCE
):
    """Examine all top packages for typosquatters.

    Loop through all top packages and check for instances of
    typosquatting.

    Args:
        all_packages (list): all package names
        top_packages (list): package names to perform comparison
        max_distance (int): maximum edit distance to check for typosquatting

    Returns:
        dict: top packages (key) and potential typosquatters (value)
    """
    suspicious_packages = collections.OrderedDict()

    for top_package in top_packages:
        close_packages = distance_calculations(top_package, all_packages, max_distance)
        suspicious_packages[top_package] = close_packages

    return suspicious_packages


def store_squatting_candidates(squat_candidates):
    """Persist results of squatting candidate search.

    Dump typosquatter candidate list to a json file. Store
    with time-stamped file name to results folder.

    Args:
        squat_candidates (dict): top packages and potential typosquatters
    """
    # TODO: Remove time. and just use strftime
    timestamp = time.strftime("%d-%b-%Y-%H-%M-%S", time.localtime())
    full_file_name = timestamp + "-record" + ".json"
    file_name = os.path.join("results", full_file_name)
    with open(file_name, "w") as path:
        json.dump(squat_candidates, path)


def create_potential_squatter_names(module_name):
    """Create a set of potential typosquatting names.

    Given a module name, create a set of potential typosquatting
    names based on qwerty distance, a measure of how close keys
    are to each other. This is a more sophisticated measure of
    keyboard key distance than levenshtein distance.

    Args:
        module_name (str): a name for a module

    Returns:
        list: potential typosquatting name
    """
    potential_candidates = MrsWord(module_name).qwerty_swap()
    potential_candidates_joined = " ".join(potential_candidates)
    potential_candidates_set = set(potential_candidates_joined.split(" "))
    return potential_candidates_set


def store_recent_scan_results(packages, folder="package_lists"):
    """Store results of scanning packages recently added to PyPI.

    Save timestamped version of JSON file to allow analysis of packages
    recently added to PyPI

    Args:
        packages (list): Packages on PyPI
        folder (str): Folder in which to store JSON file

    """
    timestamp = strftime("%Y-%b-%d-%H-%M-%S", gmtime())
    filename = "pypi-package-list-" + timestamp + ".json"
    # Platform-independent path joining
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(packages, f, ensure_ascii=False, indent=4)


def load_most_recent_packages(folder="package_lists"):
    """Load the most recent package list from at least 24 hours ago.

    Load the JSON file containing PyPI packages with the most recent
    timestamp that was created at least 24 hours ago.

    Args:
        folder (str): Folder in which to check for file

    Returns:
        package_set (set): Packages loaded from JSON file

    """
    # Identify all json files
    path = os.path.join(folder, "*.json")
    json_files = glob.glob(path)

    # Find newest json file that is at least 24 hours old
    current_time = time()
    newest_file_older_than_1day = ""
    DAY_IN_SECONDS = 60  # * 60 * 24
    for file in json_files:
        file_timestamp = os.path.getmtime(file)
        if file_timestamp <= (current_time - DAY_IN_SECONDS):
            newest_file_older_than_1day = file
            break

    # Check for existence of file and load if it exists
    if not newest_file_older_than_1day:
        raise FileNotFoundError("No json files older than one day found.")
    else:
        with open(newest_file_older_than_1day, "r") as f:
            package_set = set(json.load(f))
            return package_set


def print_suspicious_packages(packages):
    """Pretty print a suspicious package list.

    Args:
        packages (dict): (key) package and (value) potential typosquatters

    """
    print("Number of new packages to examine: " + str(len(packages)))
    cnt_potential_squatters = 0
    for pkg in packages:
        print(pkg, ": ", packages[pkg])
        cnt_potential_squatters += len(packages[pkg])
    print("Number of potential typosquatters: " + str(cnt_potential_squatters))
