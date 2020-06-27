"""
Functions for filtering typosquatting-related lists

A module that contains all functions that filter data related to typosquatting
data.
"""

import Levenshtein

import constants

MAX_DISTANCE = constants.MAX_DISTANCE
MIN_LEN_PACKAGE_NAME = constants.MIN_LEN_PACKAGE_NAME


def filter_by_package_name_len(package_list, min_len=MIN_LEN_PACKAGE_NAME):
    """ Keep packages whose name is at least as long as a minimum length

	INPUTS:
	--package_list: a list of package names
	--min_len: a minimum length of characters

	OUTPUTS:
	--filtered_package_list: filtered list of package names
	"""

    return [pkg for pkg in package_list if len(pkg) >= min_len]


def distance_calculations(package_of_interest, all_packages, max_distance=MAX_DISTANCE):
    """ Find packages within a defined edit distance and return sorted list

	INPUTS:
	--package_of_interest: package name on which to perform comparison
	--all_packages: list of all package names
	--max_distance: the maximum distance that justifies reporting

	OUTPUTS:
	--similar_package_names: list of potential typosquatters
	"""

    # Empty list to store similar package names
    similar_package_names = []

    # Loop thru all package names
    for package in all_packages:

        # Skip if the package is the package of interest
        if package == package_of_interest:
            continue

        # Calculate distance
        distance = Levenshtein.distance(package_of_interest, package)

        # If distance is sufficiently small, add to list
        if distance <= max_distance:
            similar_package_names.append(package)

    # Return alphabetically sorted list of similar package names
    return sorted(similar_package_names)


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
