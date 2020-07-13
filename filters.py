"""Filter typosquatting-related lists.

A module that contains all functions that filter data related to typosquatting
data.
"""

import Levenshtein

import constants

MAX_DISTANCE = constants.MAX_DISTANCE
MIN_LEN_PACKAGE_NAME = constants.MIN_LEN_PACKAGE_NAME


def filter_by_package_name_len(package_list, min_len=MIN_LEN_PACKAGE_NAME):
    """Keep packages whose name is >= a minimum length.

    Args:
        package_list (list): a list of package names
        min_len (int): a minimum length of charactersArgs

    Returns:
        list: filtered package names
    """
    return [pkg for pkg in package_list if len(pkg) >= min_len]


def distance_calculations(package_of_interest, all_packages, max_distance=MAX_DISTANCE):
    """Find packages <= defined edit distance and return sorted list.

    Args:
        package_of_interest (str): package name on which to perform comparison
        all_packages (list): list of all package names
        max_distance (int): the maximum distance that justifies reporting

    Returns:
        list: potential typosquatters
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


def confusion_attack_screen(package, all_packages):
    """Find packages that prey on user confusion.

    Because not all typosquatting attacks are misspelling attacks,
    a typosquatting defense requires for checking whether there are
    variants of a package that prey on user confusion. For instance,
    python-nmap vs nmap-python. The edit distance is very high, but
    the conceptual distance is close. This function helps currently
    identifies only packages that capitalize on user confusion about
    word order when words are separated by dashes or underscores. Future
    versions of this function might add additional functionality.

    Args:
        package (str): package name on which to perform comparison
        all_packages (list): list of all package names

    Returns:
        list: potential typosquatting packages preying on user confusion
    """
    # Check if there is only one total dash or underscore
    # TODO: Consider dealing with other cases (e.g. >=2 dashes)
    squatters = None
    if package.count("-") + package.count("_") == 1:
        if package.count("-") == 1:
            pkg_name_list = package.split("-")
            reversed_name = pkg_name_list[1] + "-" + pkg_name_list[0]
        else:
            pkg_name_list = package.split("_")
            reversed_name = pkg_name_list[1] + "_" + pkg_name_list[0]
        # Check if this reversed name is contained in the full package list
        if reversed_name in all_packages:
            squatters = [reversed_name]

    return squatters


def whitelist(squat_candidates, whitelist_filename="whitelist.txt"):
    """Remove whitelisted packages from typosquat candidate list.

    Args:
        squat_candidates (dict): dict of packages and potential typosquatters
        whitelist_filename (str): file location for whitelist

    Returns:
        dict: packages and post-whitelist potential typosquatters
    """
    # Create whitelist
    whitelist = []
    with open(whitelist_filename, "r") as file:
        for line in file:
            # Strip out end of line character
            whitelist.append(line.strip("\n"))

    # Remove packages contained in whitelist
    whitelist_set = set(whitelist)
    for pkg in squat_candidates:
        new_squat_candidates_set = set(squat_candidates[pkg]) - whitelist_set
        new_squat_candidates_list = list(new_squat_candidates_set)
        # Update typosquat candidate list
        squat_candidates[pkg] = new_squat_candidates_list

    return squat_candidates
