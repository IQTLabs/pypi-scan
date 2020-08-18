"""Filter typosquatting-related lists.

A module that contains all functions that filter data related to typosquatting
data.
"""

import jellyfish
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


def order_attack_screen(package, all_packages):
    """Find packages that prey on user confusion about order.

    This screen checks for attacks that prey on user confusion
    about word order. For instance, python-nmap vs nmap-python.
    The edit distance is very high, but the conceptual distance is
    close. This function currently identifies only packages that
    capitalize on user confusion about  word order when words are
    separated by dashes or underscores.

    Args:
        package (str): package name on which to perform comparison
        all_packages (list): list of all package names

    Returns:
        list: potential typosquatting packages
    """
    # Check if there is only one total dash or underscore
    # TODO: Consider dealing with other cases (e.g. >=2 dashes)
    squatters = []
    if package.count("-") + package.count("_") == 1:
        if package.count("-") == 1:
            pkg_name_list = package.split("-")
            reversed_name = pkg_name_list[1] + "-" + pkg_name_list[0]
            switch_symbol = pkg_name_list[0] + "_" + pkg_name_list[1]
            switch_symbol_reversed = pkg_name_list[1] + "_" + pkg_name_list[0]
        else:
            pkg_name_list = package.split("_")
            reversed_name = pkg_name_list[1] + "_" + pkg_name_list[0]
            switch_symbol = pkg_name_list[0] + "-" + pkg_name_list[1]
            switch_symbol_reversed = pkg_name_list[1] + "-" + pkg_name_list[0]
        # Check if each attack is contained in the full package list
        for attack in [reversed_name, switch_symbol, switch_symbol_reversed]:
            if attack in all_packages:
                squatters.append(attack)

    return squatters


def homophone_attack_screen(package_of_interest, all_packages):
    """Find packages that prey on homophone confusion.

    This screen checks for attacks that prey on user confusion
    related to homophones. For instance, 'klumpz' vs. 'clumps'.
    This function helps find confusion attacks, rather than
    misspelling attacks.

    Args:
        package (str): package name on which to perform comparison
        all_packages (list): list of all package names

    Returns:
        list: potential typosquatting packages
    """
    # Empty list to store similar package names
    homophone_package_names = []

    # Calculate metaphone code for package of interest, only once
    package_of_interest_metaphone = jellyfish.metaphone(package_of_interest)

    # Loop thru all package names
    for package in all_packages:

        # Skip if the package is the package of interest
        if package == package_of_interest:
            continue

        # Compare package metaphone code to the metaphone code of the
        # package of interest
        if jellyfish.metaphone(package) == package_of_interest_metaphone:
            homophone_package_names.append(package)

    return homophone_package_names


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
