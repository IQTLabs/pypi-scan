"""Functions that group lower-level functions and represent separate code paths.

These are the main related functionalities that can be called in main.py
"""

from filters import filter_by_package_name_len, whitelist
from scrapers import get_all_packages, get_top_packages
from utils import (
    create_potential_squatter_names,
    create_suspicious_package_dict,
    load_most_recent_packages,
    print_suspicious_packages,
    store_squatting_candidates,
    store_recent_scan_results,
)


def mod_squatters(module, max_distance):
    """Check if a particular package name has potential squatters.

    Prints any potential typosquatters for specified module

    Args:
        module (str): name to check for typosquatting
        max_distance (int): maximum edit distance to check for typosquatting

    """
    module_in_list = [module]
    package_names = get_all_packages()
    squat_candidates = create_suspicious_package_dict(
        package_names, module_in_list, max_distance
    )
    # Print results
    print("Checking " + module + " for typosquatting candidates.")
    # Check for no typosquatting candidates
    if len(squat_candidates[module]) == 0:
        print("No typosquatting candidates found.")
    else:
        for i, candidate in enumerate(squat_candidates[module]):
            print(str(i) + ": " + candidate)


def names_to_defend(module_name):
    """Print out module names that might merit defending.

    Args:
        module_name (str): Initial module name to protect from typosquatting

    """
    print(
        f'Here is a list of similar names--measured by keyboard distance--to "{module_name}":'
    )
    names = create_potential_squatter_names(module_name)
    for i, name in enumerate(names):
        print(f"{i}:", name)


def top_mods(max_distance, top_n, min_len, stored_json):
    """Check top packages for typosquatters.

    Prints top packages and any potential typosquatters

    Args:
        max_distance (int): maximum edit distance to check for typosquatting
        top_n (int): the number of top packages to retrieve
        min_len (int): a minimum length of characters
        stored_json (bool): a flag to denote whether to used stored top packages json

    """
    # Get list of potential typosquatters
    package_names = get_all_packages()
    top_packages = get_top_packages(top_n=top_n, stored=stored_json)
    filtered_package_list = filter_by_package_name_len(top_packages, min_len=min_len)
    squat_candidates = create_suspicious_package_dict(
        package_names, filtered_package_list, max_distance
    )
    post_whitelist_candidates = whitelist(squat_candidates)
    store_squatting_candidates(post_whitelist_candidates)

    print_suspicious_packages(post_whitelist_candidates)


def scan_recent(max_distance, save_new_list=False):
    """Scan packages recently added to pypi for possible typosquatting.

    Print recently added packages and any package names on which these
    packages are potentially typosquatting.

    Args:
        max_distance (int): maximum edit distance to check for typosquatting
        save_new_list (bool): flag to save new list

    """
    # Download current list of PyPI packages and convert to set
    current_packages_set = set(get_all_packages())
    # If saving is requested, save new list with timestamped name
    if save_new_list == True:
        store_recent_scan_results(list(current_packages_set))

    # Load most recent stored list of PyPI packages and concert to set
    recent_packages_set = load_most_recent_packages()

    # Find packages that are in newest list but not old list
    # This is a set operation: find all elements in first not in second
    new_packages = current_packages_set - recent_packages_set

    # Check each new package and see if it is a potential typosquatter
    squat_candidates = create_suspicious_package_dict(
        current_packages_set, new_packages, max_distance
    )

    # TODO: Consider adding in length to avoid checking short package names

    print_suspicious_packages(squat_candidates)
