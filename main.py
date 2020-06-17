"""
Pypi typosquatting scanning capability

This program contains functionality related to scanning pypi, the python
package index, for typosquatting. Typosquatting occurs when there are packages
that are intentionally named such that common mis-typings of the original
package could result in typing this other package name. Mis-typing distance
is measured via levenshtein distance, a measure of "edit" distance.

One functionality allows user to specify a package name and to see if there
are any other packages that are similarly named. This could help a package
creator or maintainer check for possible typosquatting.

There is also a functionality better suited for the administrators of pypi
or for an information security researcher: this program can check the top
packages (the default is the top 50) for typosquatting. The default
configuration identifies a package as a potential typosquatter if its edit
distance is less than or equal a specified value (default is 1) compared to
one of the top packages. Additionally, there is a whitelist capability to
exclude packages that are known good. Note: Only packages whose names are at
least as long a specified minimum are analyzed.
"""

import argparse
import sys
import textwrap

from filters import filterByPackageNameLen, whitelist
from scrapers import getAllPackages, getTopPackages
from utils import createSuspiciousPackageDict, storeSquattingCandidates


def parseArgs():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-o",
        "--operation",
        help="Specify operation to perform.",
        choices=["mod-squatters", "top-mods"],
        default="mod-squatters",
    )
    parser.add_argument(
        "-m", "--module_name", help="Module name to check for typosquatters."
    )
    parser.add_argument(
        "-e",
        "--edit_distance",
        help="Maximum edit distance to check.",
        default=1,  # Set default to 1
        type=int,  # Convert argument input to integer
    )
    parser.add_argument(
        "-n",
        "--number_packages",
        help="Specify number of top packages to scan",
        default=50,
        type=int,
    )
    parser.add_argument(
        "-l",
        "--len_package_name",
        help="Specify minimum length of package name",
        default=5,
        type=int,
    )
    args = parser.parse_args()

    return args


def topMods(max_distance, top_n, min_len):
    """ Check top packages for typosquatters

    Prints top packages and any potential typosquatters

    INPUTS:
    max_distance: maximum edit distance to check for typosquatting
    top_n: the number of top packages to retrieve
    min_len: a minimum length of characters
    """

    # Get list of potential typosquatters
    package_names = getAllPackages()
    top_packages = getTopPackages(top_n=top_n)
    filtered_package_list = filterByPackageNameLen(top_packages, min_len=min_len)
    squat_candidates = createSuspiciousPackageDict(
        package_names, filtered_package_list, max_distance
    )
    post_whitelist_candidates = whitelist(squat_candidates)
    storeSquattingCandidates(post_whitelist_candidates)

    # Print all top packages and potential typosquatters
    print("Number of top packages to examine: " + str(len(squat_candidates)))
    cnt_potential_squatters = 0
    for i in post_whitelist_candidates:
        print(i, ": ", post_whitelist_candidates[i])
        cnt_potential_squatters += len(post_whitelist_candidates[i])
    print("Number of potential typosquatters: " + str(cnt_potential_squatters))


def modSquatters(module, max_distance):
    """ Check if a particular package name has potential squatters

    Prints any potential typosquatters for specified module

    INPUTS:
    module: name to check for typosquatting
    max_distance: maximum edit distance to check for typosquatting
    """

    module_in_list = [module]
    package_names = getAllPackages()
    squat_candidates = createSuspiciousPackageDict(
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


if __name__ == "__main__":

    cli_args = parseArgs()  # get command line arguments

    # Check top packages for typosquatters
    if cli_args.operation == "top-mods":
        topMods(
            cli_args.edit_distance, cli_args.number_packages, cli_args.len_package_name
        )
    # Check particular package for typosquatters
    elif cli_args.operation == "mod-squatters":
        # Make sure user proviced --module flag
        if cli_args.module_name == None:
            print(textwrap.dedent("""
                ERROR: User must use -m flag to specify module.
                For instance:
                >>> python main.py -m requests
                """
                ))
            sys.exit(0) # Exit program
        else:
            modSquatters(cli_args.module_name, cli_args.edit_distance)
