"""
Pypi typosquatting scanning capability

Rewrite to make clear this is a bunch of related functionality

This programs checks the top packages (the default is the top 50)
for typosquatting, i.e. instances of other packages that are intentionally
named such that common mis-typings of the original package could result in
typing this other package name. Mis-typing distance is measured via
levenshtein distance, a measure of "edit" distance. The default configuration
identifies a package as a potential typosquatter if its edit distance is less
than or equal a specified value (default is 1) compared to one of the top
packages. Additionally, there is a whitelist capability to exclude packages
that are known good. Note: Only packages whose names are at least as long a
specified minimum are analyzed.
"""

import argparse

from filters import filterByPackageNameLen, distanceCalculations, whitelist
from scrapers import getAllPackages, getTopPackages
from utils import createSuspiciousPackageDict, storeSquattingCandidates

def parseArgs():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--operation",
                        help="Specify operation to perform.",
                        choices=['mod-squatters', 'top-mods'],
                        default='mod-squatters')
    parser.add_argument("-m", "--module_name",
                        help="Module name to check for typosquatters.")
    args = parser.parse_args()

    return args

def topMods():
    """ Check top packages for typosquatters """

    # Get list of potential typosquatters
    package_names = getAllPackages()
    top_packages = getTopPackages()
    filtered_package_list = filterByPackageNameLen(top_packages)
    squat_candidates = createSuspiciousPackageDict(package_names, filtered_package_list)
    post_whitelist_candidates = whitelist(squat_candidates)
    storeSquattingCandidates(post_whitelist_candidates)

    # Print all top packages and potential typosquatters
    print("Number of top packages to examine: " + str(len(squat_candidates)))
    cnt_potential_squatters = 0
    for i in post_whitelist_candidates:
        print(i, ": ", post_whitelist_candidates[i])
        cnt_potential_squatters += len(post_whitelist_candidates[i])
    print("Number of potential typosquatters: " + str(cnt_potential_squatters))

def modSquatters(module):
    """ Check if a particular package name has potential squatters"""

    module_in_list = [module]
    package_names = getAllPackages()
    squat_candidates = createSuspiciousPackageDict(package_names,
                                                   module_in_list)
    # Print results
    print('Checking ' + module + ' for typosquatting candidates.')
    # Check if there are not typosquatting candidates
    if len(squat_candidates[module]) == 0:
        print('No typosquatting candidates found.')
    else:
        for i, candidate in enumerate(squat_candidates[module]):
            print(str(i) + ": " + candidate)

if __name__ == "__main__":

    cli_args = parseArgs() # get command line arguments

    # Check top packages for typosquatters
    if cli_args.operation == "top-mods":
        topMods()
    elif cli_args.operation == "mod-squatters":
        #TODO: Make specifying edit distance a choice
        modSquatters(cli_args.module_name)
