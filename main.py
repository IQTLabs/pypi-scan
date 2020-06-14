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

from filters import filterByPackageNameLen, distanceCalculations, whitelist
from scrapers import getAllPackages, getTopPackages
from utils import createSuspiciousPackageDict, storeSquattingCandidates

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
