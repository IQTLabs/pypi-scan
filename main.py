"""
Pypi typosquatting scanning capability

This program contains functionality related to scanning pypi, the python
package index, for typosquatting. Typosquatting occurs when there are packages
that are intentionally named such that common mis-typings of the original
package could result in typing this other package name. Mis-typing distance
is measured via levenshtein distance, a measure of "edit" distance.

One functionality (mod-squatters) allows user to specify a package name and to
see if there are any other packages that are similarly named. This could help
a package creator or maintainer check for possible typosquatting.

Another functionality (defend-name) allows a user to specify a package
name and to then view a list of potential names that might be worth defending
given the similarity of those names. A user could then register those names
too to try to prevent typosquatting attacks.

There is also a functionality (top-mods) better suited for the administrators of
pypi or for an information security researcher: this program can check the top
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

from porcelain import mod_squatters, names_to_defend, top_mods


def parse_args():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-o",
        "--operation",
        help="Specify operation to perform.",
        choices=["mod-squatters", "top-mods", "defend-name"],
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
    # Switch to use stored top package list
    parser.add_argument(
        "-s", "--stored_json", help="Use a stored top package list", action="store_true"
    )
    args = parser.parse_args()

    return args


if __name__ == "__main__":

    cli_args = parse_args()  # get command line arguments

    # Check top packages for typosquatters
    if cli_args.operation == "top-mods":
        # Check to see if stored_json file of top packages
        # is requested at command line
        stored_json = False
        if cli_args.stored_json is not None and cli_args.stored_json == True:
            stored_json = True
        top_mods(
            cli_args.edit_distance,
            cli_args.number_packages,
            cli_args.len_package_name,
            stored_json,
        )

    # Check particular package for typosquatters
    elif cli_args.operation == "mod-squatters":
        # Make sure user provided --module flag
        if cli_args.module_name == None:
            print(
                textwrap.dedent(
                    """
                ERROR: User must use -m flag to specify module.
                For instance:
                >>> python main.py -m requests
                """
                )
            )
            sys.exit(0)  # Exit program
        else:
            mod_squatters(cli_args.module_name, cli_args.edit_distance)

    # Enumerate potential names that could potentially be typosquatted
    elif cli_args.operation == "defend-name":
        # Make sure user provided --module flag
        if cli_args.module_name == None:
            print(
                textwrap.dedent(
                    """
                ERROR: User must use -m flag to specify module.
                For instance:
                >>> python main.py -o defend-name -m requests
                """
                )
            )
            sys.exit(0)
        else:
            names_to_defend(cli_args.module_name)
