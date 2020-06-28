"""
Functions for webscraping

A module that contains any functions that can make internet
calls to gather data related to typosquatting.
"""

import json
import urllib.request

from bs4 import BeautifulSoup
import requests
import jsontree

import constants

TOP_N = constants.TOP_N


def get_all_packages(page="https://pypi.org/simple/"):
    """Download simple list of pypi package names

	pypi.org/simple conveniently lists all the names of current
	packages. This function scrapes that listing and then places
	the package names in a python list structure.

	OUPUT:
	package_names: a list of package names on pypi
	"""

    # Retrieve package name listing data from pypy
    pypi_package_page = requests.get(page)

    # Convert html to easily digestible format
    soup = BeautifulSoup(pypi_package_page.text, "html.parser")

    # Store package names in list
    package_names = []
    for elem in soup.find_all("a"):  # Find all <a> tags
        package_names.append(elem.string)  # Get string inside a tag

    # Return timestamp and package name list
    return package_names


def get_top_packages(top_n=TOP_N, stored=False):
    """Identify top packages by download count on pypi

	A friendly person has already provided an occasionally
	updated JSON feed to enable this program to build a list
	of the top pypi packages by download count. The default
	does a fresh pull of this feed. If the user wants to use
	a stored list, that is possible if the user sets the stored
	flag to true.

	INPUTS:
	--top_n: the number of top packages to retrieve
	--stored: whether to use the stored package list

	OUTPUTS:
	--top_packages: dict with top packages
	"""

    if stored:  # Get stored data
        with open("top_packages_may_2020.json", "r") as f:
            data = json.load(f)
    else:  # Get json data for top pypi packages from website
        top_packages_url = (
            "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json"
        )
        with urllib.request.urlopen(top_packages_url) as url:  # nosec
            data = json.loads(url.read().decode())

    # Make JSON data easy to navigate
    json_data = jsontree.jsontree(data)

    # Place top_n packages in dict, where key is package
    # name and value is rank
    top_packages = {}
    for i in range(0, top_n):
        package_info = json_data.rows[i]
        package_name = package_info["project"]
        top_packages[package_name] = i + 1

    return top_packages
