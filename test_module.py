"""Test all functions used to execute pypi-scan"""

import collections
from io import StringIO
import os
import subprocess  # nosec
import unittest
from unittest.mock import patch

from filters import (
    confusion_attack_screen,
    distance_calculations,
    filter_by_package_name_len,
    whitelist,
)
from scrapers import get_all_packages, get_top_packages, get_metadata
from utils import (
    create_potential_squatter_names,
    create_suspicious_package_dict,
    load_most_recent_packages,
    print_suspicious_packages,
    store_recent_scan_results,
    store_squatting_candidates,
)


class TestFunctions(unittest.TestCase):
    """Test all functions for pypi-scan script."""

    def test_get_all_packages(self):
        """Test get_all_packages function."""
        package_names = get_all_packages()
        self.assertTrue(len(package_names) > 200000)

    def test_get_top_packages(self):
        """Test get_top_packages function."""
        # Check default setting
        top_packages = get_top_packages()
        self.assertEqual(len(top_packages), 50)
        self.assertEqual(top_packages["requests"], 5)

        # Check user supplied number of top packages
        top_packages = get_top_packages(100)
        self.assertEqual(len(top_packages), 100)
        self.assertEqual(top_packages["requests"], 5)

        # Check if stored package option works
        stored_packages = get_top_packages(50, stored=True)
        self.assertEqual(len(stored_packages), 50)
        self.assertEqual(stored_packages["requests"], 4)

    def test_distance_calculations(self):
        """Test distance_calculations function."""
        package_of_interest = "cat"
        all_packages = ["bat", "apple"]
        squatters = distance_calculations(package_of_interest, all_packages)
        self.assertEqual(squatters, ["bat"])

    def test_filter_by_package_name_len(self):
        """Test filterByPackageNameLen."""
        initial_list = ["eeny", "meeny", "miny", "moe"]
        six_char_list = filter_by_package_name_len(initial_list, 6)
        five_char_list = filter_by_package_name_len(initial_list, 5)
        four_char_list = filter_by_package_name_len(initial_list, 4)
        three_char_list = filter_by_package_name_len(initial_list, 3)
        self.assertEqual(six_char_list, [])
        self.assertEqual(five_char_list, ["meeny"])
        self.assertEqual(four_char_list, ["eeny", "meeny", "miny"])
        self.assertEqual(three_char_list, ["eeny", "meeny", "miny", "moe"])

    def test_whitelist(self):
        """Test whitelist function."""
        test_whitelist = {"key1": ["val1"], "key2": ["val2"]}
        result = whitelist(test_whitelist, "test_data/whitelist.txt")
        self.assertEqual(result, {"key1": [], "key2": ["val2"]})
        self.assertEqual(len(result), 2)
        self.assertTrue("key1" in result)

    def test_potential_squatter_names(self):
        """Test create_potential_squatter_names function."""
        module_name = "test"
        potential_list = create_potential_squatter_names(module_name)
        expected_list = set(
            ["tedt", "trst", "tesy", "tesr", "rest", "teat", "twst", "yest"]
        )
        self.assertEqual(potential_list, expected_list)

    def test_store_recent_scan_results(self):
        """Test store_recent_scan_results function."""
        test_package_list = ["peter", "paul", "mary"]
        store_recent_scan_results(test_package_list, folder="test_data")

    def test_load_most_recent_packages(self):
        """Test load_most_recent_packages function."""
        with self.assertRaises(FileNotFoundError):
            load_most_recent_packages("docs")
        # Sort because loading order appears to happen randomly
        package_list = load_most_recent_packages("test_data")
        self.assertEqual(["peter", "paul", "mary"].sort(), list(package_list).sort())

    def test_print_suspicious_packages(self):
        """Test print_suspicious_packages function."""
        expected_output = "".join(
            [
                "Number of packages to examine: 2\n",
                "evil :  ['eval']\n",
                "knievel :  ['kneevel', 'kanevel']\n",
                "Number of potential typosquatters: 3\n",
            ]
        )
        # Set up monkey patch to collect output printed to sys.stdout
        with patch("sys.stdout", new=StringIO()) as fake_out:
            print_suspicious_packages(
                {"evil": ["eval"], "knievel": ["kneevel", "kanevel"]}
            )
            self.assertEqual(fake_out.getvalue(), expected_output)

    def test_confusion_attack_screen(self):
        """Test confusion_attack_screen function"""
        # Check that positive mach situation functions properly
        input_package = "python-nmap"
        test_list = ["apple", "pear", "nmap-python", "python-nmap"]
        expected_output = ["nmap-python"]
        output = confusion_attack_screen(input_package, test_list)
        self.assertEqual(output, expected_output)

        # Check that no match situation functions properly
        input_package = "python-koala"
        test_list = ["apple", "pear", "nmap-python", "python-nmap"]
        expected_output = None
        output = confusion_attack_screen(input_package, test_list)
        self.assertEqual(output, expected_output)

    def test_create_suspicious_package_dict(self):
        """Test create_suspicious_package_dict function"""
        # Check if misspelling and confusion attacks are detected
        ALL_PACKAGES = ["eeny", "meeny", "miny", "moe", "cup-joe", "joe-cup"]
        TOP_PACKAGE = ["eeny", "cup-joe"]
        MAX_DISTANCE = 1
        output = create_suspicious_package_dict(ALL_PACKAGES, TOP_PACKAGE, MAX_DISTANCE)
        expected_output = collections.OrderedDict(
            {"eeny": ["meeny"], "cup-joe": ["joe-cup"]}
        )
        self.assertEqual(output, expected_output)

    def test_get_metadata(self):
        """Test metadata scrape functionality on pcap2map.

        This package uses pcap2map because John Speed developed pcap2map
        and placed it on PyPI and he has no intention of changing the
        metadata associated with the PyPI package.
        """
        package = get_metadata("pcap2map")
        self.assertEqual(package["info"]["author_email"], "anon@gmail.com")
        self.assertEqual(package["info"]["author"], "John Speed Meyers")
        self.assertEqual(
            package["info"]["package_url"], "https://pypi.org/project/pcap2map/"
        )

    def test_compare_metadata(self):
        """Test compare_metadata functionality.
        One test should compare the same exact package (pcap2map) to
        itself and check they are equivalent. Another should check
        packages that share only one feature and return "low." Another
        should find multiple similarities and return "high risk." Another
        should check entirely different packages and return "no risk."
        """
        pass

    def test_end2end(self):
        """Test pypi-scan analysis from start to finish."""
        package_names = get_all_packages()
        top_packages = get_top_packages()
        squat_candidates = create_suspicious_package_dict(package_names, top_packages)
        store_squatting_candidates(squat_candidates)

    def test_commandline(self):
        """Test command line usage."""

        # Test single module scan usage for module with no typosquatters
        output = subprocess.run(
            ["python", "main.py", "-m", "pcap2map"], capture_output=True
        )  # nosec
        expected = "".join(
            [
                "Checking pcap2map for typosquatting candidates.",
                os.linesep,
                "No typosquatting candidates found.",
                os.linesep,
            ]
        )
        self.assertEqual(output.stdout.decode("utf-8"), expected)

        # Test single module scan usage for module with typosquatters
        output = subprocess.run(
            ["python", "main.py", "-m", "urllib3"], capture_output=True
        )  # nosec
        expected = "".join(
            [
                "Checking urllib3 for typosquatting candidates.",
                os.linesep,
                "0: urllib4",
                os.linesep,
                "1: urllib5",
                os.linesep,
            ]
        )
        self.assertEqual(output.stdout.decode("utf-8"), expected)

        # Test multiple module scan usage with stored package used
        output = subprocess.run(
            ["python", "main.py", "-o", "top-mods", "-s"], capture_output=True
        )  # nosec
        processed_output = output.stdout.decode("utf-8")
        split_processed_output = processed_output.splitlines()
        self.assertEqual(len(split_processed_output), 45)
        self.assertEqual(split_processed_output[0], "Number of packages to examine: 43")

        # Test defend-package usage, i.e. names that are likely candidates based
        # on spelling alone that could be typosquatters
        output = subprocess.run(
            ["python", "main.py", "-o", "defend-name", "-m", "test"],
            capture_output=True,
        )  # nosec
        processed_output = output.stdout.decode("utf-8")
        split_processed_output = processed_output.splitlines()
        self.assertEqual(len(split_processed_output), 9)
        self.assertEqual(
            split_processed_output[0],
            'Here is a list of similar names--measured by keyboard distance--to "test":',
        )

    # TODO: Rewrite scan recent infrastructure to enable straightfoward testing
    @unittest.skip("Skipping because this test is slow")
    def test_recent_scan_command_line(self):
        """Test scan recent functionality end to end.

        This test can be slow if the most recent scan for comparison was
        more than a few days ago.

        """
        output = subprocess.run(
            ["python", "main.py", "-o", "scan-recent"], capture_output=True
        )
        processed_output = output.stdout.decode("utf-8")
        split_processed_output = processed_output.splitlines()
        self.assertEqual(
            split_processed_output[0][:30],  # TODO: Is this the correct number?
            "Number of packages to examine:",
        )


if __name__ == "__main__":
    unittest.main()
