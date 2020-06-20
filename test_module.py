""" Test all functions used to execute pypi-scan """

import subprocess
import unittest

from filters import filterByPackageNameLen, distanceCalculations, whitelist
from scrapers import getAllPackages, getTopPackages
from utils import createSuspiciousPackageDict, storeSquattingCandidates


class TestFunctions(unittest.TestCase):
    """Test all functions for pypi-scan script"""

    def test_getAllPackages(self):
        """Test getAllPackages function"""
        package_names = getAllPackages()
        self.assertTrue(len(package_names) > 200000)

    def test_getTopPackages(self):
        """Test getTopPackages function"""
        top_packages = getTopPackages(100)
        self.assertEqual(len(top_packages), 100)
        self.assertEqual(top_packages["requests"], 4)

        # Check if stored package option works
        stored_packages = getTopPackages(50, stored=True)
        self.assertEqual(len(stored_packages), 50)
        self.assertEqual(stored_packages["requests"], 4)

    def test_distanceCalculations(self):
        """Test distanceCalculations function"""
        top_package = "cat"
        all_packages = ["bat", "apple"]
        squatters = distanceCalculations(top_package, all_packages)
        self.assertEqual(squatters, ["bat"])

    def test_filterByPackageNameLen(self):
        """Test filterByPackageNameLen"""
        initial_list = ["eeny", "meeny", "miny", "moe"]
        six_char_list = filterByPackageNameLen(initial_list, 6)
        five_char_list = filterByPackageNameLen(initial_list, 5)
        four_char_list = filterByPackageNameLen(initial_list, 4)
        three_char_list = filterByPackageNameLen(initial_list, 3)
        self.assertEqual(six_char_list, [])
        self.assertEqual(five_char_list, ["meeny"])
        self.assertEqual(four_char_list, ["eeny", "meeny", "miny"])
        self.assertEqual(three_char_list, ["eeny", "meeny", "miny", "moe"])

    def test_whitelist(self):
        """Test whitelist function"""
        test_whitelist = {"key1": ["val1"], "key2": ["val2"]}
        result = whitelist(test_whitelist, "test_data/whitelist.txt")
        self.assertEqual(result, {"key1": [], "key2": ["val2"]})
        self.assertEqual(len(result), 2)
        self.assertTrue("key1" in result)

    def test_end2end(self):
        """Test pypi-scan analysis from start to finish"""
        package_names = getAllPackages()
        top_packages = getTopPackages()
        squat_candidates = createSuspiciousPackageDict(package_names, top_packages)
        storeSquattingCandidates(squat_candidates)

    def test_commandline(self):
        """Test command line usage"""

        # Test single module scan usage for module with no typosquatters
        output = subprocess.run(
            ["python", "main.py", "-m", "pcap2map"], capture_output=True
        )
        self.assertEqual(
            output.stdout.decode("utf-8"),
            "Checking pcap2map for typosquatting candidates.\r\nNo typosquatting candidates found.\r\n",
        )

        # Test single module scan usage for module with typosquatters
        output = subprocess.run(
            ["python", "main.py", "-m", "urllib3"], capture_output=True
        )
        self.assertEqual(
            output.stdout.decode("utf-8"),
            "Checking urllib3 for typosquatting candidates.\r\n0: urllib4\r\n1: urllib5\r\n",
        )

        # Test multiple module scan usage
        output = subprocess.run(
            ["python", "main.py", "-o", "top-mods"], capture_output=True
        )
        processed_output = output.stdout.decode("utf-8")
        split_processed_output = processed_output.splitlines()
        self.assertEqual(len(split_processed_output), 45)
        self.assertEqual(
            split_processed_output[0], "Number of top packages to examine: 43"
        )

        # Test multiple module scan usage with stored package used
        output = subprocess.run(
            ["python", "main.py", "-o", "top-mods", "-s"], capture_output=True
        )
        processed_output = output.stdout.decode("utf-8")
        split_processed_output = processed_output.splitlines()
        self.assertEqual(len(split_processed_output), 45)
        self.assertEqual(
            split_processed_output[0], "Number of top packages to examine: 43"
        )

        # TODO: Add test for multiple module scan using lots of flags


if __name__ == "__main__":
    unittest.main()
