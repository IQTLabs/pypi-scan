""" Test all functions used to execute pypi-scan """

import unittest

import main  # Script containing pypi-scan functions
from scrapers import getAllPackages, getTopPackages

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
        squatters = main.distanceCalculations(top_package, all_packages)
        self.assertEqual(squatters, ["bat"])

    def test_filterByPackageNameLen(self):
        """test filterByPackageNameLen"""
        initial_list = ["eeny", "meeny", "miny", "moe"]
        six_char_list = main.filterByPackageNameLen(initial_list, 6)
        five_char_list = main.filterByPackageNameLen(initial_list, 5)
        four_char_list = main.filterByPackageNameLen(initial_list, 4)
        three_char_list = main.filterByPackageNameLen(initial_list, 3)
        self.assertEqual(six_char_list, [])
        self.assertEqual(five_char_list, ["meeny"])
        self.assertEqual(four_char_list, ["eeny", "meeny", "miny"])
        self.assertEqual(three_char_list, ["eeny", "meeny", "miny", "moe"])

    def test_whitelist(self):
        """test whitelist function"""
        test_whitelist = {"key1": ["val1"], "key2": ["val2"]}
        result = main.whitelist(test_whitelist, "test_data/whitelist.txt")
        self.assertEqual(result, {"key1": [], "key2": ["val2"]})
        self.assertEqual(len(result), 2)
        self.assertTrue("key1" in result)

    def test_end2end(self):
        """Test pypi-scan analysis from start to finish"""
        package_names = getAllPackages()
        top_packages = getTopPackages()
        squat_candidates = main.createSuspiciousPackageDict(package_names, top_packages)
        main.storeSquattingCandidates(squat_candidates)


if __name__ == "__main__":
    unittest.main()
