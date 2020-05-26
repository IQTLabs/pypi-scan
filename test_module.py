''' Test all functions used to execute pypi-scan '''

import unittest

import main  # Script containing pypi-scan functions

class TestFunctions(unittest.TestCase):
    '''Test all functions for pypi-scan script'''

    def test_getAllPackages(self):
        '''Test getAllPackages function'''
        current_timestamp, package_names = main.getAllPackages()
        self.assertTrue(current_timestamp)
        self.assertIsInstance(current_timestamp, float)
        self.assertTrue(len(package_names) > 200000)

    def test_getTopPackages(self):
        '''Test getTopPackages function'''
        top_packages = main.getTopPackages(100)
        self.assertEqual(len(top_packages), 100)
        self.assertEqual(top_packages['requests'], 4)

    def test_distanceCalculations(self):
        '''Test distanceCalculations function'''
        top_package = 'cat'
        all_packages = ['bat', 'apple']
        squatters = main.distanceCalculations(top_package,
                                              all_packages)
        self.assertEqual(squatters, ['bat'])

    def test_end2end(self):
        '''Test pypi-scan analysis from start to finish'''
        current_timestamp, package_names = main.getAllPackages()
        top_packages = main.getTopPackages()
        squat_candidates = main.createSuspiciousPackageDict(package_names,
                                                            top_packages)

if __name__ == '__main__':
    unittest.main()
