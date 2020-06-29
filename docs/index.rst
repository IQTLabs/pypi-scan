.. pypi-scan documentation master file, created by
   sphinx-quickstart on Sat Jun 27 06:15:52 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to pypi-scan's documentation!
=====================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Pypi-scan assists with your anti-typosquatting needs related to the python
package index (PyPI), a repository for open soucre Python programs.
Typosquatting refers to packages that use names similar to another, more
popular package to trick unsuspecting users into downloading malicious
software. PyPI, like many other package managers, has been been subject to
these typosquatting attacks in recent years; based on news reporting, there
have been at least several dozen documented typosquatting attacks on PyPI.

Pypi-scan can help detect typosquatting on PyPI. There are currently
three uses of pypi-scan:

- Scan PyPI for packages that have similar names to the most downloaded
  packages.
- Scan PyPI for packages that have similar names to a particular package.
- Enumerate potential names that typosquatters might use to attack a
  particular package.

.. automodule:: scrapers
   :members:

More documentation coming soon!

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
