# pypi-scan
Scan pypi for typosquatting

Have you ever wanted to see if other packages are typosquatting your pypi package or
any pypi package of interest? Have you ever wanted to check the most downloaded packages
on pypi for potential typosquatters? You can do both of these actions with pypi-scan.

Pypi (the Python Package Index) is a repository for Python packages. It's like a store
where anybody with an internet connection can download (for free) Python packages.
Typosquatting is a practice in which someone chooses a package name that is similar to
an existing package and places a malicious package in this deceptively titled namespace.
Imagine you want to download the package 'numpy' but you mistype that name and spell
'nunpy' instead. You then download a malicious package. Of course, not all packages with
similar names are malicious, but some might be. 

## Usage

List potential typosquatters on numpy:
```
>>> python main.py -m numpy
Checking numpy for typosquatting candidates.
0: bumpy
1: dumpy:
2: gnumpy
...
```

List potential typosquatters on top packages:
```
>>> python main.py -o top-mods
Number of top packages to examine: 43
urllib3 : ['urllib4', 'urllib5']
botocore : ['kotocore']
...
```

More coming soon...