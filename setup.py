from setuptools import setup, find_packages
import re

VERSIONFILE="aiosecretsdump/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
	verstr = mo.group(1)
else:
	raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))


setup(
	# Application name:
	name="aiosecretsdump",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsecprojects.com",

	# Packages
	packages=find_packages(),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/skelsec/aiosecretsdump",

	zip_safe = True,
	#
	# license="LICENSE.txt",
	description="Secretsdump for aiosmb",
	long_description="Secretsdump for aiosmb",

	# long_description=open("README.txt").read(),
	python_requires='>=3.6',
	classifiers=(
		"Programming Language :: Python :: 3.6",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	),
	install_requires=[
		'aiosmb>=0.2.22',
		'pypykatz>=0.3.11',
		'tqdm',
	],
	entry_points={
		'console_scripts': [
			'aiosecretsdump = aiosecretsdump.secretsdump:main',
		],
	}
)