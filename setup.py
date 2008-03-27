from os.path import dirname, join
from setuptools import setup, Extension, Feature

version = '1.3.0'

setup (
	name = 'jsonlib',
	version = version,
	description = "JSON serializer/deserializer for Python",
	long_description = open (join (dirname (__file__), 'README.txt')).read (),
	author = "John Millikin",
	author_email = "jmillikin@gmail.com",
	license = "MIT",
	url = "https://launchpad.net/jsonlib",
	download_url = "http://cheeseshop.python.org/pypi/jsonlib/%s" % version,
	packages = ['jsonlib', 'jsonlib.tests'],
	platforms = ["Platform Independent"],
	classifiers = [
		"Development Status :: 5 - Production/Stable",
		"Intended Audience :: Developers",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
		"Programming Language :: Python",
		"Topic :: Software Development :: Libraries :: Python Modules",
	],
	keywords = ["json"],
	features = {'performance': Feature (
		"Performance-enhancing extension modules",
		standard = True,
		ext_modules = [
			Extension ('jsonlib._reader', ['jsonlib/ext/_reader.c']),
			Extension ('jsonlib._writer', ['jsonlib/ext/_writer.c']),
		],
	)},
	test_suite = 'jsonlib.tests.suite',
)
