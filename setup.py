from os.path import dirname, join
from distutils.core import setup, Extension

# If you change the version here, also change it in jsonlib.py.
version = '1.4'

setup (
	name = 'jsonlib',
	version = version,
	description = "JSON serializer/deserializer for Python",
	long_description = open (join (dirname (__file__), 'README.txt')).read (),
	author = "John Millikin",
	author_email = "jmillikin@gmail.com",
	license = "GPL",
	url = "https://launchpad.net/jsonlib",
	download_url = "http://cheeseshop.python.org/pypi/jsonlib-python3/%s" % version,
	platforms = ["Platform Independent"],
	classifiers = [
		"Development Status :: 4 - Beta",
		"Intended Audience :: Developers",
		"License :: OSI Approved :: GNU General Public License (GPL)",
		"Operating System :: OS Independent",
		"Programming Language :: Python",
		"Programming Language :: Python 3",
		"Programming Language :: C",
		"Topic :: Software Development :: Libraries :: Python Modules",
	],
	keywords = ["json"],
	py_modules = ['jsonlib'],
	ext_modules = [
		Extension ('_jsonlib', ['_jsonlib.c']),
	],
)
