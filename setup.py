from setuptools import setup, find_packages
import sys
#sys.path.append('./src')
setup(
    name = "header",
    version = "0.1",
    description = "Header detect tool",
    packages = find_packages(),
    entry_points="""
    [console_scripts]
    header = src.header:main
    """,)
