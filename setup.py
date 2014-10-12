from setuptools import setup, find_packages
import sys
#sys.path.append('./src')
setup(
    name = "headcap",
    version = "1.0",
    description = "Malicious Packet Detection Tool",
    packages = find_packages(),
    entry_points="""
    [console_scripts]
    headcap = src.headcap:main
    """,)
