from setuptools import setup, find_packages
import sys
setup(
    name = "tkiwa",
    version = "1.0",
    description = "Malicious Packet Detection Tool",
    packages = find_packages(),
    author="Takashi Koide",
    author_email="koide-takashi-mx@ynu.jp",
    url="http://ipsr.ynu.ac.jp/tkiwa/index.html",
    entry_points="""
    [console_scripts]
    headcap = src.headcap:main
    """,)
