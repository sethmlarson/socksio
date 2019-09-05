import os
from setuptools import setup


base_dir = os.path.dirname(os.path.abspath(__file__))


with open(os.path.join(base_dir, "README.md")) as f:
    long_description = f.read()


setup(
    name="socks",
    version="0.1",
    author="Seth Michael Larson",
    author_email="sethmichaellarson@gmail.com",
    url="https://github.com/sethmlarson/socks",
    description="Sans-I/O implementation of SOCKS4, SOCKS4A, and SOCKS5",
    long_description=long_description,
    long_description_content_type="text/markdown",
    python_requires=">=3.6",
    packages=["socks"],
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Internet :: Proxy Servers",
    ]
)
