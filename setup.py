from setuptools import setup

setup(
    name = "cfscan",
    version = "0.0.2",
    author = "cloudhound.io",
    author_email = "info@cloudhound.io",
    description = ("cfscan is an open source vulnerability scanner for cloud foundry"),
    license = "BSD",
    keywords = "cf cloud foundry cloudfoundry security health scanner tester vulnerability",
    url = "https://github.com/cloudhound-io/cfscan",
    packages=['cfscan'],
    install_requires=['requests'],
    scripts=['bin/cfscan'],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: BSD License",
    ],
)
