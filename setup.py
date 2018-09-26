from setuptools import setup

setup(
    name = "cfscan",
    version = "0.0.4",
    author = "https://cloudhound.io",
    author_email = "info@cloudhound.io",
    description = ("cfscan is an open source vulnerability scanner for cloud foundry"),
    license = "BSD",
    keywords = "free open-source cf cloud foundry cloudfoundry security health vulnerability scanner",
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
