from setuptools import setup

setup(
    name = "cftest",
    version = "0.0.1",
    author = "cloudhound.io",
    author_email = "info@cloudhound.io",
    description = ("self-contained security and best-practices testing-tool for Cloud Foundry environments"),
    license = "BSD",
    keywords = "cf security health best practice test tester cloud foundry",
    url = "https://github.com/cloudhound-io/cftest",
    packages=['cftester'],
    install_requires=['requests'],
    scripts=['bin/cftest'],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: BSD License",
    ],
)
