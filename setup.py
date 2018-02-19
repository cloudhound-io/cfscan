from setuptools import setup

setup(
    name = "cftest",
    version = "0.0.5",
    author = "cloudhound.io",
    author_email = "info@cloudhound.io",
    description = ("an open source security, best-practices and vulnerability scanner for Cloud Foundry"),
    license = "BSD",
    keywords = "cf security health best vulnerability scanner cloudfoundry practice test tester cloud foundry",
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
