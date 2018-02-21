# cfscan
cfscan is an open-source vulnerability scanner for Cloud Foundry, maintained by the good people of https://cloudhound.io


## Installation
Installation is as easy as:

```
$ pip install cfscan
```

## Usage
You can use cfscan from the command-line:

```
$ cfscan http://api.local.pcfdev.io
```

Where `api.local.pcfdev.io` is the API address of the Cloud Foundry instance you wish to scan

## Advanced Usage
You can also call the scanner programatically from within a python script:

```
import cfscan
scanner = cfscan.CFScanner('http://api.local.pcfdev.io')

for test, result in scanner.scan():
    print test.desc # desctiption of the test
    for status, msg in result:
        print status, msg
```

## Writing tests
You can also subclass the CFScanner class to add your own tests. a test is quite-simply an annotated generator method:

```
import cfscan

class MyScanner(cfscan.CFScanner):
    
    @cfscan.test
    def hello_world_test(self):
        """ this is a hello world test """ # this will be test.desc
        yield cfscan.PASS, "hello from the new test!"
        
```