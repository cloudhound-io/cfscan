import sys

def test(func):
    """
    :type func function
    mark function as test
    """
    func.__setattr__('__test__', True)
    return func


class bcolors(set):
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Tester(object):

    def __init__(self, target, stdout=sys.stdout, stderr=sys.stderr):
        if not target.startswith('http'):
            target = 'http://' + target
        self.target = target
        self.stdout = stdout
        self.stderr = stderr

    def __get_tests(self):
        return [o for o in self.__class__.__dict__.itervalues() if (callable(o) and hasattr(o, '__test__'))]

    def format(self, fd=None, _format="", *args):
        if not fd:
            fd = self.stdout
        fd.write(_format % args)

    def run_tests(self):
        self.format(self.stdout, 'Generating report for target %s:\n\n', self.target)
        for test_func in self.__get_tests():
            self.format(self.stdout, "\tTest: %s\n", test_func.__doc__.strip())
            try:
                for passed, msg in test_func(self):
                    if not passed:
                        self.format(self.stdout, '\t\t[%sFAIL%s] %s\n', bcolors.FAIL, bcolors.ENDC, msg)
                    else:
                        self.format(self.stdout, '\t\t[%sPASS%s] %s\n', bcolors.OKGREEN, bcolors.ENDC, msg)
            except Exception as e:
                self.format(self.stdout, '\t\t[%sFAIL%s] %s\n', bcolors.FAIL, bcolors.ENDC, e.message)

            self.format(self.stdout, '\n')
