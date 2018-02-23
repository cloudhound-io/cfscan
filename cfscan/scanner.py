PASS = True
FAIL = False


def test(func):
    """
    :type func function
    mark function as test
    """
    func.__test__ = True
    func.desc = func.__doc__.strip()
    func.name = func.__name__
    return func


class Scanner(object):

    def __init__(self, target):
        if not target.startswith('http'):
            target = 'http://' + target
        self.target = target

    def get_tests(self):
        return [o for o in self.__class__.__dict__.itervalues() if (callable(o) and hasattr(o, '__test__'))]

    def scan(self):
        for testfunc in self.get_tests():
            try:
                result = testfunc(self)
                yield testfunc, result
            except BaseException as e:
                yield testfunc, [(FAIL, e.message)]
