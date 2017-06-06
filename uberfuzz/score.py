'''main scoring module'''

import tracer


class Scorer(object):
    '''Gives a score to testcases'''
    # pylint: disable=too-few-public-methods

    def __init__(self, binary, extra_opts=None, reads_file=None):
        self.binary = binary
        self._reads_file = reads_file
        self._argv = [binary].extend(extra_opts) if extra_opts else None
        if reads_file:
            self._argv = self._argv.append(reads_file) if self._argv else [binary, reads_file]

    def _score(self, testcase):
        '''Score a single testcase'''
        if self._reads_file:
            with open(self._reads_file, 'wb') as f:
                f.write(testcase)
        tr = tracer.Tracer(self.binary, argv=self._argv, input=testcase)
        last_active = tr.run()
        return last_active[0].length
    __call__ = _score
