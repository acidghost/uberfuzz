'''main scoring module'''
# pylint: disable=too-few-public-methods

import tracer


class Scorer(object):
    '''Gives a score to testcases'''

    def __init__(self, binary, extra_opts=None, reads_file=None):
        self.binary = binary
        self._reads_file = reads_file
        self._argv = [binary].extend(extra_opts) if extra_opts else None
        if reads_file:
            self._argv = self._argv.append(reads_file) if self._argv else [binary, reads_file]

    def _score(self, testcase):
        '''Score a single testcase'''
        raise NotImplementedError('_score has to be implemented by child')

    def __call__(self, testcase):
        return self._score(testcase)


class AngrScorer(Scorer):
    '''Angr-based scorer'''

    def _score(self, testcase):
        if self._reads_file:
            with open(self._reads_file, 'wb') as f:
                f.write(testcase)
        tracer_inst = tracer.Tracer(self.binary, argv=self._argv, input=testcase)
        last_active = tracer_inst.run()
        return last_active[0].length


class LengthScorer(Scorer):
    '''Length-based scorer'''

    def _score(self, testcase):
        return len(testcase)
