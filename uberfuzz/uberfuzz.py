'''Main module for fuzzers cooperation'''

import threading
import logging
import operator as op
import os

from .external import Driller, AFLFast
# from .score import AngrScorer, LengthScorer
from . import score


l = logging.getLogger('uberfuzz')
l.setLevel(logging.DEBUG)


#  http://stackoverflow.com/a/41450617
class InfiniteTimer(object):
    """A Timer class that does not stop, unless you want it to."""
    # pylint: disable=missing-docstring

    def __init__(self, seconds, target):
        self._should_continue = False
        self.is_running = False
        self.seconds = seconds
        self.target = target
        self.thread = None

    def _handle_target(self):
        self.is_running = True
        self.target()
        self.is_running = False
        self._start_timer()

    def _start_timer(self):
        if self._should_continue: # Code could have been running when cancel was called.
            self.thread = threading.Timer(self.seconds, self._handle_target)
            self.thread.start()

    def start(self):
        if not self._should_continue and not self.is_running:
            self._should_continue = True
            self._start_timer()
        else:
            print "Timer already started or running, please wait if you're restarting."

    def cancel(self):
        if self.thread is not None:
            self._should_continue = False # Just in case thread is running and cancel fails.
            self.thread.cancel()


class Uberfuzz(object):
    '''Let those fuzzers cooperate!'''
    # pylint: disable=too-many-instance-attributes

    DEFAULT_AFLFAST_PATH = os.environ['AFLFAST_PATH'] \
                           if os.environ.has_key('AFLFAST_PATH') else None

    def __init__(self, binary_path, work_dir, pollenation_interval=30,
                 aflfast_path=DEFAULT_AFLFAST_PATH, use_driller=True,
                 callback_time_interval=None, callback_fn=None, target_opts=None,
                 logging_time_interval=None, read_from_file=None, scorer=score.LengthScorer):
        # pylint: disable=too-many-arguments
        self.binary_path = binary_path
        self.work_dir = work_dir

        scorer_file = None
        if scorer == score.AngrScorer and target_opts and '@@' in target_opts:
            if read_from_file:
                scorer_file = read_from_file
                read_from_file = None
            else:
                # this is to allow the scorer to work properly (future TODO)
                raise ValueError('read_from_file has to be set if giving \
                                 file with @@ and AngrScorer')
        self._scorer = scorer(binary_path, extra_opts=target_opts, reads_file=scorer_file)

        self.fuzzers = []
        if use_driller:
            self.driller = Driller(binary_path, work_dir, read_from_file=read_from_file,
                                   target_opts=target_opts)
            self.fuzzers.append(self.driller)
        else:
            self.driller = None

        if aflfast_path is None:
            self.aflfast = None
        else:
            self.aflfast = AFLFast(binary_path, work_dir, aflfast_path,
                                   read_from_file=read_from_file, target_opts=target_opts)
            self.fuzzers.append(self.aflfast)

        self._timers = []
        self.pollenation_interval = pollenation_interval
        self._pollenation_timer = InfiniteTimer(pollenation_interval, self._pollenation_callback)
        self._timers.append(self._pollenation_timer)

        self.callback_time_interval = callback_time_interval
        self.callback_fn = callback_fn
        if callback_time_interval is None and callback_fn is None:
            self._callback_timer = None
        else:
            self._callback_timer = InfiniteTimer(callback_time_interval, callback_fn)
            self._timers.append(self._callback_timer)

        self.logging_time_interval = logging_time_interval
        if logging_time_interval:
            self._logging_timer = InfiniteTimer(logging_time_interval,
                                                self._logging_callback)
            self._timers.append(self._logging_timer)
        else:
            self._logging_timer = None

    def start(self):
        '''Starts fuzzing'''
        l.info('Starting fuzzers')

        for fuzzer in self.fuzzers:
            fuzzer.start()
            l.info('%14s started | %s', fuzzer.identifier, fuzzer.binary_path)
        for timer in self._timers:
            timer.start()

    def kill(self):
        '''Kills fuzzers'''
        for fuzzer in self.fuzzers:
            fuzzer.kill()
        for timer in self._timers:
            timer.cancel()

    @property
    def queue(self):
        '''List of queued testcases for each fuzzer'''
        queue = {}
        for fuzzer in self.fuzzers:
            queue[fuzzer.identifier] = fuzzer.queue
        return queue

    @property
    def crashes(self):
        '''List of crashing testcases for each fuzzer'''
        crashes = {}
        for fuzzer in self.fuzzers:
            crashes[fuzzer.identifier] = fuzzer.crashes
        return crashes

    def _pollenation_callback(self):
        if not self.driller or not self.aflfast:
            return

        driller_queue = self.driller.queue
        driller_pollenated = self.driller.pollenated
        driller_all = list(set(driller_queue).union(set(driller_pollenated)))
        aflfast_pollen = [x for x in self.aflfast.queue if x not in driller_all]

        scored_pollen = []
        aflfast_pollen_n = len(aflfast_pollen)
        for i in xrange(aflfast_pollen_n):
            pollen = aflfast_pollen[i]
            l.info('Scoring pollen %4d / %d...', i+1, aflfast_pollen_n)
            scored_pollen.append((self._scorer(pollen), pollen))
        sorted_pollen_score = sorted(scored_pollen, key=op.itemgetter(0), reverse=True)
        sorted_pollen = [x[1] for x in sorted_pollen_score]

        all_pollen_len = len(sorted_pollen)
        if all_pollen_len > 0:
            selection_pressure = 0.4
            selected_n = all_pollen_len * selection_pressure
            selected_pollen = sorted_pollen[1 : int(selected_n)]
            elite_pollen = sorted_pollen[0]
            final_pollen = []
            final_pollen.append(elite_pollen)
            final_pollen.extend(selected_pollen)
            self.driller.pollenate(final_pollen)

            l.info('Elite pollen length %6d', len(elite_pollen))
            l.info('Selected #pollen    %6d', selected_n)

    def _logging_callback(self):
        for fuzzer in self.fuzzers:
            l.info("%12s %4d queued %4d crashed", fuzzer.identifier,
                   len(fuzzer.queue), len(fuzzer.crashes))
