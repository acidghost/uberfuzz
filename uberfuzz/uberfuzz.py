from .external import Driller, AFLFast
import threading
import logging

l = logging.getLogger('uberfuzz')
l.setLevel(logging.DEBUG)


#  http://stackoverflow.com/a/41450617
class InfiniteTimer():
    """A Timer class that does not stop, unless you want it to."""

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

    def __init__(
        self, binary_path, work_dir, use_driller=True, use_aflfast=True,
        pollenation_interval=10, callback_time_interval=None, callback_fn=None,
        logging_time_interval=None
    ):
        self.binary_path = binary_path
        self.work_dir = work_dir

        self.fuzzers = []
        if use_driller:
            self.driller = Driller(binary_path, work_dir)
            self.fuzzers.append(self.driller)
        else:
            self.driller = None

        if use_aflfast:
            self.aflfast = AFLFast(binary_path, work_dir)
            self.fuzzers.append(self.aflfast)
        else:
            self.aflfast = None

        self.pollenation_interval = pollenation_interval
        self._pollenation_timer = InfiniteTimer(pollenation_interval, self._pollenation_callback)

        self.callback_time_interval = callback_time_interval
        self.callback_fn = callback_fn
        if callback_time_interval == None and callback_fn == None:
            self._callback_timer = None
        else:
            self._callback_timer = InfiniteTimer(callback_time_interval, callback_fn)

        self.logging_time_interval = logging_time_interval
        self._logging_timer = InfiniteTimer(logging_time_interval,
            self._logging_callback) if logging_time_interval else None

    def start(self):
        for fuzzer in self.fuzzers:
            fuzzer.start()
        self._pollenation_timer.start()
        if self._callback_timer:
            self._callback_timer.start()
        if self._logging_timer:
            self._logging_timer.start()

    def kill(self):
        for fuzzer in self.fuzzers:
            fuzzer.kill()
        self._pollenation_timer.cancel()
        if self._callback_timer:
            self._callback_timer.cancel()
        if self._logging_timer:
            self._logging_timer.cancel()

    @property
    def queue(self):
        queue = {}
        for fuzzer in self.fuzzers:
            queue[fuzzer.identifier] = fuzzer.queue
        return queue

    @property
    def crashes(self):
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
        aflfast_pollen = filter(lambda x: not x in driller_all, self.aflfast.queue)
        if len(aflfast_pollen) > 0:
            self.driller.pollenate(aflfast_pollen)
        l.info('Pollenated %d into driller', len(aflfast_pollen))

    def _logging_callback(self):
        for fuzzer in self.fuzzers:
            l.info("%12s %4d queued %4d crashed", fuzzer.identifier,
                len(fuzzer.queue), len(fuzzer.crashes))
