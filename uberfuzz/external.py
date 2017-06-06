'''External fuzzers interfaces'''

import os
import signal
import subprocess

import fuzzer
import driller


class ExternalFuzzer(object):
    '''External fuzzer abstract class'''

    def __init__(self, binary_path, work_dir, identifier, seeds):
        self.binary_path = binary_path
        self.work_dir = work_dir
        self.identifier = identifier
        self.fuzzer_dir = os.path.join(work_dir, identifier)
        self.binary_name = os.path.basename(binary_path)
        if not identifier in os.listdir(work_dir):
            os.makedirs(self.fuzzer_dir)
        if isinstance(seeds, basestring):
            self.seeds = [seeds]
        else:
            self.seeds = seeds

    def start(self):
        '''Starts fuzzing'''
        pass

    def kill(self):
        '''Kills fuzzer'''
        pass

    @property
    def queue(self):
        '''List of queued testcases'''
        pass

    @property
    def crashes(self):
        '''List of crashing testcases'''
        pass

    @property
    def stats(self):
        '''Fuzzer stats'''
        pass

    def pollenate(self, testcases):
        '''Inject testcases into the fuzzer'''
        pass

    @staticmethod
    def _pollenated(nectary_queue_dir):
        testcases = []
        if not os.path.isdir(nectary_queue_dir):
            return testcases
        for pollen in os.listdir(nectary_queue_dir):
            with open(os.path.join(nectary_queue_dir, pollen), 'rb') as f:
                testcases.append(f.read())
        return testcases

    @property
    def pollenated(self):
        '''List of injected testcases'''
        pass

    def __del__(self):
        try:
            self.kill()
        except OSError:
            pass


class Driller(ExternalFuzzer):
    '''Driller interface'''

    def __init__(self, binary_path, work_dir, afl_count=1, driller_count=1,
                 time_limit=None, seeds='fuzz'):
        # pylint: disable=too-many-arguments
        super(Driller, self).__init__(binary_path, work_dir, "driller", seeds)
        self.time_limit = time_limit

        drill_callback = driller.LocalCallback(num_workers=driller_count)
        self.driller = fuzzer.Fuzzer(binary_path, self.fuzzer_dir, time_limit=time_limit,
                                     afl_count=afl_count, stuck_callback=drill_callback,
                                     seeds=seeds)

    def start(self):
        self.driller.start()

    def kill(self):
        self.driller.kill()

    @property
    def queue(self):
        return self.driller.queue()

    @property
    def crashes(self):
        return self.driller.crashes()

    @property
    def stats(self):
        stats = self.driller.stats
        return stats['fuzzer-master'] if len(stats.keys()) == 1 else stats

    def pollenate(self, testcases):
        self.driller.pollenate(testcases)

    @property
    def pollenated(self):
        nectary_queue_dir = os.path.join(self.driller.out_dir, 'pollen', 'queue')
        return ExternalFuzzer._pollenated(nectary_queue_dir)


class AFLFast(ExternalFuzzer):
    '''AFL Fast interface'''
    # pylint: disable=too-many-instance-attributes

    def __init__(self, binary_path, work_dir, seeds='fuzz'):
        super(AFLFast, self).__init__(binary_path, work_dir, "aflfast", seeds)

        self.fuzzer_binary_dir = os.path.join(self.fuzzer_dir, self.binary_name)
        self.sync_dir = os.path.join(self.fuzzer_binary_dir, "sync")
        self.resuming = bool(os.listdir(self.sync_dir)) if os.path.isdir(self.sync_dir) else False
        self.input_dir = '-' if self.resuming else os.path.join(self.fuzzer_binary_dir, "input")
        self.process = None
        self.afl_path = os.environ['AFLFAST_PATH']

    def start(self):
        args = [self.afl_path]

        # create aflfast/binary_name dir
        if not self.binary_name in os.listdir(self.fuzzer_dir):
            os.makedirs(self.fuzzer_binary_dir)

        # create aflfast/binary_name/input dir and seeds
        if not self.resuming:
            if not "input" in os.listdir(self.fuzzer_binary_dir):
                os.makedirs(self.input_dir)
            for i in xrange(len(self.seeds)):
                with open(os.path.join(self.input_dir, "seed-%d" % i), 'w') as f:
                    f.write(self.seeds[i])

        # create aflfast/binary_name/sync dir
        if not "sync" in os.listdir(self.fuzzer_binary_dir):
            os.makedirs(self.sync_dir)

        args += ["-i", self.input_dir]
        args += ["-o", self.sync_dir]
        args += ["-m", "8G"]
        args += ["-Q"]

        args += ["--"]
        args += [self.binary_path]

        outfile = "%s.log" % self.identifier
        with open(os.path.join(self.fuzzer_binary_dir, outfile), 'w') as f:
            self.process = subprocess.Popen(args, stdout=f, close_fds=True)

    def kill(self):
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None

    @property
    def queue(self):
        queue_path = os.path.join(self.sync_dir, "queue")
        queue_files = [x for x in os.listdir(queue_path) if x != '.state']

        queue_l = []
        for queue_file in queue_files:
            with open(os.path.join(queue_path, queue_file), 'rb') as f:
                queue_l.append(f.read())

        return queue_l

    @property
    def crashes(self):
        signals = [signal.SIGSEGV, signal.SIGILL]
        crashes = set()
        crashes_dir = os.path.join(self.sync_dir, "crashes")
        if not os.path.isdir(crashes_dir):
            return []

        for crash in os.listdir(crashes_dir):
            if crash == "README.txt":
                # skip the readme entry
                continue

            attrs_arr = [y.split(':') for y in crash.split(',')]
            attrs = dict([(x[0], x[-1]) for x in attrs_arr])

            if int(attrs['sig']) not in signals:
                continue

            crash_path = os.path.join(crashes_dir, crash)
            with open(crash_path, 'rb') as f:
                crashes.add(f.read())

        return list(crashes)

    @property
    def stats(self):
        stats = {}
        stats_file = os.path.join(self.sync_dir, "fuzzer_stats")
        if os.path.isfile(stats_file):
            with open(stats_file, 'rb') as f:
                stat_blob = f.read()
                stat_lines = stat_blob.split("\n")[:-1]
                for stat in stat_lines:
                    key, val = stat.split(":")
                    stats[key.strip()] = val.strip()
        return stats

    def pollenate(self, testcases):
        # TODO
        pass

    @property
    def pollenated(self):
        nectary_queue_dir = os.path.join(self.sync_dir, 'pollen', 'queue')
        return ExternalFuzzer._pollenated(nectary_queue_dir)
