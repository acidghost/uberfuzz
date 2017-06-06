#!/usr/bin/env python

import sys
import os
import time
import argparse
import logging

import uberfuzz


LOG = logging.getLogger('uber-runner')
LOG.setLevel(logging.INFO)


def main(args):
    uber = uberfuzz.Uberfuzz(args.binary, args.work_dir, logging_time_interval=1,
                             read_from_file=args.reads_file, target_opts=args.extra_opts.split(' '),
                             pollenation_interval=5)
    LOG.info('Starting Uberfuzz on %s', args.binary)
    uber.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        uber.kill()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Uberfuzz runner")
    parser.add_argument('binary', help='Binary to fuzz')
    parser.add_argument('-w', '--work-dir', help='Working directory for fuzzers',
                        default=os.path.join(os.path.dirname(__file__), "work"))
    parser.add_argument('-f', '--reads-file', help='If binary reads from a specific file')
    parser.add_argument('--extra-opts', help='Extra cmd line options for target')
    args = parser.parse_args()

    main(args)
