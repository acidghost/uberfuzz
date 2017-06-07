'''main module runner: uberrun'''

import os
import time
import argparse
import logging
import IPython

import uberfuzz


LOG = logging.getLogger('ubermain')
LOG.setLevel(logging.INFO)


def main(binary, work_dir, reads_file, extra_opts, aflfast_path, interactive):
    '''main function'''
    # pylint: disable=too-many-arguments
    target_opts = extra_opts.split(' ') if extra_opts else None
    uber = uberfuzz.Uberfuzz(binary, work_dir, logging_time_interval=1,
                             read_from_file=reads_file, target_opts=target_opts,
                             pollenation_interval=5, aflfast_path=aflfast_path)
    LOG.info('Starting Uberfuzz on %s', binary)
    uber.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        uber.kill()

    if interactive:
        IPython.embed()


if __name__ == '__main__':
    # pylint: disable=invalid-name

    WORK_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'work'))

    parser = argparse.ArgumentParser(prog='uberrun', description='Uberfuzz runner')
    parser.add_argument('binary', help='Binary to fuzz')
    parser.add_argument('-w', '--work-dir', help='Working directory for fuzzers',
                        default=os.path.join(os.path.dirname(__file__), '..', 'work'))
    parser.add_argument('-f', '--reads-file', help='If binary reads from a specific file')
    parser.add_argument('-e', '--extra-opts', help='Extra cmd line options for target')
    parser.add_argument('-a', '--aflfast-path', help='AFL Fast executable')
    parser.add_argument('-i', '--interactive', help='Opens IPython after fuzzing',
                        action='store_true')
    parser.set_defaults(interactive=False)
    args = parser.parse_args()

    main(args.binary, args.work_dir, args.reads_file, args.extra_opts, args.aflfast_path,
         args.interactive)
