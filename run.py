import sys
import os
import uberfuzz
import time


def main(binary_path, work_dir):
    uber = uberfuzz.Uberfuzz(binary_path, work_dir, logging_time_interval=1)
    uber.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        uber.kill()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage: %s binary_path [work_dir]' % os.path.basename(sys.argv[0])
        sys.exit()
    default_work_dir = os.path.join(os.path.dirname(__file__), "work")
    work_dir = sys.argv[2] if len(sys.argv) > 2 else default_work_dir
    main(sys.argv[1], work_dir)
