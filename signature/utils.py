"""utils"""

import subprocess


def run_command(cmd, close_fds=False, stdout=subprocess.PIPE):
    """run a system call"""
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE,
        stderr=subprocess.PIPE, stdout=stdout,
        close_fds=close_fds, shell=False)

    (stdout, stderr) = proc.communicate()

    return proc.returncode, stdout, stderr
