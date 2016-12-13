"""utils"""

import subprocess


def run_command(cmd):
    """run a system call"""
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE,
        stderr=subprocess.PIPE, stdout=subprocess.PIPE,
        close_fds=False, shell=False)

    (stdout, stderr) = proc.communicate()

    return stdout, stderr
