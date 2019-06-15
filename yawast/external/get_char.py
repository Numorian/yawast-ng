# From: https://stackoverflow.com/a/36974338
# License: Creative Commons Attribution-Share Alike
# Copyright: Matthew Strax-Haber


def getchar():
    # figure out which function to use once, and store it in _func
    if "_func" not in getchar.__dict__:
        try:
            # for Windows-based systems
            import msvcrt  # If successful, we are on Windows

            getchar._func = msvcrt.getch

        except ImportError:
            # for POSIX-based systems (with termios & tty support)
            import tty, sys, termios, fcntl, os

            def _ttyread():
                fd = sys.stdin.fileno()

                oldterm = termios.tcgetattr(fd)
                newattr = termios.tcgetattr(fd)
                newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
                termios.tcsetattr(fd, termios.TCSANOW, newattr)

                oldflags = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)

                try:
                    while 1:
                        try:
                            answer = sys.stdin.read(1)

                            if answer == "\x03":
                                raise KeyboardInterrupt

                            break
                        except IOError:
                            pass
                finally:
                    termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
                    fcntl.fcntl(fd, fcntl.F_SETFL, oldflags)

                return answer

            getchar._func = _ttyread

    return getchar._func()
