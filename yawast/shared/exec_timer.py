#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from datetime import datetime


class ExecutionTimer:
    def __enter__(self):
        self.begin = datetime.now()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = datetime.now()
        self.execution_time = self.end - self.begin

    def to_ms(self) -> int:
        """
        Returns the execution time, in milliseconds
        :return:
        """
        return int(self.execution_time.total_seconds() * 1000)
