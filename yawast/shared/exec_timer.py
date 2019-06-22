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
