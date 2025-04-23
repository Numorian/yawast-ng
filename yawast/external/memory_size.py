# From: https://github.com/ActiveState/code/blob/master/recipes/Python/578323_Humreadable_filememory_sizes/recipe-578323.py
# License: MIT
# Copyright: ActiveState

import math


class Size(int):
    """define a size class to allow custom formatting
    format specifiers supported :
        em : formats the size as bits in IEC format i.e. 1024 bits (128 bytes) = 1Kib
        eM : formats the size as Bytes in IEC format i.e. 1024 bytes = 1KiB
        sm : formats the size as bits in SI format i.e. 1000 bits = 1kb
        sM : formats the size as bytes in SI format i.e. 1000 bytes = 1KB
        cm : format the size as bit in the common format i.e. 1024 bits (128 bytes) = 1Kb
        cM : format the size as bytes in the common format i.e. 1024 bytes = 1KB
    """

    def __format__(self, fmt):
        # Handle empty format string safely
        if (
            not fmt
            or len(fmt) < 2
            or fmt[-2:].lower() not in ["em", "sm", "cm", "eM", "sM", "cM"]
        ):
            if fmt and fmt[-1].lower() in [
                "b",
                "c",
                "d",
                "o",
                "x",
                "n",
                "e",
                "f",
                "g",
                "%",
            ]:
                # Numeric format.
                return int(self).__format__(fmt)
            else:
                return str(self).__format__(fmt)

        fmt_key = fmt[-2:]
        if fmt_key == "em":
            factor = 8
            base = 1024
            mult = ["", "K", "M", "G", "T", "P"]
            suffix = "ib"
        elif fmt_key == "eM":
            factor = 1
            base = 1024
            mult = ["", "K", "M", "G", "T", "P"]
            suffix = "iB"
        elif fmt_key == "sm":
            factor = 8
            base = 1000
            mult = ["", "k", "m", "g", "t", "p"]  # lower-case for SI bits
            suffix = "b"
        elif fmt_key == "sM":
            factor = 1
            base = 1000
            mult = ["", "K", "M", "G", "T", "P"]
            suffix = "B"
        elif fmt_key == "cm":
            factor = 8
            base = 1024
            mult = ["", "K", "M", "G", "T", "P"]
            suffix = "b"
        elif fmt_key == "cM":
            factor = 1
            base = 1024
            mult = ["", "K", "M", "G", "T", "P"]
            suffix = "B"
        else:
            factor = 1
            base = 1024
            mult = ["", "K", "M", "G", "T", "P"]
            suffix = "B"

        val = float(self) * factor
        i = 0 if val < 1 else int(math.log(val, base)) + 1
        v = val / math.pow(base, i)
        v, i = (v, i) if v > 0.5 else (v * base, i - 1)

        width = "" if fmt.find(".") == -1 else fmt[: fmt.index(".")]
        precis = fmt[:-2] if width == "" else fmt[fmt.index(".") : -2]
        if precis == "":
            precis = ".2"

        t = ("{0:{1}f}" + mult[i] + suffix).format(v, precis)
        return "{0:{1}}".format(t, width) if width != "" else t
