#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class MyError(object):
    """
    Definition of standard error.
    """

    def __init__(self):
        self.error_codes = {
            # 20[0-9][1-9] Error for special code
            "ErrorCode": 2000,  # code that may raise exception in here
            # 21[0-9][1-9] Error for dependencies
            "ImportError": 2101,  # code that may raise ImportError
            # 22[0-9][1-9] Error for objects
            "AttributeError": 2201,  # code that may raise AttributeError
            "TypeError": 2202,  # code that may raise TypeError
            "ValueError": 2203,  # code that may raise ValueError
            "IndexError": 2204,  # code that may raise IndexError
            "KeyError": 2205,  # code that may raise KeyError
            "RuntimeError": 2206,  # code that may raise RuntimeError
            # 23[0-9][1-9] Error for operations
            "ZeroDivisionError": 2301,  # code that may raise ZeroDivisionError
            # 24[0-9][1-9] Error for I/O
            "FileNotFoundError": 2401,  # code that may raise FileNotFoundError
            "FileExistsError": 2402,  # code that may raise FileExistsError
            # 25[0-9][1-9] Error for Connect
            "ConnectionError": 2501,  # code that may raise ConnectionError
            "TimeoutError": 2502,  # code that may raise TimeoutError
        }

    def encoding(self, exception):
        """
        Give the error code for exception in standard.
        Error codes have been standardized via the format of
        [standard error][class of error][reserved][index in the class] = 2[0-9][0-9][1-9].
        And special error code in format of 200x.
        param exceptin: -> string
           Same as the exception name to be excepted.
        return:
            Error code in standard.
        """
        if exception in self.error_codes.keys():
            return self.error_codes[exception]
        else:
            return self.error_codes["ErrorCode"]

    def report(self, error, exception, operand, operator):
        """
        Formalize a standard output string to report.
        param error: -> Exception
        param exception: -> string
            Same as the exception name to be excepted.
        param operand: -> string
            Key operation caused error
        param operator: -> string
            Operator operated the operand
        return: -> string
            Error string formalized.
        """
        error_message = str(error)
        error_code = self.encoding(exception)
        return "[{0:}]'{1:}' operated on '{2:}' caused ERROR of [{3:}].".format(error_code,
                                                                                operator,
                                                                                operand,
                                                                                error_message)

    def display(self, error_message):
        """
        Display error message in format.
        param error_message: -> string
            Error message formalized.
        return:
        """
        if error_message is None:
            return 0
        print(error_message)
        return 0
