class TLSError(Exception):
    pass


class WantWriteError(TLSError):
    pass


class WantReadError(TLSError):
    pass


class RaggedEOF(TLSError):
    pass


class ConfigurationError(TLSError):
    pass


class EarlyDataRejectedError(TLSError):
    pass


class ParseError(TLSError, ValueError):
    # bytes or text that do not have the shape they were said to have
    pass


class ProxyError(ConnectionError):
    pass
