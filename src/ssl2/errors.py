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


class EarlyDataRejected(TLSError):
    pass
