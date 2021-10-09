class UnexpectedStatusError(Exception):

    def __init__(self, status: int):
        super().__init__(f"Unexpected HTTP status: {status}")

class APIError(Exception):

    def __init__(self, message: str):
        super().__init__(message)