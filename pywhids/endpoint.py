
class Endpoint():

    def __init__(self, client, data: dict):
        self._client = client
        self._data = data

    @property
    def data(self):
        return self._data

    @property
    def uuid(self):
        return self._data["uuid"]

    @property
    def ip_address(self) -> str:
        return self._data["ip"]

    @property
    def hostname(self) -> str:
        return self._data["hostname"]
