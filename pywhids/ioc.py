import uuid

from .objects import APIObject

class IOC(APIObject):

    def __init__(self, uuid="", guuid="", source="", value="", type=""):
        self.uuid = uuid
        self.guuid = guuid
        self.source = source
        self.value = value
        self.type = type

        if self.uuid is None or self.uuid == "":
            self.uuid = uuid.uuid4()

    
    def __str__(self):
        return f"uuid:{self.uuid} guuid:{self.guuid} source:{self.source} type:{self.type} value:{self.value}"


