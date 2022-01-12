import json

class APIObject():

    def __init__(self):
        pass

    def from_dict(self, d: dict):
        for k,v in d.items():
            self.__setattr__(k, v)

    def to_dict(self):
        d = {}
        for k,v in self.__dict__.items():
            # do not serialize private attributes
            if not k.startswith("_"):
                d[k] = v
        return d
    
    def to_json(self):
        return json.dumps(self.to_dict())