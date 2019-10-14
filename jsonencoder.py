import base64
import dataclasses
import json
from typing import Any

try:
    from .android.dex import AccessFlag
except ImportError:
    from android.dex import AccessFlag


class DataclassJSONEncoder(json.JSONEncoder):
    def default(self, o: object) -> Any:
        if isinstance(o, bytes):
            return base64.b64encode(o).decode()
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, AccessFlag):
            return o.value
        return super().default(o)
