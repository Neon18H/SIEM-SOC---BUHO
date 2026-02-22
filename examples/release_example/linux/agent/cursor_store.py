import json
from pathlib import Path


class CursorStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text('{}', encoding='utf-8')

    def load(self):
        return json.loads(self.path.read_text(encoding='utf-8') or '{}')

    def save(self, data):
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
