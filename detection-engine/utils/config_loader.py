import yaml
from pathlib import Path

def load_config(path="config.yaml"):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path.resolve()}")
    with path.open("r") as f:
        return yaml.safe_load(f)

