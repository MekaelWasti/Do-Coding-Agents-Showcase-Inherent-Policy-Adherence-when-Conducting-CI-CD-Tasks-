"""Shared generated-output location; downloaded raw data is unaffected."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / 'output_location.json'
OUT = Path(json.loads(CONFIG.read_text(encoding='utf-8'))['outputs']) if CONFIG.exists() else ROOT / 'outputs'
