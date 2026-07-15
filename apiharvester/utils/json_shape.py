"""Shared JSON response field extraction — used by recon and attack phases."""
import json


def extract_fields(body):
    """Extract top-level field names from a JSON response body."""
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            return set(data.keys())
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return set(data[0].keys())
    except (json.JSONDecodeError, TypeError):
        pass
    return set()
