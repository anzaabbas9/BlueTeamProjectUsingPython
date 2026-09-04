"""Simple JSON-file cache so repeated runs don't burn API rate limits."""

import json

DEFAULT_CACHE_FILE = 'cache.json'


def load_cache(filename=DEFAULT_CACHE_FILE):
    """Load the cache from disk, returning an empty dict if it doesn't exist yet."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}


def save_cache(cache, filename=DEFAULT_CACHE_FILE):
    """Write the cache dict back to disk as JSON."""
    with open(filename, 'w') as f:
        json.dump(cache, f)
