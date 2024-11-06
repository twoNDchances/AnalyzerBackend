import re


def get_value_from_json(data, path: str):
    keys = re.split(r'\.(?![^\[]*\])', path)
    for key in keys:
        match = re.match(r'([\w\-]+)(\[(\d+)\])?', key)
        if not match:
            return None
        key, _, index = match.groups()
        if isinstance(data, dict):
            data = data.get(key)
            if data is None:
                return None
        else:
            return None
        if index is not None:
            try:
                index = int(index)
                data = data[index]
            except (IndexError, TypeError, ValueError):
                return None
    return data


def parse_path(path: str) -> list[str] | str | None:
    if path.startswith("[") and path.endswith("]"):
        paths = re.split(r',\s*', path[1:-1].strip())
        if all(re.match(r'^[\w\.-]+$', p) for p in paths):
            return paths
        else:
            return None
    elif re.match(r'^[\w\.-]+$', path):
        return path
    else:
        return None


def is_valid_regex(pattern):
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def traverse_json(data, parent_key='') -> list[dict]:
    paths = []
    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            paths.extend(traverse_json(value, new_key))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            new_key = f"{parent_key}[{index}]"
            paths.extend(traverse_json(item, new_key))
    else:
        paths.append({parent_key: data})
    return paths

