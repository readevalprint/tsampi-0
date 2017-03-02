import tsampi
import json
import hashlib
import os
import glob


"""
This is a docstring for bantz.
"""

schema = {
    "properties": {
        "text": {
            "type": "string"
        }
    },
    "required": ["text"]
}


def post(text):
    """Save this message"""

    data = json.dumps({'text': str(text)})
    filename = hashlib.sha256(data).hexdigest() + '.json'
    filepath = os.path.abspath(os.path.join('data', filename))
    with open(filepath, 'w') as f:
        f.write(data)
    return(get(filename))


def get(filename):
    """Get a post"""

    filepath = os.path.abspath(os.path.join('data', filename))
    with open(filepath) as f:
        data = json.load(f)
    return {'id': filename, 'data': data}


def get_list():
    """List of paginated posts"""
    return [get(path.split('/')[-1]) for path in glob.glob('data/*')]
