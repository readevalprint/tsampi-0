import json


def echo(x):
    """This is a doc string"""
    print("some output from echo()")
    return "You supplied: " + json.dumps(x)

def write(name, data):
    with open(name, 'w') as f:
        f.write(data)
