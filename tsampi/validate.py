from __future__ import print_function
import monkeypatch  # nopep8

import sys

import StringIO
import patch as pypatch
import argparse
import re
import hashlib
import cgitb
import json

from unidiff import PatchSet
# from voluptuous import Schema, Required, All, Length, Any

# Because debugging from within the sandbox is a PITA.
cgitb.enable(format="text")

DEVELOPER_FINGERPRINTS = ['8C2E500D0D0045B50DB627867CDA9DF0F5CF98B9']


class ValidationError(Exception):
    pass


def parse_diff(lines):
    parents = []
    fingerprint = False
    commit_hash = None

    diff_lines = []
    for line in lines:
        if line.startswith("commit "):
            _, commit_hash = line.split()

        if line.startswith("parent "):
            _, parent = line.split()
            parents.append(parent)

        if diff_lines:
            diff_lines.append(line)

        # get the rest of the diffs after the first one
        if line.startswith('diff ') and not diff_lines:
            diff_lines = [line]

        if line.startswith('Primary key fingerprint:'):
            # This is bad, kids. Stay in school.
            # ex: line = 'Primary key fingerprint: 22E6 9398 3D87 4EA0 CF7C  1947 D934 BC84 BD2F FE0E'
            # this parses out the fingerprint into a single hex number
            fingerprint = ''.join(line.split(':')[1].split())

    # old patch lib
    patch = PatchSet(diff_lines)
    #patch = pypatch.fromstring(''.join(diff_lines))

    return commit_hash, fingerprint, parents, patch, diff_lines


def make_assertions(commit_hash, fingerprint, parents, patch, diff_lines):

    errors = {}
    # no POW for merge.
    if len(parents) == 0:
        if fingerprint not in DEVELOPER_FINGERPRINTS:
            errors['genesis'] = "orphan commit is not signed properly"

    # If this is a valid signed commit, skip everythign else.
    if fingerprint:
        if fingerprint in DEVELOPER_FINGERPRINTS:
            return None
        errors['fingerprint'] = "Fingerprint: %s not in it %s" % (fingerprint, DEVELOPER_FINGERPRINTS)

    if not (commit_hash and re.match('^[0-9a-f]{40}$', commit_hash)):
        error['commit'] = "invalid commit hash %s" % commit_hash
    elif len(parents) == 1:
        # if not commit_hash[0] == '0':
        diff_string = ''.join(diff_lines)
        diff_size = len(diff_string) + 1  # `+ 1` to match `wc -c`
        if not (int((30.0 / (diff_size)) * 1461501637330902918203684832716283019655932542975) > int(commit_hash, 16)):
            errors['pow'] = "Needs more work. Diff size: %s" % (diff_size,)

        if len(patch) > 1:
            errors["files"] = "too many files commited"

        if len(patch.removed_files) != 0:
            errors["files-removed"] = "too many files removed"

        if len(patch.added_files) != 1:
            errors["files-added"] = "only one file can be added: %s" % (patch.added_files)

        try:
            diff_string.decode('utf-8')
        except UnicodeDecodeError as e:
            errors['utf8'] = str(e)

        # TODO: implement gpg key distribution
        # if not fingerprint:
        #    errors['fingerprint'] = 'missing fingerprint on commit: %s' % (commit_hash, )
    else:
        if len(diff_lines) > 0:
            errors['merge'] = 'merge commit should have no conflicts or changes: %s', (commit_hash, )

    # So we know that there is only a single new file that is being validated here.
    # Now extract the data without the unifieddiff meta data and hash it to match the
    # filename.
    patch = pypatch.fromstring(''.join(diff_lines))
    for p in patch.items:

        # Lol.
        # new_file = str('\n'.join('\n'.join(str(l)[1:] for l in h)
        #                         for h in patched_file))
        if p.source == 'dev/null':  # no access to the real /dev/nul
            original_file = StringIO.StringIO()
        else:
            original_file = open(p.source)

        new_file = ''.join(list(patch.patch_stream(original_file, p.hunks)))
        if diff_lines[-1] == '\ No newline at end of file':
            new_file = new_file[:-1]

        # Validate data structure now
        #data = None
        # try:
        #    data = bencode.bdecode(raw_data)
        # except ValueError as e:
        #    raise ValidationError(e)

        # schema = Schema({
        #    Required('parent_sha1'): Any("", All(str, Length(min=40, max=40))),
        #    Required('data'): Any(dict, str)
        #})

        # Validate it!
        # schema(data)

        data_hash = hashlib.sha256(new_file).hexdigest()

        # Data hash matches file name in the ./data/ directory
        if p.target.startswith('b/data/'):

            if p.target.endswith('.json'):
                target_path = ('data/' + data_hash + '.json')
                if p.target[2:] != target_path:
                    errors["name"] = 'Target file %s is not named %s, make sure the path and sha1 hexdigest is correct' % (p.target[2:], target_path)

                schema = Schema({
                    Required('parent_sha1'): Any("", All(str, Length(min=40, max=40))),
                    Required('data'): Any(dict, str)
                })

                # Validate it!
                schema(data)

            else:
                errors['name'] = "Invalid extension"

        else:
            errors["path"] = 'invalid directory. Should be in "data/"'  # we need better error messages

    return errors


def add_arguments(parser):
    parser.add_argument('-f', '--git-show-file',
                        type=argparse.FileType('r'),
                        default='-',
                        dest='diff',
                        help='file with `git show --show-signature -c COMMIT_HASH` data (default stdin)')


def run(parser):  # pragma: no cover
    args = parser.parse_args()
    lines = args.diff.readlines()

    commit_hash, valid_sig, parents, patch, diff_lines = parse_diff(lines)
    errors = make_assertions(commit_hash, valid_sig, parents, patch, diff_lines)
    print(json.dumps(errors))
    if errors:
        sys.exit(errors)

if __name__ == '__main__':  # pragma: no branch
    # Hmmm, coverage doesn't respect `pragma: no cover` for these kwargs on
    # different lines.
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description='Validated the potential child commit.\nPipe output of `git show --format=raw --show-signature -c COMMIT_HASH` to this script')  # pragma: no cover

    # This allows other moduels to include these options in their argparer
    add_arguments(parser)  # pragma: no cover
    run(parser)  # pragma: no cover
