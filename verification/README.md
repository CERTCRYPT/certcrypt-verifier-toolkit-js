# Verifying this repository

Every file published in this repository is certified by CERTCRYPT: a proof
that its exact bytes existed, as published by CERTCRYPT, when the proof
settled. Anyone can check it without asking anyone, and without CERTCRYPT
continuing to exist.

It establishes when each version of each file existed, and that it was published
here. It says nothing about whether the content is correct, and by itself it
does not establish who holds the rights in it: the copyright notices and the
license do.

## What is certified

Files are certified as they are published. Each certification covers the files
that were new or changed since the previous one, with one certificate:

| | |
| --- | --- |
| Subject | one `subject.collection/1` |
| Leaves | one `subject.binary/1` per file, its exact bytes, in path order |
| Declared cardinality | the number of files the certification covers |

`subject.binary/1` applies no normalization: a file verifies only if every byte
is the one that was published. Paths are not part of a leaf; content and order
are, and `collection.json` gives the order.

Files change. A changed file is certified again when it is published, and every
earlier certification still proves the version it covered: a file has as many
certified versions as it has had published contents.

This directory is not certified: it is where the proofs are published.

## What is here

- `index.json`: every file of the repository, its SHA3-256 digest and the
  certification that certifies its current content.
- `<id>/`: one directory per certification, named after the time it was issued
  (UTC):
  - `verification-package.json`: the proof, as a `verification-package/1`;
  - `system-foundation.json`: the `system-foundation/1` it is verified against;
  - `collection.json`: the certified files in leaf order, with their digests, the
    collection root and the proof's `subtree_root`.

The history of this repository keeps every certified version. In the first
commit that contains `<id>/`, every file that certification lists has exactly
its certified bytes:

```
git log --diff-filter=A --format=%H -- verification/<id>/collection.json
```

## How to verify a certification

1. **Take the files.** Check out the commit above and read, in the order
   `collection.json` lists them, the files of the certification.
2. **Recompute the collection.** The base certificate is in the package. Its
   `anchor` member carries `nonce_hex`, and its one subject is a
   `subject.collection/1` whose leaves list one digest per file. For each file, compute its leaf under
   `collection.merkle-sha3-256/1` over its exact bytes, salted with the ASCII
   bytes of `nonce_hex` (`subject.collection/1` §8), compare it with the leaf at
   the same position, and fold the leaves into the collection root.
3. **Compare.** The folded root must equal the collection root the certificate
   signs, and the number of files its declared cardinality. If anything differs,
   the files are not the ones certified.
4. **Verify the proof.** Read the package under `verification-package/1` and
   validate it under `independence.proof/1`: its settlement reference, its
   inclusion and its finality, each as the settlement material carries it. No
   CERTCRYPT service is needed.

The JavaScript verifier toolkit performs steps 2 to 4 with
`verifyCertifiedFiles`. It is not required: the procedure above is complete, and
the specifications it cites are published in `certcrypt-specs`.

## Contributions

Proposals and defect reports are welcome as issues. Pull requests are not
accepted: every file here is written by the CERTCRYPT team, which is what
lets each one carry this certification.
