# Purpose Source's public signing keys: a signed copy

This repository holds a copy of the key set that Purpose Source publishes at
<https://api.purposesource.org/jwks.json>: the public keys that check the signatures on its certificates
(<https://purposesource.org/docs/verify>). It is a second channel, kept apart from our websites, so that a change
to our sites alone cannot swap a key unnoticed.

## Who can change it

- Only the Association's two administrators.
- Every change to `main` is a pull request that the other administrator approves. GitHub refuses unsigned commits,
  force-pushes and deletion on `main`, and no one is exempt.
- Our own commits are signed with an administrator's personal SSH key. `allowed_signers` lists both keys, so anyone
  can see which key signed what. The merge commits are signed by GitHub itself
  (<https://github.com/web-flow.gpg>).
- Software Heritage archives every change (<https://archive.softwareheritage.org>). Its visit dates show,
  independently of our clocks, by when each key was here.

## How to check it

```bash
git clone https://github.com/purposesource/keys && cd keys
git config gpg.ssh.allowedSignersFile allowed_signers
git log --show-signature        # our commits: Good "git" signature for ... with ED25519 key SHA256:...
curl -s https://api.purposesource.org/jwks.json | jq -S .keys > live.json
jq -S .keys jwks.json | diff - live.json && echo "the published keys match the signed copy"
```

`tools/ceremony-thumbprint.py` prints a key's RFC 7638 thumbprint, the fingerprint each participant reads out at a
key ceremony. It uses Python's standard library only.

## What it shows, and what it does not

- **It shows** whether the keys our sites serve are the keys our two administrators put here. Any difference is
  visible to anyone.
- **It does not show** how a private key was made. That is the key ceremony's witnessed record, kept in
  `ceremonies/` from the first ceremony on.
- **It does not stop** the administrators from deleting this repository or loosening its rules. The Software
  Heritage copy survives that, and GitHub's audit log records a change of the rules.
