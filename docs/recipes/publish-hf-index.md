# Publish a dataset archive index once

Publish an archive's ratarmount index alongside the archive on the Hugging Face
Hub. Every downloader can then mount it without scanning archive headers to
rebuild the file table. Archive fingerprint checks still make a few Range reads;
“zero scan” does not mean zero network requests.

The archive must already exist in the repository. Use a token with **write**
access to that repository (for a fine-grained token, grant that repository write
permission). Keep the token in the environment or the normal Hub token file:

```sh
export HF_TOKEN='hf_...'
ratarmount --publish-index 'hf://datasets/your-name/your-dataset@main/shards/00001.tar.zst'
```

This command opens the archive through the same session factory as a mount,
builds or validates a disk index, fingerprints the remote archive, and exits after
publication. It uploads `00001.tar.zst.index.<sha256>.sqlite` and
`00001.tar.zst.index.ptr` in one atomic Hub commit. The pointer identifies the
SQLite bytes by SHA-256 and records the archive's original pinned commit.
An upload or rejected commit cannot expose a new pointer without its blob.
A lost commit response is ambiguous; check the repository history before retrying.

Downloaders need no publication flag:

```sh
ratarmount 'hf://datasets/your-name/your-dataset@main/shards/00001.tar.zst' mnt/
cat mnt/path/to/member
```

Use the branch after publication or the **new commit** printed by the publisher.
The archive's earlier pinned commit does not contain the new sidecars. Readers
pin their own commit and discover both sidecars there, verify the blob SHA-256
and archive fingerprint, and reuse the index. Replacing the archive requires
publishing a fresh index.

For review before updating the dataset branch:

```sh
ratarmount --publish-index --publish-revision main --create-pr \
  'hf://datasets/your-name/your-dataset@main/shards/00001.tar.zst'
```

`--publish-revision` names an existing branch. The default is the archive's
revision when it is a branch; a tag or commit defaults to `main`. The archive at
the destination branch must match the indexed bytes. Concurrent changes to the
branch reject the commit through the Hub's `parentCommit` check. A PR becomes
discoverable from the main branch after it is merged (or directly through its
`@refs/pr/N` revision).

An explicit remote destination names the **archive**, not an index object:

```sh
ratarmount --publish-index-to 'hf://datasets/your-name/your-dataset@main/shards/00001.tar.zst' \
  ./00001.tar.zst
```

The destination archive must already have matching bytes. Local destinations
retain the existing `--publish-index-to PATH` sidecar-copy behavior.

The same blob-before-pointer protocol works with `s3://`, `gs://`, and `az://`
archive URLs, using their existing credential environment variables. Anonymous
publication is refused. Object stores use two ordered writes; a failed pointer
write may leave an orphan immutable blob, while the previous pointer remains.
Remote publication currently limits index blobs to 64 MiB, matching the existing
S3 sibling publisher and bounding in-memory Hub commit encoding.
Hub publication supports ordinary Git files and LFS basic/multipart uploads.
Xet-backed repositories work when their Hub accepts LFS; Xet-only upload
requirements produce an explicit error. Native Xet upload and archive overlay
write-back are not part of index publication.

See [Hub authentication, endpoints, and discovery](../remote-hf.md).
