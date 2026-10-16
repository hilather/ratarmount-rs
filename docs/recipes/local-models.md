# Lazy model files for vLLM and llama.cpp

Keep model artifacts on the Hub and inspect or read them through ratarmount's
`hf://` source instead of first expanding an entire repository. Pin a commit
SHA for a reproducible deployment. Use the remote range cache and the shared
Hugging Face cache on local NVMe when supported by the installed version; set
`HF_HOME` to the NVMe cache directory before starting readers. The range cache
stores fetched file ranges, while the Hugging Face cache can share complete Hub
blobs with other Hub clients.

For example, place both caches on the model host's NVMe and size ratarmount's
persistent payload/range cache to available disk space:

```sh
export HF_HOME=/nvme/huggingface
export RATARMOUNT_PAYLOAD_CACHE_DIR=/nvme/ratarmount/payload-v1
export RATARMOUNT_PAYLOAD_CACHE_BYTES=100G
```

`RATARMOUNT_PAYLOAD_CACHE_BYTES` is a disk cache cap, not an in-memory weight
or RSS budget. See [Hub cache settings](../remote-hf.md#one-shared-hub-cache)
for the shared cache behavior.

The safetensors plugin exposes tensor metadata and byte ranges for inspection.
For example, with a mounted model directory, inspect generated
`__metadata__.json` and each tensor's `.json` sidecar. llama.cpp can use GGUF
files directly through a compatible consumer.

vLLM reads model weights into host/device memory during engine startup. A lazy
mount can avoid an up-front copy into another directory and fetch bytes on
demand during startup, but it does not turn vLLM's weight loading into
request-time paging. Provision enough memory for the full model and account for
startup network traffic.

Run the small smoke script with `MODEL_URL=hf://...` to inspect a selected
public or private model. The script reports a mount skip without `/dev/fuse`.

```sh
docs/recipes/scripts/local-models.sh
```
