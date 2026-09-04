# Tap-ready cask: unpacks the signed GitHub Release macos-arm64 tarball.
# Not a source formula (no cargo / formula build deps). Homebrew-core is out of v1.
# Tap root is packaging/homebrew/ (this file lives in Casks/).
cask "ratarmount" do
  version "0.1.30"
  sha256 "68a1e18c38ab3d70040c9655892b4211a6b9a4964f0e2e004aef3e5033ee59c5"

  url "https://github.com/hilather/ratarmount-rs/releases/download/v#{version}/ratarmount-#{version}-macos-arm64.tar.gz"
  name "ratarmount"
  desc "Mount archives as a FUSE filesystem with random access"
  homepage "https://github.com/hilather/ratarmount-rs"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: ">= :sonoma"
  depends_on arch: :arm64

  binary "ratarmount-#{version}-macos-arm64/ratarmount"

  caveats <<~EOS
    ratarmount needs a FUSE backend on macOS (there is no /dev/fuse).
    Install ONE of:

      brew install --cask macfuse          # macFUSE (recommended)
      brew install macos-fuse-t/homebrew-cask/fuse-t  # FUSE-T (no kext)

    On macOS 26 Tahoe, prefer FSKit if the kernel extension is blocked:
      ratarmount -f -o backend=fskit archive.tar.gz mnt/

    This prebuilt binary dynamically links libarchive. Install it at runtime:

      brew install libarchive

    Full guide: https://github.com/hilather/ratarmount-rs/blob/main/docs/macos.md
  EOS
end
