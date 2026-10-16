class RatarmountRs < Formula
  desc "Mount archives as a filesystem with random access"
  homepage "https://github.com/hilather/ratarmount-rs"
  url "https://github.com/hilather/ratarmount-rs/archive/refs/tags/v0.1.34.tar.gz"
  version "0.1.34"
  sha256 "62788fe978c98493aed4f196f1b5682ca39d018e41c259199f482b768c6cb618"
  license "MIT"

  depends_on :linux
  depends_on "rust" => :build
  depends_on "pkgconf" => :build
  depends_on "fuse3"
  depends_on "libarchive"
  depends_on "openssl"
  depends_on "sqlite"
  depends_on "zstd"

  def install
    system "cargo", "install", "--locked", "--path", ".", "--root", prefix,
           "--features", "nfsv4,sftp-russh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/ratarmount --version")
  end
end
