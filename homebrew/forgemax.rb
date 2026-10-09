class Forgemax < Formula
  desc "Code Mode MCP Gateway — collapses N servers x M tools into 2 tools"
  homepage "https://github.com/postrv/forgemax"
  version "0.6.1"
  license "FSL-1.1-ALv2"

  on_macos do
    depends_on macos: :ventura
    if Hardware::CPU.arm?
      url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-macos-aarch64.tar.gz"
      sha256 "3958c4bb2a9d05678e13c3b0598def3787611be4d729e956e1f6dc041da15178"
    else
      url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-macos-x86_64.tar.gz"
      sha256 "e1dc539efe4bc82e35834e68b5f648f750f0eb2f408f89a2645e9d9adf596672"
    end
  end

  on_linux do
    url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-linux-x86_64.tar.gz"
    sha256 "72c8fc90b52a47b58da6d6e92d672cef7454aea84bc07f45cb4a42afe3bc4bd2"
  end

  def install
    bin.install "forgemax"
    bin.install "forgemax-worker"
    share.install "forge.toml.example"
  end

  test do
    assert_match "forgemax #{version}", shell_output("#{bin}/forgemax --version")
  end
end
