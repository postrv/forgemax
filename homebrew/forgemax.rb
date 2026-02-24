class Forgemax < Formula
  desc "Code Mode MCP Gateway — collapses N servers x M tools into 2 tools"
  homepage "https://github.com/postrv/forgemax"
  version "0.1.1"
  license "FSL-1.1-ALv2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-macos-aarch64.tar.gz"
      sha256 "c94dc7bb84f2b69c914c363d6715f5b3c6dfdd3a96934c26c3031deddf47d793"
    else
      url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-macos-x86_64.tar.gz"
      sha256 "d0d8edde4fd2906d61228df5e8fbe4554647c2790fa0b59df3d0b3c7bca5ade2"
    end
  end

  on_linux do
    url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-linux-x86_64.tar.gz"
    sha256 "1210e9398e397825d9dbf0f183ecf4639d3c1a7974d4fab9efb53da4ba51e8a2"
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
