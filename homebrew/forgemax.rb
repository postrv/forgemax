class Forgemax < Formula
  desc "Code Mode MCP Gateway — collapses N servers x M tools into 2 tools"
  homepage "https://github.com/postrv/forgemax"
  version "0.1.0"
  license "FSL-1.1-ALv2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-macos-aarch64.tar.gz"
      # sha256 "PLACEHOLDER — update after first release"
    else
      url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-macos-x86_64.tar.gz"
      # sha256 "PLACEHOLDER — update after first release"
    end
  end

  on_linux do
    url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-linux-x86_64.tar.gz"
    # sha256 "PLACEHOLDER — update after first release"
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
