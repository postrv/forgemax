class Forgemax < Formula
  desc "Code Mode MCP Gateway — collapses N servers x M tools into 2 tools"
  homepage "https://github.com/postrv/forgemax"
  version "0.6.0"
  license "FSL-1.1-ALv2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-macos-aarch64.tar.gz"
      sha256 "7136464d73ddf1938d12858854b258fd0881e4baeb6a8db609450c29243b3125"
    else
      url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-macos-x86_64.tar.gz"
      sha256 "7cd650d63e5ca072509411cf54d3dd4454126b68b7cac106cd2eab04a7ed5849"
    end
  end

  on_linux do
    url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-linux-x86_64.tar.gz"
    sha256 "70f7d32ac9e1e7a5d9ed0f12cca8f8b642a8417fbb3d92c418c0ee36fbcb23cb"
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
