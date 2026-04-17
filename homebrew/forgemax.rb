class Forgemax < Formula
  desc "Code Mode MCP Gateway — collapses N servers x M tools into 2 tools"
  homepage "https://github.com/postrv/forgemax"
  version "0.5.1"
  license "FSL-1.1-ALv2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-macos-aarch64.tar.gz"
      sha256 "9960b0996be10748e6ac3bb54f092d0f9672ec02866f84a4b6607e4bba04983f"
    else
      url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-macos-x86_64.tar.gz"
      sha256 "bac2dd73402dbc6942f510ab7b5c00efc9433823b534ee11c9c2d30ed91c3691"
    end
  end

  on_linux do
    url "https://github.com/postrv/forgemax/releases/download/v#{version}/forgemax-v#{version}-linux-x86_64.tar.gz"
    sha256 "f94afc5bf618c62d8dc0203a4f8298d55d183a36a1dd8f7c52a9869088fb21a3"
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
