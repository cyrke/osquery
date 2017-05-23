require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Smartmontools < AbstractOsqueryFormula
  desc "SMART hard drive monitoring; Fork with smartctl exposed as a static library"
  homepage "https://www.smartmontools.org/"
  url "https://github.com/allanliu/smartmontools/archive/v0.2.2.tar.gz"
  sha256 "e8b43194d3c967fc09b99e883da6b57f70e979ffd3bde8c456a9bde58e357e32"


  depends_on "automake" => :build
  depends_on "autoconf" => :build
  depends_on "libtool" => :build

  def install
    system "./autogen.sh"

    ENV.append "CXXFLAGS", "-fPIC"
    system "./configure", "--prefix=#{prefix}"
    system "make", "install"
  end
end
