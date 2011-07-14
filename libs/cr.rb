#
#  Copyright (c) 2011, John-John Tedro <johnjohn.tedro@toolchain.eu>
#  All rights reserved.
#  see LICENSE
#
require 'openssl'
require 'base64'

class CR
  @@algos = {
    "SHA1" => OpenSSL::Digest::SHA1,
    "MD5"  => OpenSSL::Digest::MD5,
    "DSS1" => OpenSSL::Digest::DSS1
  }

  def initialize(key)
    @keydata = File.read(key)
    @pk      = OpenSSL::PKey::DSA.new(@keydata)
  end

  def get_algorithm(name)
    name = name.to_s.upcase
    a = @@algos[name] || nil
    raise RuntimeError, "no algorithm matching '#{name}'" if a.nil?
    return name, a
  end

  def sign(source, algo = :dss1)
    name, md = get_algorithm(algo)
    digest = digest_type(source, md)
    dg = Base64.encode64(@pk.sign(md.new, digest)).gsub(/\s/, "")
    "#{name}:#{dg}"
  end

  def verify?(source, sig)
    sep = sig.index(":")
    return false if sep.nil?

    begin
      name, md = get_algorithm(sig[0..sep-1])
      sig = Base64.decode64(sig[sep..-1])
      digest = digest_type(source, md)
      @pk.verify(md.new, sig, digest)
    rescue
      return false
    end
  end

private
  def digest_type(source, md)
    if source.instance_of? String
      digest_string(source, md)
    elsif source.instance_of? File
      digest_file(source, md)
    else
      raise RuntimeError, "unsupported type '#{source.class}'"
    end
  end

  def digest_file(file, md)
    d = file.read(4096)
    m = md.new

    while d
      m.update(d)
      d = file.read(4096)
    end

    return m.digest
  end

  def digest_string(str, md)
    m = md.new
    m.update(str)
    m.digest
  end
end
