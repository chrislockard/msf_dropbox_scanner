##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Dropbox scanner',
      'Description' => 'This module scans for dropbox listeners on default TCP and UDP ports', 
      'Author'      => 'Dagorim - penetrate.io',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(17500),
        OptInt.new('TIMEOUT', [true, 'Timeout for Dropbox probe', 30])
      ], self.class)
  end

  def to
    return 30 if datastore['TIMEOUT'].to_i.zero?
    datastore['TIMEOUT'].to_i
  end
  
  def run_host(ip)
    begin
      ::Timeout.timeout(to) do
        res = connect
        banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
        print_status("#{ip}:#{rport} DROPBOX#{banner_sanitized}")
        report_service(:host => rhost, :port => rport, :name => "Dropbox", :info => banner_sanitized)
    end
    rescue ::Rex::ConnectionError
    rescue Timeout::Error
        print_error("#{target_host}:#{rport}, Server timed out after #{to} seconds.  Skipping.")
    rescue ::Exception => e
        print_error("#{e},#{e.backtrace}")
    end
  end
end
