##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Dropbox scanner',
      'Version'     => '1.1',
      'Description' => 'This module scans for dropbox listeners on default TCP port 17500', 
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
        print_status("DROPBOX Service Listening: #{ip}:#{rport}")
        report_service(:host => rhost, :port => rport, :name => "Dropbox")
      end
    
    rescue ::Rex::ConnectionError
    rescue Timeout::Error
        print_error("#{target_host}:#{rport}, Server timed out after #{to} seconds.  Skipping.")
    rescue ::Exception => e
        print_error("#{e},#{e.backtrace}")
    end

  end
end
