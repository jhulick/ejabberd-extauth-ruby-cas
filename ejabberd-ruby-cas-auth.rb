#!/usr/local/bin/ruby
 
require 'rubygems'
require 'logger'
require 'net/https'
require 'hpricot'
 
$stdout.sync = true
$stdin.sync = true
 
log_path = "/ejabberd/var/log/ejabberd/cas-auth.log" # TODO put into config file
file = File.open(log_path, File::WRONLY | File::APPEND | File::CREAT)
file.sync = true
logger = Logger.new(file)
logger.level = Logger::DEBUG
 
client = Casual::Client.new({
  :hostname => 'https://localhost',
  :path => '/cas',
  :callback_url => "https://localhost/cas_proxy_callback/receive_pgt",
  :logger => logger,
  :http_proxy => "https://proxy:8080"
})
 
def auth(username, password)
  tokens = password.split(",") # if CAS pwd, it will look like https://localhost, ST-765-SX3dfbUFbTOop7LVJmW-cas
 
  if tokens[1].exists? and tokens[1] =~ /^ST-/
    result = client.authenticate(username, tokens[1])
    if result.eql? username
      return true
    else
      return false
    end
  else
    return true # TODO: check if this was an internal auth
  end
 
rescue Exception
  return false
end
 
# TODO add CAS response validation, xml parsing, etc.
 
 
logger.info "Starting ejabberd authentication service"
 
loop do
  begin
    $stdin.eof? # wait for input
    start = Time.now
 
    msg = $stdin.read(2)
    if !msg.nil?
      length = msg.unpack('n').first
 
      msg = $stdin.read(length)
      cmd, *data = msg.split(":")
      pwd = msg.split(",")[1] rescue ""
 
      logger.info "Incoming Request: '#{cmd}'"
      success = case cmd
                  when "auth"
                    logger.info "Authenticating #{data[0]}@#{data[1]} with password: #{pwd}"
                    auth(data[0], data[2])
                  else
                    false
                end
 
      bool = success ? 1 : 0
      $stdout.write [2, bool].pack("nn")
      logger.info "Response: #{success ? "success" : "failure"}"
    end
  rescue => e
    logger.error "#{e.class.name}: #{e.message}"
    logger.error e.backtrace.join("\n\t")
  end
end
 
# Fork the Casual gem instead of using thousands of lines of code from rubycas-client, which
# is tightly coupled to rails and merb. Big ups to Zach Holman - https://github.com/holman/casual
# -- added http proxy and auto detect ssl
module Casual
  class Client
    attr_accessor :hostname, :path, :http_proxy, :callback_url
 
    def initialize(config)
      @hostname     = config[:hostname]
      @path         = config[:path]
      @http_proxy   = config[:http_proxy]
      @callback_url = config[:callback_url]
    end
 
    def authorization_url
      "#{server_url}/login?service=#{callback_url}"
    end
 
    def authenticate(username, password)
      login_page = connection.get("/#{no_slash_path}/login")
      headers = { 'Cookie' => login_page.response["set-cookie"] }
      ticket = acquire_ticket(login_page)
      params = "username=#{username}&password=#{password}&lt=#{ticket}"
      params << '&_eventId=submit&submit=LOGIN'
 
      status,response =
          connection.post("/#{no_slash_path}/login", params, headers)
 
      if response =~ /JA-SIG/
        (response =~ /Log In Successful/) ? username : nil
      else
        status.code == '200' ? username : nil
      end
    end
 
    def acquire_ticket(login_page)
      ticket = Hpricot(login_page.body).search('input[@name=lt]').first
      ticket ? ticket['value'] : nil
    end
 
    def connection
      uri = URI.parse(hostname)
      proxy = URI.parse(http_proxy)
      https = Net::HTTP::Proxy(proxy.host, proxy.port).new(uri.host, uri.port)
      https.use_ssl = (uri.scheme == 'https')
      https
    end
 
    def authenticate_ticket(ticket)
      connection.
        get("/#{no_slash_path}/serviceValidate?service=#{callback_url}" +
            "&ticket=#{ticket}").
        body
    end
 
    def user_login(ticket)
      user = Hpricot::XML(authenticate_ticket(ticket)).
                search('//cas:authenticationSuccess //cas:user').text
      user.strip != '' ? user : nil
    end
 
    def server_url
      "#{hostname}/#{no_slash_path}"
    end
 
    def no_slash_path
      path[0] == 47 ? path[1..path.size] : path
    end
 
  end
end
