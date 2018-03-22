require 'socket'
require 'openssl'
require 'json'

module APNS
  class Core
    attr_accessor :host, :pem, :port, :pass

    def initialize(options={})
      @host = options.delete(:host) || 'gateway.sandbox.push.apple.com'
      @port = options.delete(:port) || 2195
      # openssl pkcs12 -in mycert.p12 -out client-cert.pem -nodes -clcerts
      @pem = options.delete(:pem) # this should be the path of the pem file not the contentes
      @pass = options.delete(:pass)

      @persistent = false
      @mutex = Mutex.new
      @retries = 3 # TODO: check if we really need this

      @sock = nil
      @ssl = nil
    end

    def start_persistence
      @persistent = true
    end

    def stop_persistence
      @persistent = false

      @ssl&.close
      @sock&.close
    end

    def send_notification(device_token, message)
      n = APNS::Notification.new(device_token, message)
      self.send_notifications([n])
    end

    def send_notifications(notifications)
      @mutex.synchronize do
        self.with_connection do
          notifications.each do |n|
            @ssl.write(n.packaged_notification)
          end
        end
      end
    end

    def feedback
      sock, ssl = self.feedback_connection

      apns_feedback = []

      while line = ssl.read(38)   # Read lines from the socket
        line.strip!
        f = line.unpack('N1n1H140')
        apns_feedback << { :timestamp => Time.at(f[0]), :token => f[2] }
      end

      ssl&.close
      sock&.close

      return apns_feedback
    end

  protected

    def with_connection
      attempts = 1

      begin
        # If no @ssl is created or if @ssl is closed we need to start it
        if @ssl.nil? || @sock.nil? || @ssl.closed? || @sock.closed?
          @sock, @ssl = self.open_connection
        end

        yield

      rescue StandardError, Errno::EPIPE
        raise unless attempts < @retries

        @ssl&.close
        @sock&.close

        attempts += 1
        retry
      end

      # Only force close if not persistent
      unless @persistent
        @ssl&.close
        @ssl = nil
        @sock&.close
        @sock = nil
      end
    end

    def open_connection
      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless @pem
      raise "The path to your pem file does not exist!" unless File.exist?(@pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(@pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(@pem), @pass)

      sock         = TCPSocket.new(@host, @port)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
      ssl.connect

      return sock, ssl
    end

    def feedback_connection
      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
      raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(@pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(@pem), @pass)

      fhost = @host.gsub('gateway','feedback')

      sock         = TCPSocket.new(fhost, 2196)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock, context)
      ssl.connect

      return sock, ssl
    end
  end
end
