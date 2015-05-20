# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/timestamp"

# This input will pull events from a http://msdn.microsoft.com/en-us/library/windows/desktop/bb309026%28v=vs.85%29.aspx[Windows Event Log].
#
# To collect Events from the System Event Log, use a config like:
# [source,ruby]
#     input {
#       eventlog {
#         type  => 'Win32-EventLog'
#         logfile  => 'System'
#       }
#     }
class LogStash::Inputs::EventLog < LogStash::Inputs::Base

  config_name "eventlog"

  default :codec, "plain"

  # Event Log Name
  config :logfile, :validate => :string, :validate => [ "Application", "Security", "System" ], :default => "Application"

  # How frequently should tail check for new event logs in ms (default: 1 second)
  config :interval, :validate => :number, :default => 1000

  public
  def register

    # wrap specified logfiles in suitable OR statements
    @hostname = Socket.gethostname
    @logger.info("Opening eventlog #{@logfile}")

    require "win32/eventlog"

    @eventlog = Win32::EventLog.open(@logfile)
  end # def register

  public
  def run(queue)

    @logger.debug("Tailing Windows Event Log '#{@logfile}'")
    @eventlog.tail(@interval/1000.0) do |log|

      e_hash = Hash[log.each_pair.to_a].merge({
        "host" => @hostname,
        "path" => @logfile,
      })
      @logger.debug e_hash.inspect
      event = LogStash::Event.new(e_hash)

      decorate(event)
      queue << event

    end # loop

  rescue LogStash::ShutdownSignal
    return
  rescue => ex
    @logger.error("Windows Event Log error: #{ex}\n#{ex.backtrace}")
    sleep 1
    retry
  end # def run

end # class LogStash::Inputs::EventLog
