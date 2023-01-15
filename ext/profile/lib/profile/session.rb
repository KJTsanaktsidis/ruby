# frozen_string_literal: true

module Profile
  class Session
    def initialize
      @perf_helper = Profile::PerfHelperProxy.new
      binding.irb
      @perf_io, @ringbuffer_io = @perf_helper.setup
      @eventloop_wakepipe_r, @eventloop_wakepipe_w = IO.pipe
      @eventloop_thread = _spawn_eventloop_thread
    rescue
      close rescue nil
      raise
    end

    def close
      @eventloop_wakepipe_w&.close
      @eventloop_wakepipe_r&.close
      _signal_stop_eventloop_thread
      @eventloop_thread&.join
      @perf_helper&.close
      nil
    end

    def start
      Thread.list.each do |th|
        @perf_helper.newthread th
      end
    end

    def stop
      # Todo
    end
  end
end
