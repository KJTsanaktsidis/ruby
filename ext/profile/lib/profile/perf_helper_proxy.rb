# frozen_string_literal: true

module Profile
  class PerfHelperProxy
    def initialize
      @helper_socket, helper_socket_remote = Socket.socketpair :AF_UNIX, :SOCK_SEQPACKET
      @helper_stderr, helper_stderr_remote = IO.pipe
      @helper_pidfd = self.class._fork_perf_helper(
        self.class.perf_helper_bin_path, helper_socket_remote, helper_stderr_remote
      )
    ensure
      helper_socket_remote&.close
      helper_stderr_remote&.close
    end

    def close
      @helper_socket.close
      Profile::Linux.pidfd_send_sigkill @helper_pidfd
      Profile::Linux.pidfd_wait @helper_pidfd
      @helper_pidfd.close
      @helper_stderr.close
    end

    def setup(max_threads: 1024)
      body_bytes = self.class._build_message_setup(max_threads)
      self_pidfd = Profile::Linux.pidfd_for_main_thread
      creds_ancdata = Profile::Linux.scm_credentials_ancdata
      rights_ancdata = Socket::AncillaryData.unix_rights(self_pidfd)

      @helper_socket.sendmsg body_bytes, 0, nil, creds_ancdata, rights_ancdata
      _, _, _, recvd_ancdata = @helper_socket.recvmsg
      # [0] is the perf group fd, [1] is the bpf ringbuffer fd.
      recvd_ancdata.unix_rights[0..1]
    end

    def newthread
      body_bytes = self.class._build_message_newthread
      thread_pidfd = Profile::Linux.pidfd_for_current_thread
      ancdata = Socket::AncillaryData.unix_rights(thread_pidfd)
    end

    def self.perf_helper_bin_path
      @perf_helper_bin_path ||= begin
        ext_dir = File.dirname(_get_ext_path)
        File.join(ext_dir, "perf_helper#{RbConfig::CONFIG['EXEEXT']}")
      end
    end
  end
end
