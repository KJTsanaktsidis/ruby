# frozen_string_literal: true
require 'profile.so'
require 'rbconfig'
require 'socket'
require 'stringio'
require 'open3'
require 'io/nonblock'

class Profile
  def self._find_perf_helper
    $LOAD_PATH.map { File.join(_1, "perf_helper#{RbConfig::CONFIG['EXEEXT']}") }.find { File.exist? _1 }
  end

  def self._get_fds_from_helper(req_str)
      r, w = UNIXSocket.pair
      _, errmsg, status = Open3.capture3(_find_perf_helper, "3", 3 => w, stdin_data: req_str)
      if !status.success?
        raise "perf_helper failed: #{errmsg}"
      end
      _, _, _, fds = r.recvmsg(scm_rights: true)
      fds.unix_rights
  end
end
