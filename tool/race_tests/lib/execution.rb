# frozen_string_literal: true

require 'rbconfig'
require 'shellwords'

module RaceTests
  class Execution
    def initialize(program)
      @program_text = program
    end

    attr_reader :gdb

    def run
      @program_file = Tempfile.create
      @program_file.write @program_text
      @program_file.rewind

      child_env = {}
      %w(RUBYLIB GEM_PATH PATH LIBRUBY_SO RUBY).each do |var|
        child_env[var] = ENV[var] if ENV.key?(var)
      end
      %w(LANG LC_ALL LC_CTYPE).each do |var|
        child_env[var] = 'C'
      end

      @gdb = GdbMi.new(gdb: RbConfig::CONFIG['GDB'])
      @gdb.run do
        @gdb.auto_load_enabled = false
        @gdb.debuginfod_enabled = false
        @gdb.start_inferior(EnvUtil.rubybin, @program_file.path, env: child_env, clear_env: true)
        yield self
      end
    ensure
      stop
    end

    def stop
      @program_file&.close
      File.unlink @program_file rescue nil
    end
  end
end
