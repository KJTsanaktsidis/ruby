# frozen_string_literal: true

require 'rbconfig'
require 'shellwords'
require_relative 'gdbmi_parser'

module RaceTests
  class GdbMi
    def initialize(cmd:, env: ENV, gdb: 'gdb')
      @spawn_env = env
      @spawn_gdb = gdb
      @spawn_cmd = cmd
     end

    def run
      start
      yield self
    ensure
      stop
    end

    def start
      @program_stdin_r, @program_stdin_w = IO.pipe
      @program_stdout_r, @program_stdout_w = IO.pipe
      @program_stderr_r, @program_stderr_w = IO.pipe
      @gdbmi_stdin_r, @gdbmi_stdin_w = IO.pipe
      @gdbmi_stdout_r, @gdbmi_stdout_w = IO.pipe
      redirections = {
        # FDs we use to talk to gdb/mi itself
        0 => @gdbmi_stdin_r,
        1 => @gdbmi_stdout_w,
        2 => $stderr,
        # FDs we will bind to the child process
        3 => @program_stdin_r,
        4 => @program_stdout_w,
        5 => @program_stderr_w,
        :close_others => true,
      }

      if $stdin.tty?
        @tty = File.readlink("/proc/self/fd/#{$stdin.fileno}")
        redirections[6] = @tty
      end

      gdb_cmdline = [@spawn_gdb, '--interpreter=mi4', '--nh', '--nx']
      @gdb_pid = Process.spawn(@spawn_env, *gdb_cmdline, redirections)
      @gdbmi_stdin_r.close
      @gdbmi_stdout_w.close

      # Mirror gdb/mi's state into here.
      @token_counter = 0
      @threads = {}

      mi_read_output_block
    end

    def stop
      if @gdb_pid
        Process.kill :TERM, @gdb_pid
        Process.waitpid2 @gdb_pid
      end

      @program_stdin_r&.close
      @program_stdin_w&.close
      @program_stdout_r&.close
      @program_stdout_w&.close
      @program_stderr_r&.close
      @program_stderr_w&.close
      @gdbmi_stdin_r&.close
      @gdbmi_stdin_w&.close
      @gdbmi_stdout_r&.close
      @gdbmi_stdout_w&.close
    end

    def set(setting, value)
      set_cmd = "set #{setting} #{value.dump}"
      mi_run_command_blocking("-interpreter-exec", params: ["console", set_cmd])
    end

    private

    def mi_run_command_blocking(command, opts: {}, params: [])
      token_val = @token_counter
      @token_counter += 1

      command_str = mi_build_command_string(token_val, command, opts: opts, params: params)
      mi_log_output_line command_str
      @gdbmi_stdin_w.puts command_str
      mi_read_output_block
    end

    def mi_build_command_string(token, command, opts: {}, params: [])
      opts_str = opts.map do |k, v|
        s = "-" + k
        if !v.nil? && v != ""
          s += " " + v.dump
        end
      end.join(' ')
      params_str = params.map { _1.dump }.join(' ')

      [token&.to_s, command, opts_str, "--", params_str].compact.join(' ')
    end

    def mi_read_output_block
      result_record = nil
      loop do
        line = @gdbmi_stdout_r.gets.strip
        mi_log_output_line line

        # End of the output block
        break if line == "(gdb)"

        record = GDBMIParser.new.parse(line)
        mi_update_state record
        result_record = record if record.record_type == :result
      end
      return result_record
    end

    def mi_log_output_line(line)
      $stderr.puts "GDB/MI -> #{line}"
    end

    def mi_log_input_line(line)
      $stderr.puts "GDB/MI <- #{line}"
    end


    def mi_update_state(record)

    end
  end

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

      @gdb = GdbMi.new(cmd: EnvUtil.rubybin, env: child_env, gdb: RbConfig::CONFIG['GDB'])
      @gdb.run { yield self }
    ensure
      stop
    end

    def stop
      @program_file&.close
      File.unlink @program_file rescue nil
    end
  end

   class ExecutionOldDeleteMe
      def initialize(program)
        @program_file = Tempfile.create
        @program_file.write program
        @program_file.rewind
        @program_stdin_r, @program_stdin_w = IO.pipe
        @program_stdout_r, @program_stdout_w = IO.pipe
        @program_stderr_r, @program_stderr_w = IO.pipe
        @gdbmi_stdin_r, @gdbmi_stdin_w = IO.pipe
        @gdbmi_stdout_r, @gdbmi_stdout_w = IO.pipe
        child_env = {}
        %w(RUBYLIB GEM_PATH PATH LIBRUBY_SO RUBY).each do |var|
          child_env[var] = ENV[var] if ENV.key?(var)
        end
        %w(LANG LC_ALL LC_CTYPE).each do |var|
          child_env[var] = 'C'
        end
        gdb_cmdline = [
          RbConfig::CONFIG['GDB'],
          '--interpreter=mi4',
          '--nh', '--nx',
        ]

        redirections = {
          # FDs we use to talk to gdb/mi itself
          0 => @gdbmi_stdin_r,
          1 => @gdbmi_stdout_w,
          2 => $stderr,
          # FDs we will bind to the child process
          3 => @program_stdin_r,
          4 => @program_stdout_w,
          5 => @program_stderr_w,
          :close_others => true,
        }

        if $stdin.tty?
          redirections[6] = File.readlink("/proc/self/fd/#{$stdin.fileno}")
        end
        @gdb_pid = Process.spawn(child_env, *gdb_cmdline, redirections)
        @gdbmi_stdin_r.close
        @gdbmi_stdout_w.close

        puts "READ -> " + @gdbmi_stdout_r.gets
        puts "READ -> " + @gdbmi_stdout_r.gets

        @mi_counter = 0
        mi_read_until_prompt
        mi_exec_command_blocking("-interpreter-exec console \"#{Shellwords.escape('set auto-load off')}\"")
        mi_exec_command_blocking("-interpreter-exec console \"#{Shellwords.escape('set debuginfod enabled off')}\"")
        mi_exec_command_blocking([
          "-file-exec-and-symbols", Shellwords.escape(EnvUtil.rubybin)
        ].join(' '))
        mi_exec_command_blocking([
          "-exec-arguments", Shellwords.escape(@program_file.path),
          "0</proc/self/fd/3", "1>/proc/self/fd/4", "2>/proc/self/fd/5"
        ].join(' '))
        mi_exec_command_blocking("-gdb-set mi-async on")
        mi_exec_command_blocking "-exec-run --start"
        mi_exec_command_blocking("-interpreter-exec console \"#{Shellwords.escape('set scheduler-locking on')}\"")
        mi_exec_command_blocking("-exec-continue")
      end

      def stdin = @program_stdin_w
      def stdout = @program_stdout_r
      def stderr = @program_stderr_r

      def debugger
         mi_exec_command_blocking("-interpreter-exec console  \"new-ui console #{Shellwords.escape(File.readlink("/proc/self/fd/#{$stdin.fileno}"))}\"")
      end

      def stop
        if @gdb_pid
          Process.kill :TERM, @gdb_pid
          Process.waitpid2 @gdb_pid
        end

        @program_stdin_r&.close
        @program_stdin_w&.close
        @program_stdout_r&.close
        @program_stdout_w&.close
        @program_stderr_r&.close
        @program_stderr_w&.close
        @gdbmi_stdin_r&.close
        @gdbmi_stdin_w&.close
        @gdbmi_stdout_r&.close
        @gdbmi_stdout_w&.close

        if @program_file
          @program_file.close
          File.unlink(@program_file)
        end
      end


      private

      def mi_event_loop_once
        line = @gdbmi_stdin_r.gets
      end

      def mi_read_until_prompt
         loop do
           ln = @gdbmi_stdout_r.gets
           mi_log_line_in ln
           break if ln.strip == "(gdb)"
         end
      end

      def mi_exec_command_blocking(cmd)
        cmd_index = @mi_counter
        @mi_counter += 1

        fullcmd = "#{cmd_index}#{cmd}"
        mi_log_line_out fullcmd
        @gdbmi_stdin_w.puts fullcmd
        retln = nil
        loop do
          ln = @gdbmi_stdout_r.gets
          mi_log_line_in ln
          if ln.start_with?("#{cmd_index}^")
            retln = ln
            break
          end
        end
        mi_read_until_prompt
        retln
      end

      def mi_log_line_in(line)
        $stderr.puts "GDB/MI <- #{line}"
      end

      def mi_log_line_out(line)
        $stderr.puts "GDB/MI -> #{line}"
      end
   end
end
