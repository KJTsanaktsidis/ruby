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
        @gdb.set_target_env(child_env, replace: true)
        @gdb.file = EnvUtil.rubybin
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
