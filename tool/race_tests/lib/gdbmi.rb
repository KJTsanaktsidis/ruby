# frozen_string_literal: true

require 'rbconfig'
require 'shellwords'
require_relative 'gdbmi_parser'

module RaceTests
  class GdbMi

    MI_COMMANDS_WITH_OPTIONAL_PARAMETERS = %w().freeze
    ENV_ASSIGN_REGEXP = /^([^=]+)=(.*)$/m.freeze

    def initialize(gdb: 'gdb')
      @spawn_gdb = gdb
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
      @gdb_pid = Process.spawn(*gdb_cmdline, redirections)
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

    def debuginfod_enabled=(value)
        mi_run_console_command('set', 'debuginfod', 'enabled', on_or_off(value))
    end

    def auto_load_enabled=(value)
        mi_run_console_command('set', 'auto-load', on_or_off(value))
    end

    def start_inferior(*command, env: {}, clear_env: false)
        file = command[0]
        arguments = command[1..]

        mi_run_command_blocking('-file-exec-and-symbols', params: [file])
        mi_run_command_blocking('-exec-arguments',
            parmas: arguments.map { Shellwords.escape(_1) },
        )

        child_env = {}
        child_env.merge!(ENV) unless clear_env
        child_env.merge!(env)

        wrapper_program = <<~RUBY
            child_env = Marshal.load(#{Marshal.dump(child_env).dump})
            exec child_env, *ARGV, { 0 => 3, 1 => 4, 2 => 5}
        RUBY
        exec_wrapper = [File.readlink('/proc/self/exe'), '-e', wrapper_program]
        mi_run_console_command('set', 'exec-wrapper', Shellwords.join(exec_wrapper))

        mi_run_command_blocking('-exec-run', params: ['--start'])
        mi_run_console_command('set', 'scheduler-locking', 'on')
        mi_run_command_blocking("-exec-continue")
    end

    def file=(value)
        mi_run_command_blocking('-file-exec-and-symbols', params: [value])
    end

    def async=(value)
        mi_run_command_blocking('-gdb-set', params:['mi-async', on_or_off(value)])
    end
    
    private

    def mi_run_command_blocking(command, opts: {}, params: [], &blk)
      token_val = @token_counter
      @token_counter += 1

      command_str = mi_build_command_string(token_val, command, opts: opts, params: params)
      mi_log_input_line command_str
      @gdbmi_stdin_w.puts command_str
      loop do
        record = mi_read_output_block(&blk)
        return record if record && record.numtoken == token_val
      end
    end

    def mi_build_command_string(token, command, opts: {}, params: [])
      opts_str = opts.map do |k, v|
        s = "-" + k.to_s
        if !v.nil? && v != ""
          s += " " + v.dump
        end
        s
      end
      pos_separator = '--' if MI_COMMANDS_WITH_OPTIONAL_PARAMETERS.include?(command)
      params_str = params.map { _1.dump }.join(' ')

      [token&.to_s + command, *opts_str, pos_separator, params_str].compact.join(' ')
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
        yield record if block_given?
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

    def mi_run_console_command(*command, &blk)
      command_string = command.join(' ')
      mi_run_command_blocking('-interpreter-exec', params: ["console", command_string], &blk)
    end


    def mi_update_state(record)

    end

    def on_or_off(bool_val)
        if bool_val
            'on'
        else
            'off'
        end
    end
  end
end
