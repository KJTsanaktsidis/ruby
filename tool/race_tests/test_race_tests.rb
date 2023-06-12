# frozen_string_literal: true

require 'test/unit'
require '-test-/race_tests'

class TestRaceTests < Test::Unit::TestCase
  def test_atest
    omit 'needs cooking'
    program = <<~RUBY
    r, w = IO.pipe
      begin
        th = Thread.new do
          RaceTests.marker(:reading_from_new_thread)
          r.read
      rescue IOError
        :closed
      end
      RaceTests.marker(:closing_from_main_thread)
      r.close
      puts th.value.inspect
    RUBY

    stdout, stderr, status = run_race_test(program) do |t|
      # Take the main thread to the :closing_from_main_thread point
      t.threads[0].run_until do |ev|
        ev.marker == :closing_from_main_thread
      end
      # Take the new thread to the :reading_from_new_thread point
      t.threads[1].run_until do |ev|
        ev.marker == :reading_from_new_thread
      end
      # Take the reading thread right up to the point where it calls poll(2)
      t.threads[1].run_until do |ev|
        ev.usdt_probe == :nogvl__wait__for__pre__poll
      end
      # Continue the closing thread until it's ready to start waiting for the mutex,
      # which should be _after_ it's tried to interrupt the reading thread
      t.threads[0].run_until do |ev|
        ev.usdt_probe == :rb__notify__fd__close__wait__start
      end
      # Run to completion. It should not deadlock.
      t.multi(*t.threads).run_until |ev|
      t.threads.all?(&:terminated?)
    end
    assert status.success?
    assert_equal ":closed", stdout.chomp
  end

  def test_infra
    program = <<~RUBY
      $stdout.puts "stdout"
      $stderr.puts "stderr"
      sleep 10
    RUBY

    RaceTests::Execution.new(program).run do |e|
      pp e.gdb.get_target_env
    end
    # puts "STDOUT READ -> #{e.stdout.gets}"
    # puts "STDERR READ -> #{e.stderr.gets}"
    # e.debugger
    # e.stop
  end
end
