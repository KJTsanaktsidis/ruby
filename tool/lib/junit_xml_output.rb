module JUnitXMLOutput
  class Writer
    TestSuite = Struct.new(:name, :test_cases, keyword_init: true)
    TestCase = Struct.new(
      :name, :path, :lineno, :time, :error, keyword_init: true
    )
    XML_REPLACEMENTS = {
      '<' => '&lt;',
      '>' => '&gt;',
      '"' => '&quot;',
      "'" => '&apos;',
      "\r" => '&#13;',
      "\n" => '&#10;',
      '&' => '&amp;',
    }.freeze
    XML_REPLACEMENTS_REGEX = Regexp.union(XML_REPLACEMENTS.keys).freeze
    CONTROL_CHAR_REGEX = /(?=[[:cntrl:]])(?=[^\n\t])/

    def xml_escape(str)
      str.to_s.gsub(CONTROL_CHAR_REGEX, '').gsub(XML_REPLACEMENTS_REGEX, XML_REPLACEMENTS)
    end

    def open_xml_element(element, attrs = {})
      [
        "<",
        element,
        (attrs && attrs.any?) ? " " : "",
        attrs.map { |k, v| "#{k}=\"#{xml_escape(v)}\"" }.join(' '),
        ">",
      ].compact.join
    end

    def close_xml_element(element)
      ["</", element, ">"].join
    end

    def initialize
      @testsuites = Hash.new do |h, k|
        h[k] = TestSuite.new(name: k, test_cases: [])
      end
    end

    def record(suite_name, test_name, path, lineno, time, error)
      @testsuites[suite_name].test_cases << TestCase.new(
        name: test_name, path:, lineno:, time:, error:,
      )
    end

    def write_to_file(path)
      File.open(path, 'w') do |f|
        f << '<?xml version="1.0" encoding="UTF-8"?>'
        f << open_xml_element('testsuites')
        @testsuites.values.each do |suite|
          f << open_xml_element('testsuite', { 'name' => suite.name })
          suite.test_cases.each do |tc|
            emit_testcase(f, tc)
          end
          f << close_xml_element('testsuite')
        end
        f << close_xml_element('testsuites')
      end
    end

    private

    def emit_testcase(f, tc)
      f << open_xml_element('testcase', {
        'name' => tc.name,
        'time' => tc.time.to_s,
        'file' => tc.path,
        'lineno' => tc.lineno.to_s,
      })
      case tc.error
      when nil
      when Test::Unit::PendedError
        f << open_xml_element('skipped', { 'message' => tc.error.message })
        f << close_xml_element('skipped')
      when Test::Unit::AssertionFailedError, Timeout::Error
        f << open_xml_element('failure', {
          'type' => tc.error.class.name,
          'message' => tc.error.message,
        })
        f << xml_escape(tc.error.backtrace.join("\n"))
        f << close_xml_element('failure')
      else
        f << open_xml_element('error', {
          'type' => tc.error.class.name,
          'message' => tc.error.message,
        })
        f << xml_escape(tc.error.backtrace.join("\n"))
        f << close_xml_element('error')
      end
      f << close_xml_element('testcase')
    end
  end

  private def setup_options(opts, options)
    super
    opts.on_tail '--junit-filename=PATH', String, 'JUnit XML format output' do |path|
      @junit_xml_reporter = JUnitXMLOutput::Writer.new
      @junit_xml_report_path = path
      main_pid = Process.pid
      at_exit do
        # This block is executed when the fork block in a test is completed.
        # Therefore, we need to verify whether all tests have been completed.
        stack = caller
        if stack.size == 0 && main_pid == Process.pid && $!.is_a?(SystemExit)
          @junit_xml_reporter.write_to_file path
        end
      end
    end
  end

  def record(suite, method, assertions, time, error, source_location = nil)
    return super unless @junit_xml_reporter

    loc = source_location || suite.instance_method(method).source_location || []
    path, lineno = loc
    repo_path = File.expand_path("#{__dir__}/../../")
    relative_path = path.delete_prefix("#{repo_path}/")
    test_name = "#{suite.name}##{method}"
    @junit_xml_reporter.record(suite.name, test_name, relative_path, lineno, time, error)

    super
  end
end
