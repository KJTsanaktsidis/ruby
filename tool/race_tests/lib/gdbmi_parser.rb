# frozen_string_literal: true

require 'strscan'
require_relative 'gdbmi_parser.tab'

module RaceTests
  class GDBMIParser
    KvPair = Struct.new(:key, :value)
    OutputRecord = Struct.new(:numtoken, :record_type, :record_class, :value)
    StreamRecord = Struct.new(:record_type, :value)

    def parse(str)
      @scanner = StringScanner.new(str)
      @lexer_state = NORMAL_LEXER_REGEXPS
      do_parse
    end

    NORMAL_LEXER_REGEXPS = [
      ['\n',              -> { [:NEWLINE, @scanner.matched] }],
      ['"',               -> do
        @lexer_state = CSTRING_LEXER_REGEXPS
        [:QUOTE, @scanner.matched]
      end],
      ['^',               -> { [:CARET, @scanner.matched] }],
      ['*',               -> { [:ASTERISK, @scanner.matched] }],
      ['+',               -> { [:PLUS, @scanner.matched] }],
      ['=',               -> { [:EQUALS, @scanner.matched] }],
      ['~',               -> { [:TILDE, @scanner.matched] }],
      ['@',               -> { [:AT, @scanner.matched] }],
      ['&',               -> { [:AMPERSAND, @scanner.matched] }],
      ['{',               -> { [:OPEN_CURLY, @scanner.matched] }],
      ['}',               -> { [:CLOSE_CURLY, @scanner.matched] }],
      ['[',               -> { [:OPEN_SQUARE, @scanner.matched] }],
      [']',               -> { [:CLOSE_SQUARE, @scanner.matched] }],
      [',',               -> { [:COMMA, @scanner.matched] }],
      [/\s+/,             -> { nil }],
      [/[0-9]+/,          -> { [:NUMTOKEN, @scanner.matched] }],
      [/[A-Za-z0-9\-_]+/, -> { [:WORD, @scanner.matched] }],
    ].freeze

    CSTRING_LEXER_REGEXPS = [
      # Octal escape
      [/\\([0-7]{1,3})/,        -> do
        [:STRING_CONTENT, [@scanner.captures[0].to_i(8)].pack("C")]
      end],
      # Hex escape
      [/\\x([0-9A-Fa-f]{2})/,   -> do
        [:STRING_CONTENT, [@scanner.captures[0].to_i(16)].pack("C")]
      end],
      # Unicode code point
      [/\\u([0-9A-Fa-f]{4})/,   -> do
        [:STRING_CONTENT, @scanner.captures[0].to_i(16).chr(Encoding::UTF_8)]
      end],
      # Bigger Unicode code point
      [/\\U([0-9A-Fa-f]{8})/,   -> do
        [:STRING_CONTENT, @scanner.captures[0].to_i(16).chr(Encoding::UTF_8)]
      end],
      ['\\a',     -> { [:STRING_CONTENT, "\x07"] }],
      ['\\b',     -> { [:STRING_CONTENT, "\x08"] }],
      ['\\f',     -> { [:STRING_CONTENT, "\x0c"] }],
      ['\\n',     -> { [:STRING_CONTENT, "\x0a"] }],
      ['\\r',     -> { [:STRING_CONTENT, "\x0d"] }],
      ['\\t',     -> { [:STRING_CONTENT, "\x09"] }],
      ['\\t',     -> { [:STRING_CONTENT, "\x09"] }],
      ['\\v',     -> { [:STRING_CONTENT, "\x0b"] }],
      ['\\\\',    -> { [:STRING_CONTENT, "\x5c"] }],
      ["\\'",     -> { [:STRING_CONTENT, "\x27"] }],
      ['\\"',     -> { [:STRING_CONTENT, "\x22"] }],
      ['\\?',     -> { [:STRING_CONTENT, "\x3f"] }],
      ['"',       -> do
        @lexer_state = NORMAL_LEXER_REGEXPS
        [:QUOTE, @scanner.matched]
      end],
      [/[^\\"]+/, -> { [:STRING_CONTENT, @scanner.matched] }],
    ].freeze


    def next_token
      loop do
        return [false, false] if @scanner.empty?

        matching_rule = @lexer_state.find { |m| @scanner.scan(m[0]) }
        raise "don't know how to lex #{@scanner.peek 5}" if matching_rule.nil?
        token = instance_exec &matching_rule[1]
        return token unless token.nil?
      end
    end
  end
end
