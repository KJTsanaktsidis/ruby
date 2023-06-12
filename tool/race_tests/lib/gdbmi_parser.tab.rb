#
# DO NOT MODIFY!!!!
# This file is automatically generated by Racc 1.6.2
# from Racc grammar file "".
#

require 'racc/parser.rb'
module RaceTests
  class GDBMIParser < Racc::Parser
##### State transition tables begin ###

racc_action_table = [
    38,    38,    39,    39,    38,    11,    39,    18,    19,    21,
    16,    18,    18,    23,    25,    18,    13,    14,    15,     7,
    26,    23,    30,     8,     9,    10,    31,    32,    30,    30,
    31,    45,    46,    47 ]

racc_action_check = [
    32,    39,    32,    39,    47,     1,    47,     6,    11,    12,
     5,    32,    39,    18,    20,    47,     5,     5,     5,     0,
    22,    23,    25,     0,     0,     0,    28,    30,    31,    38,
    40,    41,    42,    43 ]

racc_action_pointer = [
    10,     5,   nil,   nil,   nil,     6,    -9,   nil,   nil,   nil,
   nil,     8,     6,   nil,   nil,   nil,   nil,   nil,    -4,   nil,
    12,   nil,     4,     4,   nil,    19,   nil,   nil,    24,   nil,
    23,    25,    -5,   nil,   nil,   nil,   nil,   nil,    26,    -4,
    28,    25,    24,    31,   nil,   nil,   nil,    -1,   nil ]

racc_action_default = [
   -23,   -35,    -1,    -2,    -3,   -35,   -35,   -24,   -29,   -30,
   -31,   -35,   -35,   -25,   -26,   -27,   -28,    -5,   -33,    49,
    -8,   -22,   -35,   -33,    -4,   -35,   -32,   -34,    -9,   -10,
   -35,   -35,   -35,   -11,   -12,   -13,   -14,   -15,    -6,   -18,
    -7,   -35,   -35,   -19,   -20,   -16,   -17,   -35,   -21 ]

racc_goto_table = [
    34,    28,     1,    22,     2,     3,     4,    44,    27,     5,
    12,    20,    24,     6,    40,    48,    17,    41,    33,    42,
    43 ]

racc_goto_check = [
    14,    12,     1,    19,     2,     3,     4,    14,    19,     5,
     6,     7,     8,     9,    12,    14,    10,    11,    13,    17,
    18 ]

racc_goto_pointer = [
   nil,     2,     4,     5,     6,     9,     5,    -1,    -8,    13,
    10,   -21,   -24,   -13,   -32,   nil,   nil,   -20,   -19,   -15 ]

racc_goto_default = [
   nil,   nil,   nil,   nil,   nil,   nil,   nil,   nil,   nil,   nil,
    35,   nil,   nil,    29,   nil,    36,    37,   nil,   nil,   nil ]

racc_reduce_table = [
  0, 0, :racc_error,
  1, 19, :_reduce_none,
  1, 20, :_reduce_2,
  1, 20, :_reduce_3,
  4, 21, :_reduce_4,
  2, 22, :_reduce_5,
  0, 29, :_reduce_6,
  1, 29, :_reduce_7,
  0, 26, :_reduce_8,
  2, 26, :_reduce_9,
  1, 30, :_reduce_10,
  3, 30, :_reduce_11,
  3, 31, :_reduce_12,
  1, 32, :_reduce_13,
  1, 32, :_reduce_14,
  1, 32, :_reduce_15,
  3, 33, :_reduce_16,
  3, 34, :_reduce_17,
  0, 35, :_reduce_18,
  1, 35, :_reduce_19,
  1, 36, :_reduce_20,
  3, 36, :_reduce_21,
  1, 25, :_reduce_22,
  0, 23, :_reduce_23,
  1, 23, :_reduce_24,
  1, 24, :_reduce_25,
  1, 24, :_reduce_26,
  1, 24, :_reduce_27,
  1, 24, :_reduce_28,
  1, 27, :_reduce_29,
  1, 27, :_reduce_30,
  1, 27, :_reduce_31,
  3, 28, :_reduce_32,
  0, 37, :_reduce_33,
  2, 37, :_reduce_34 ]

racc_reduce_n = 35

racc_shift_n = 49

racc_token_table = {
  false => 0,
  :error => 1,
  :COMMA => 2,
  :WORD => 3,
  :EQUALS => 4,
  :OPEN_CURLY => 5,
  :CLOSE_CURLY => 6,
  :OPEN_SQUARE => 7,
  :CLOSE_SQUARE => 8,
  :NUMTOKEN => 9,
  :CARET => 10,
  :ASTERISK => 11,
  :PLUS => 12,
  :TILDE => 13,
  :AT => 14,
  :AMPERSAND => 15,
  :QUOTE => 16,
  :STRING_CONTENT => 17 }

racc_nt_base = 18

racc_use_result_var = true

Racc_arg = [
  racc_action_table,
  racc_action_check,
  racc_action_default,
  racc_action_pointer,
  racc_goto_table,
  racc_goto_check,
  racc_goto_default,
  racc_goto_pointer,
  racc_nt_base,
  racc_reduce_table,
  racc_token_table,
  racc_shift_n,
  racc_reduce_n,
  racc_use_result_var ]

Racc_token_to_s_table = [
  "$end",
  "error",
  "COMMA",
  "WORD",
  "EQUALS",
  "OPEN_CURLY",
  "CLOSE_CURLY",
  "OPEN_SQUARE",
  "CLOSE_SQUARE",
  "NUMTOKEN",
  "CARET",
  "ASTERISK",
  "PLUS",
  "TILDE",
  "AT",
  "AMPERSAND",
  "QUOTE",
  "STRING_CONTENT",
  "$start",
  "start",
  "record",
  "output_record",
  "stream_record",
  "maybe_numtoken",
  "output_type_chr",
  "record_class",
  "maybe_kv_list_top",
  "stream_type_chr",
  "c_string",
  "maybe_kv_list",
  "kv_list",
  "kv_pair",
  "kv_value",
  "tuple_value",
  "list_value",
  "maybe_list_elts",
  "list_elts",
  "c_string_contents" ]

Racc_debug_parser = false

##### State transition tables end #####

# reduce 0 omitted

# reduce 1 omitted

module_eval(<<'.,.,', 'gdbmi_parser.y', 5)
  def _reduce_2(val, _values, result)
     result = val[0]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 6)
  def _reduce_3(val, _values, result)
     result = val[0]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 9)
  def _reduce_4(val, _values, result)
                            result = OutputRecord.new(val[0], val[1], val[2], val[3])

    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 13)
  def _reduce_5(val, _values, result)
                            result = StreamRecord.new(val[0], val[1])

    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 16)
  def _reduce_6(val, _values, result)
     result = {}
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 17)
  def _reduce_7(val, _values, result)
     result = val[0]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 19)
  def _reduce_8(val, _values, result)
     result = {}
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 20)
  def _reduce_9(val, _values, result)
     result = val[1]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 23)
  def _reduce_10(val, _values, result)
                            result = {val[0].key => val[0].value}

    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 26)
  def _reduce_11(val, _values, result)
                            result = val[0].merge({
                          val[2].key => val[2].value}
                        )

    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 31)
  def _reduce_12(val, _values, result)
     result = KvPair.new(val[0], val[2])
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 33)
  def _reduce_13(val, _values, result)
     result = val[0]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 34)
  def _reduce_14(val, _values, result)
     result = val[0]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 35)
  def _reduce_15(val, _values, result)
     result = val[0]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 37)
  def _reduce_16(val, _values, result)
     result = val[1]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 39)
  def _reduce_17(val, _values, result)
     result = val[1]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 41)
  def _reduce_18(val, _values, result)
     result = []
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 42)
  def _reduce_19(val, _values, result)
     result = val[0]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 44)
  def _reduce_20(val, _values, result)
     result = [val[0]]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 45)
  def _reduce_21(val, _values, result)
     result = val[0] + [val[2]]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 47)
  def _reduce_22(val, _values, result)
     result = val[0]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 49)
  def _reduce_23(val, _values, result)
     result = nil
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 50)
  def _reduce_24(val, _values, result)
     result = val[0].to_i
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 52)
  def _reduce_25(val, _values, result)
     result = :result
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 53)
  def _reduce_26(val, _values, result)
     result = :exec_async
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 54)
  def _reduce_27(val, _values, result)
     result = :status_async
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 55)
  def _reduce_28(val, _values, result)
     result = :notify_async
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 57)
  def _reduce_29(val, _values, result)
     result = :console_stream
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 58)
  def _reduce_30(val, _values, result)
     result = :target_stream
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 59)
  def _reduce_31(val, _values, result)
     result = :log_stream
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 61)
  def _reduce_32(val, _values, result)
     result = val[1]
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 62)
  def _reduce_33(val, _values, result)
     result = ""
    result
  end
.,.,

module_eval(<<'.,.,', 'gdbmi_parser.y', 63)
  def _reduce_34(val, _values, result)
     result = val[0] + val[1]
    result
  end
.,.,

def _reduce_none(val, _values, result)
  val[0]
end

  end   # class GDBMIParser
end   # module RaceTests
