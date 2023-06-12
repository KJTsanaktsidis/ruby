class RaceTests::GDBMIParser

rule
  start record

  record              : output_record { result = val[0] }
                      | stream_record { result = val[0] }

  output_record       : maybe_numtoken output_type_chr record_class maybe_kv_list_top {
                        result = OutputRecord.new(val[0], val[1], val[2], val[3])
                      }

  stream_record       : stream_type_chr c_string {
                        result = StreamRecord.new(val[0], val[1])
                      }

  maybe_kv_list       : /* none */ { result = {} }
                      | kv_list { result = val[0] }

  maybe_kv_list_top   : /* none */ { result = {} }
                      | COMMA kv_list { result = val[1] }

  kv_list             : kv_pair {
                        result = {val[0].key => val[0].value}
                      }
                      | kv_list COMMA kv_pair {
                        result = value[0].merge({
                          val[2].key => val[2].value}
                        )
                      }

  kv_pair             : WORD EQUALS kv_value { result = KvPair.new(val[0], val[2]) }

  kv_value            : c_string { result = val[0] }
                      | tuple_value { result = val[0] }
                      | list_value { result = val[0] }

  tuple_value         : OPEN_CURLY maybe_kv_list CLOSE_CURLY { result = val[1] }

  list_value          : OPEN_SQUARE maybe_list_elts CLOSE_SQUARE { result = val[1] }

  maybe_list_elts     : /* none */ { result = [] }
                      | list_elts { result = val[0] }

  list_elts           : kv_value { result = [val[0]] }
                      | list_elts COMMA kv_value { result = val[0] + [val[2]] }

  record_class        : WORD { result = val[0] }

  maybe_numtoken      : /* none */ { result = nil }
                      | NUMTOKEN { result = val[0].to_i }

  output_type_chr     : CARET         { result = :result }
                      | ASTERISK      { result = :exec_async }
                      | PLUS          { result = :status_async }
                      | EQUALS        { result = :notify_async }

  stream_type_chr     : TILDE         { result = :console_stream }
                      | AT            { result = :target_stream }
                      | AMPERSAND     { result = :log_stream }

  c_string            : QUOTE c_string_contents QUOTE { result = val[1] }
  c_string_contents   : /* none */ { result = "" }
                      | STRING_CONTENT c_string_contents { result = val[0] + val[1] }

end
