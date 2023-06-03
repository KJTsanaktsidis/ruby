# frozen_string_literal: true

exit 0 unless RbConfig::CONFIG['RUBY_RACE_TESTS_ENABLED'] == 'yes'

require_relative "../auto_ext.rb"
auto_ext(inc: true)
