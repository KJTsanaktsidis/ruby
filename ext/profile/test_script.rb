#!/usr/bin/env ruby

require 'profile'

Profile.start

puts "CPU time"
$x = 6
50000.times { $x *= 9 }
puts "Sleep time"
sleep 4
puts "Done"
Profile.stop

