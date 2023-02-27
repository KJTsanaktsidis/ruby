btr = BitmapTree.new 63
1024.times { btr.take_slot }
puts 'intr'
puts btr.count_in_range(0, 63)
