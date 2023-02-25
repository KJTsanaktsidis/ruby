tr = BitmapTree.new (10 * 1024 * 1024)

require 'set'
active = Set.new

loop do
  if rand > 0.3
    slot = tr.take_slot
    if active.include?(slot)
      raise "took #{slot} but already had"
    end
    if slot == -1 && active.size != (10 * 1024 * 1024)
      raise "got -1 but only #{active.size} elements"
    end
    active.add slot
  else
    slot = active.to_a.shuffle.first
    next if slot.nil?
    active.delete slot
    tr.free_slot slot
  end
end
