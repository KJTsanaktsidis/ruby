def f1
  1.times { f2 }
end

def f2
  f3
rescue
  1.times { puts "rescue" }
end

def f3
  f4
  puts "wont see me"
end

def f4
  sleep 1 
  raise "abnormal exit"
end

4.times do
  f1
end
