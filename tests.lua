require "pcaplua"

p,devname=pcaplua.new_live_capture ()
print ('new_live_capture:', p, devname)
p:set_filter ('port not 22')

local d,t,l = p:next()
print (string.format("%s: %q(%d)\n", os.date('%c',t),d,l))
-- for i= 1, 3 do
-- 	print (p:next())
-- end