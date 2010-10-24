require "pcaplua"

p,devname=pcaplua.new_live_capture ()
print ('new_live_capture:', p, devname)
p:set_filter ('port not 22')