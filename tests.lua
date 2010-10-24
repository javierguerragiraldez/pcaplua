require "pcaplua"

p=pcaplua.new_live_capture ('wlan0')
p:set_filter ('port not 22')