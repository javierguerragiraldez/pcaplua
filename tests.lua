require "pcaplua"

local function hexdump(s)
	local sz = string.len(s)
	for l = 1,sz,16 do
		io.write (string.format ("%04X: ", l-1))
		for l2 = l, math.min(sz,l+15) do
			if (l2-l)==8 then io.write ' ' end
			io.write (string.format ('%02X ', string.byte(s,l2)))
		end
		io.write ('   ')
		for l2 = l, math.min(sz,l+15) do
			if (l2-l)==8 then io.write ' ' end
			local b = string.byte(s,l2)
			if not b or b < 32 or b > 127 then b = string.byte('.') end
			io.write (string.format ('%c', b))
		end
		io.write ('\n')
	end
end

local function hexval(s)
	local fmt = string.rep ('%02X:', string.len(s))
	return string.format (fmt, string.byte(s,1,string.len(s)))
end

p,devname=pcaplua.new_live_capture ()
print ('new_live_capture:', p, devname)

do
	local n,err = p:set_filter('not a filter')
	assert (not n, 'should fail!')
	print ('rightful error:', err)
end

p:set_filter ('port not 22')

local d,t,l = p:next()
print (string.format("%s (%X,%d):\n", os.date('%c',t),l,l))
hexdump (d)
-- for i= 1, 3 do
-- 	print (p:next())
-- end

print ('------ ethernet frame ---------')
local eth = pcaplua.decode_ethernet (d)
print (hexval(eth.src), hexval(eth.dst), eth.type)
hexdump (eth.content)

if eth.type == 8 then
	print ('-------- IP packet --------')
	local ip = pcaplua.decode_ip (eth.content)
	for k,v in pairs(ip) do
		if k ~= 'content' then
			print (k,v)
		end
	end
	hexdump (ip.content)

	local tcp
	if ip.proto == 6 then
		print ('----- TCP packet ------')
		tcp = pcaplua.decode_tcp (ip.content)
		for k,v in pairs(tcp) do
			if k ~= 'content' then
				print (k,v)
			end
		end
		hexdump (tcp.content)
	end

	local udp
	if ip.proto == 17 then
		print ('------- UDP packet --------')
		udp = pcaplua.decode_udp (ip.content)
		print (string.format ('sport:%d, dport:%d, len:%d, chksum:%d',
				udp.source_port, udp.dest_port, udp.length, udp.checksum))
		hexdump (udp.content)
	end
end

local count = 0
p:setcallback (function (d,t,l)
	count = count+1
	print (string.format ('------ ethernet frame #%d ---------', count))
	local eth = pcaplua.decode_ethernet (d)
	print (hexval(eth.src), hexval(eth.dst), eth.type)
	hexdump (eth.content)
	if count > 3 then
		return 'fin'
	end
end)
print (p:loop ())