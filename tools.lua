function getRemoteIp()
	-- body
	local remoteIp=ngx.var.remote_addr
	if not remoteIp then
		remoteIp="unknow"
	end
	return remoteIp
end

function optionIsOn(option)
	return option == "on"
end