--获取远程IP地址
function getRemoteIp()
	-- body
	local remoteIp=ngx.var.remote_addr
	if not remoteIp then
		remoteIp="unknow"
	end
	return remoteIp
end

--判断开关状态
function optionIsOn(option)
	return option == "on"
end