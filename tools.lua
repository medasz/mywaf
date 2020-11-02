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

--读取规则文件
function readRule(filename)
	local rulesList = {}
	local fd =io.open(rulesPath.."/"..filename,"r")
	if not fd then
		return rulesList
	end
	
	for line in fd:lines() do
		table.insert(rulesList,line)
	end
	fd:close()
	return rulesList
end