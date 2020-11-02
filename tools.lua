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

--日志记录
--日志格式：
--x.x.x.x [xxxx-xx-xx xx:xx:xx] "method servername/uri" "data" "rule"\n
--文件名格式：
--servername_xxxx-xx-xx_sec.log
function log(method,uri,data,rule)
	if logButton then
		local msg 		= string.format([=[%s [%s] "%s %s/%s" "%s" "%s"]=],remoteIp,ngx.localtime(),method,ngx.var.server_name,uri,data,rule)
		local filename	= ngx.var.server_name.."_"..ngx.today().."_sec.log"
		logWrite(filename,msg)
	end
end

--文件写入
function logWrite(filename,msg)
	local fd = io.open(logPath.."/"..filename,"ab")
	if not fd then
		return 
	end
	fd:write(msg)
	fd:flush()
	fd:close()
end


--返回拦截界面
function sayHtml()

end