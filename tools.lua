--获取远程IP地址
function getRemoteIp()
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
		local msg 		= string.format([=[%s [%s] "%s %s%s" "%s" "%s"]=].."\n",remoteIp,ngx.localtime(),method,ngx.var.server_name,ngx.unescape_uri(uri),data,rule)
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
	if redirect then
		ngx.header.content_type="text/html"
		ngx.status=ngx.HTTP_FORBIDDEN
		ngx.say(html)
		ngx.exit(ngx.status)
	end
end

--通过content-type判断是否是文件上传
--数据格式
--Content-Type: multipart/form-data; boundary=---------------------------87733188139062126523958042595
function getBoundary()
	local boundary = ngx.req.get_headers()['Content-Type']
	if not boundary then
		return nil
	end

	local m = ngx.re.match(boundary,[[;\s*boundary=([^\",;]+)]],"isjo")
	if m then
		return m
	end

	return ngx.re.match(boundary,[=[;\s*boundary="([^\"]+)"]=],"isjo")
end

--匹配post规则拦截请求
function checkPostRule(data)
	for _,rule in ipairs(blackPostRules) do
		if rule ~= "" and ngx.re.match(ngx.unescape_uri(data),rule,"isjo") then
			log(ngx.req.get_method(),ngx.var.request_uri,data,rule)
			sayHtml()
		end
	end
	return true
end