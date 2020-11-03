--导入配置文件
require 'config'

--导入工具函数
require 'tools'

--设置变量
whiteIpButton	=	optionIsOn(whiteIpButton)
blackIpButton	=	optionIsOn(blackIpButton)
ccDenyButton	=	optionIsOn(ccDenyButton)
scanCheckButton	=	optionIsOn(scanCheckButton)
whiteUriButton	=	optionIsOn(whiteUriButton)
whiteUriRules	=	readRule("whiteUri")
blackUserAgentButton=optionIsOn(blackUserAgentButton)
blackUserAgentRules=readRule("blackUserAgent")
logButton		=	optionIsOn(logButton)
redirect		=	optionIsOn(redirect)
blackUriButton	=	optionIsOn(blackUriButton)
blackUriRules	=	readRule("blackUri")
getParamaButton	=	optionIsOn(getParamaButton)
getParamaRules	=	readRule("blackGetParama")
blackCookieButton=	optionIsOn(blackCookieButton)
blackCookieRules=	readRule("blackCookie")
blackPostButton	=	optionIsOn(blackPostButton)
blackPostRules	=	optionIsOn("blackPost")

--IP白名单检测
function checkWhiteIp()
	if whiteIpButton then
		for _,v in ipairs(whiteIpList) do
			if v==remoteIp then
				return true
			end
		end
	end
	return false
end

--IP黑名单检测
function checkBlackIp()
	if blackIpButton then
		for _,v in ipairs(blackIpList) do
			if v==remoteIp then
				ngx.exit(403)
			end
		end
	end
	return false
end

--防御CC攻击
function ccDeny()
	if ccDenyButton then
		local limit	=	ngx.shared.limit
		local uri	=	ngx.var.request_uri
		local token	=	remoteIp..uri
		local rate	=	ngx.re.match(ccDenyRate,"(.*)/(.*)")
		if limit == nil or uri == nil or token == nil or rate == nil then
			return false
		end
		local count	=	limit:get(token)
		if count then
			local totalCount	=	tonumber(rate[1])
			if count < totalCount then
				limit:incr(token,1)
			else
				ngx.exit(503)
			end
		else
			local time	=	tonumber(rate[2])
			limit:set(token,1,time)
		end
	end
	return false
end

--扫描器特征检测
function scanCheck()
	if scanCheckButton then
		if ngx.var.http_acunetix_aspect and ngx.var.http_x_scan_memo then 
			ngx.exit(444)
		end
	end
	return false
end

--uri白名单检测
function whiteUriCheck()
	if whiteUriButton then
		local uri = ngx.var.uri
		if uri and uri ~= "" then
			for _,rule in ipairs(whiteUriRules) do
				if ngx.re.match(uri,rule,"isjo") then
					return true
				end
			end
		end
	end
	return false
end

--user-agent黑名单检测
function blackUserAgentCheck()
	if blackUserAgentButton then
		local userAgent = ngx.var.http_user_agent
		if userAgent and userAgent ~= "" then
			for _,rule in ipairs(blackUserAgentRules) do
				if ngx.re.match(userAgent,rule,"isjo") then
					log(ngx.req.get_method(),ngx.var.request_uri,userAgent,rule)
					sayHtml()
					return true
				end
			end
		end
	end
	return false
end

--uri黑名单检测
function blackUriCheck()
	if blackUriButton then
		local requestUri = ngx.var.request_uri
		if requestUri and requestUri ~= "" then
			for _,rule in ipairs(blackUriRules) do
				if ngx.re.match(requestUri,rule,"isjo") then
					log(ngx.req.get_method(),requestUri,requestUri,rule)
					sayHtml()
				end
			end
		end
	end
	return false
end

--get请求参数检测
function getParamaCheck()
	if getParamaButton then
		local parama = ngx.req.get_uri_args()
		for k,v in pairs(parama) do
			local data = nil
			if type(v) == "table" then
				local t = {}
				for _,val in ipairs(v) do
					if type(val) == "boolean" then
						
					else
						table.insert(t,val)
					end
				end
				data = table.concat(t," ")
			elseif type(v)=="boolean" then

			else
				data = v
			end
			
			for _,rule in ipairs(getParamaRules) do
				if data and data ~= "" and rule ~= "" and ngx.re.match(ngx.unescape_uri(data),rule,"isjo") then
					log(ngx.req.get_method(),ngx.var.request_uri,data,rule)
					sayHtml()
				end
			end
		end
	end
	return false
end

--cookie黑名单检测
function blackCookieCheck()
	if blackCookieButton then
		local cookie = ngx.var.http_cookie
		if cookie then
			for _,rule in ipairs(blackCookieRules) do
				if rule ~= "" and ngx.re.match(cookie,rule,"isjo") then
					log(ngx.req.get_method(),ngx.var.request_uri,cookie,rule)
					sayHtml()
				end
			end
		end
	end
	return false
end

--post请求黑名单检测
function blackPostCheck()
	if blackPostButton then
		local method = ngx.req.get_method()
		if method == "POST" then
			local boundary = getBoundary()
			if boundary then
				--获取一个包含下游连接的对象
				local sock = ngx.req.socket()
				if not sock then
					return false
				end
				--创建一个当前请求的新请求体，并初始化缓存区,128KB
				ngx.req.init_body(128*1024)
				--获取当前请求体的长度
				local  length = tonumber(ngx.req.get_headers()['Content-Length'])
				--设置文件读取步长4KB
				local 	size  =	4096
				if size > length then
					size = length
				end
				--设置长度计算器
				local curSize = 0
				while curSize < length do
					local data,err,flag = sock:receive(size)
					data = data or flag
					if not data then
						return false
					end
					--向新请求体中追加数据
					ngx.req.append_body(data)
					--检查文件内容
					checkPostRule(data)
					--获取文件后缀名
					local m = ngx.re.match(data,[[;\s*filename=\"([^\"]+)\.([^\"]+)\"]],"isjo")
					if not m then
						return false
					end
					--检测文件后缀
					blackFileExtCheck(m[2])
					--增加长度计算器
					curSize = curSize + #data
					local less = length - curSize
					if less < size then
						size = less
					end
				end
				--结束新请求体构造
				ngx.req.finish_body()
				--关闭socket对象
				sock:close()
			else
				ngx.req.read_body()
				local args = ngx.req.get_post_args()
				if args then
					for k,v in pairs(args) do
						local data = nil
						if type(v) == "table" then
							local t = {}
							for _,val in ipairs(v) do
								if type(val) == 'boolean'

								else
									table.insert(t,val)
								end
							end
							data = table.concat(t," ")
						elseif type(v) == "boolean" then

						else
							data = v
						end
						if data and data ~= "" and checkPostRule(data) then
							checkPostRule(k)
						end
					end
				end
			end
		end
	end
	return false
end