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
function getParamCheck()

end