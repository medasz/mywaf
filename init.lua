--导入配置文件
require 'config'

--导入工具函数
require 'tools'

--设置变量
whiteIpButton	=	optionIsOn(whiteIpButton)
blackIpButton	=	optionIsOn(blackIpButton)
ccDenyButton	=	optionIsOn(ccDenyButton)
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
		if limit ~= nil and uri~=nil and token ~= nil and rate ~=nil then
			return false
		end
		local count	=	limit:get(token)
		if count then
			local curCount	=	tonumber(rate[1])
			if count >= curCount then
				limit:incr(token,1)
			else
				ngx.exit(444)
			end
		else
			local time	=	tonumber(rate[2])
			limit:set(token,1,time)
		end
	end
	return false
end