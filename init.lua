--导入配置文件
require 'config'

--导入工具函数
require 'tools'

--设置变量
whiteIpButton	=	optionIsOn(whiteIpButton)
blackIpButton	=	optionIsOn(blackIpButton)
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