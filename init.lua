--导入配置文件
require 'config'

--导入工具函数
require 'tools'

--设置变量
remoteIp 		= 	getRemoteIp()
whiteIpButton	=	optionIsOn(whiteIpButton)


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