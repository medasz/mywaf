--获取远程IP地址
remoteIp=getRemoteIp()
--修改响应头
ngx.header['Server']=wafName

--IP白名单检测
if checkWhiteIp() then

elseif checkBlackIp() then
	
elseif ccDeny() then

else
	return
end