--获取远程IP地址
remoteIp=getRemoteIp()
--修改响应头
ngx.header['Server']=wafName

--IP白名单检测
if checkWhiteIp() then

elseif checkBlackIp() then

elseif ccDeny() then

elseif scanCheck() then
	ngx.exit(444)
elseif whiteUriCheck() then
	
else
	ngx.exit(403)
end