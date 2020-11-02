--waf防火墙名称
wafName			=	"mywaf"

--规则库目录
--注意：必须使用绝对路径，否则会找不到规则文件，导致文件打开失败
rulesPath		=	"/opt/openresty/mywaf/rules"

--IP白名单列表和开关
whiteIpList		=	{"127.0.0.1"}
whiteIpButton	=	"on"

--IP黑名单列表和开关
blackIpList		=	{}
blackIpButton	=	"on"

--CC防御频率和开关
ccDenyRate		=	"100/60"
ccDenyButton	=	"on"

--扫描器特征检测开关
scanCheckButton	=	"on"
--scanCheckTrace	=	

--uri白名单检测开关
whiteUriButton	=	"on"

