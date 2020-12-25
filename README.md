# mywaf
一个简单的waf，完成unixhot的waf中post请求体检查部分

# 安装
### 安装openresty
```shell
#安装基础编译环境
yum groupinstall "Development Tools" -y
#安装依赖包
yum install pcre-devel openssl-devel zlib-devel
#下载openresty压缩包
wget https://openresty.org/download/openresty-1.17.8.2.tar.gz
#解压缩
tar zxf openresty-1.17.8.2
cd openresty-1.17.8.2
#编译
./configure --prefix=/opt/openresty --with-http_iconv_module --with-http_ssl_module --with-http_v2_module
gmake&&gmake install
#添加环境变量
vim /etc/profile
export PATH=$PATH:/opt/openresty/bin
export PATH=$PATH:/opt/openresty/nginx/sbin
export PATH=$PATH:/opt/openresty/luajit/bin
#从文件中加载变量和函数到执行环境
source /etc/profile
```

### 下载安装mywaf
```shell
cd /opt/openresty/nginx/conf
git clone https://github.com/medasz/mywaf.git
#根据nginx-conf目录中的nginx.conf配置文件修改openresty中的nginx配置文件
#备份原始配置
mv /opt/openresty/mywaf/nginx/conf/nginx.conf /opt/openresty/mywaf/nginx/conf/nginx.conf.bak
#复制配置文件
cp /opt/openresty/mywaf/nginx-conf/nginx.conf /opt/openresty/mywaf/nginx/conf/nginx.conf 
#按自己情况修改开放端口，和配置反向代理
```
### 检测配置文件和启动nginx
```shell
nginx -t
#返回如下提示，表示配置正确
#nginx: the configuration file /opt/openresty/nginx/conf/nginx.conf syntax is ok
#nginx: configuration file /opt/openresty/nginx/conf/nginx.conf test is successful

#开启nginx
nginx
#更新配置文件和lua文件需要重新加载nginx
nginx -s reload
#停止nginx
nginx -s quit
```

# 检查mywaf是否启动成功
```shell
检测是否安装成功：
响应头中带有server:mywaf，表示waf配置成功。
```

# 配置文件讲解
```
black_cookie.rule 		#cookie黑名单，可用正则
black_file_ext.rule 	#文件后缀黑名单，可用正则
black_get_args.rule 	#get查询参数黑名单，可用正则
black_ip.rule 			#ip地址黑名单，可用正则
black_post.rule 		#post参数黑名单，可用正则
black_uri.rule 			#uri黑名单，可用正则
black_user_agent.rule 	#user_agent黑名单，可用正则
white_ip.rule 			#ip地址白名单，可用正则
white_uri.rule 			#uri白名单，可用正则,
```

# 历史版本说明
1. 第一个版本
对[ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)进行一些小的修改
2. 第二个版本
上传了ngx_lua_waf的流程模块
3. 第三个版本
修改一些函数实现，上传了规则
4. 第四个版本
修改整体设计，主要是根据[unixhot的waf](https://github.com/unixhot/waf.git)
5. 第五个版本
根据[x-waf](https://github.com/xsec-lab/x-waf)进行修改
6. 第六个版本
修改了mywaf的规则类型，为了匹配[mywaf-admin](https://github.com/medasz/mywaf-admin)
7. 第七个版本
定时从数据库中获取配置信息

# 参考资料
1. [nginx配置文件指令](https://nginx.org/en/docs/)
2. [nginx_lua_module函数中文讲解](https://github.com/iresty/nginx-lua-module-zh-wiki)
3. [lua，oprensty和nginx基础](https://moonbingbing.gitbooks.io/openresty-best-practices/content/)

# TODO
1. <del>规则存储到数据库</del>
2. <del>waf管理界面</del>
3. 结果展示
4. <del>unixhot的waf中没有请求体检查</del>
5. IP地址规则能使用范围ip
6. 从数据库中获取规则

# About
1. 第一，二，三个版本是基于loveshell的ngx_lua_waf修改的
2. 第四个版本是基于unixhot的waf修改的
3. 第五个版本是基于xsec-lab的x-waf和x-waf-admin修改的