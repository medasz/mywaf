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

### 下载mywaf
```shell
cd /opt/openresty/
git clone https://github.com/medasz/mywaf.git

```

# 检查
```shell
检测是否安装成功：
响应头中带有server:mywaf，表示waf配置成功。
```

# 配置文件讲解

# 历史版本说明
1. 第一个版本
对[ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)进行一些小的修改
2. 第二个版本
上传了ngx_lua_waf的流程模块
3. 第三个版本
修改一些函数实现，上传了规则
4. 第四个版本
修改整体设计，主要是根据[unixhot的waf](https://github.com/unixhot/waf.git)

# 参考资料
1. [nginx配置文件指令](https://nginx.org/en/docs/)
2. [nginx_lua_module函数中文讲解](https://github.com/iresty/nginx-lua-module-zh-wiki)
3. [lua，oprensty和nginx基础](https://moonbingbing.gitbooks.io/openresty-best-practices/content/)

# TODO
1. 规则存储到数据库
2. waf管理界面
3. 结果展示
4. unixhot的waf中没有请求体检查

# About
1. 第一，二，三个版本是基于loveshell的ngx_lua_waf修改的
2. 第四个版本是基于unixhot的waf修改的
3. 第五个版本是基于xsec-lab的x-waf和x-waf-admin修改的