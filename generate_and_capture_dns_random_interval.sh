#!/bin/bash

# --- 配置 ---
CAPTURE_DURATION_MINUTES=30       # 捕获持续时间（分钟）
# OUTPUT_FILE="dns_capture_random_$(date +%Y%m%d_%H%M%S).pcapng" # 输出 pcapng 文件名
OUTPUT_FILE="/tmp/dns_capture_random_$(date +%Y%m%d_%H%M%S).pcapng"
MIN_QUERY_INTERVAL_SECONDS=20     # 最小查询间隔（秒）
MAX_QUERY_INTERVAL_SECONDS=40     # 最大查询间隔（秒）
INTERFACE=""                      # 网络接口 (留空则尝试自动检测)

# 要查询的域名列表 (可以根据需要添加更多)
DOMAINS_TO_QUERY=(
    "iot.jiangnan.edu.cn"
    "yz.jiangnan.edu.cn"
    "gs.xjtu.edu.cn"
    "grawww.nju.edu.cn"
    "www.google.com"
    "github.com"
    "www.bing.com"
    "wikipedia.org"
    "www.cloudflare.com"
    "www.baidu.com"
    "www.bilibili.com"
    "www.zhihu.com"
    "pan.baidu.com"
    "cn.aliyun.com"
    "www.apple.com.cn"
    "www.microsoft.com"
    "m.douban.com"
    "www.huya.com"
    "www.sina.com.cn"
    "www.sohu.com"
    "www.youtube.com"
    "www.facebook.com"
    "www.twitter.com"
    "www.instagram.com"
    "www.linkedin.com"
    "www.taobao.com"
    "www.jd.com"
    "www.qq.com"
    "www.weibo.com"
    "www.tmall.com"
    "www.alipay.com"
    "www.netflix.com"
    "www.wikipedia.org"
    "www.live.com"
    "www.vk.com"
    "www.twitch.tv"
    "www.discord.com"
    "www.reddit.com"
    "www.stackoverflow.com"
    "www.openai.com"
    "www.adobe.com"
    "www.spotify.com"
    "www.samsung.com"
    "www.huawei.com"
    "www.intel.com"
    "www.ibm.com"
    "www.mi.com"
    "www.163.com"
    "www.ifeng.com"
    "www.xinhuanet.com"
    "www.people.com.cn"
    "www.cctv.com"
    "www.chinadaily.com.cn"
    "www.eastday.com"
    "www.gmw.cn"
    "www.chinanews.com"
    "www.ce.cn"
    "www.hexun.com"
    "www.pinduoduo.com"
    "www.meituan.com"
    "www.dianping.com"
    "www.ctrip.com"
    "www.qunar.com"
    "www.lvmama.com"
    "www.anjuke.com"
    "www.lianjia.com"
    "www.58.com"
    "www.51job.com"
    "www.dingtalk.com"
    "www.runoob.com"
)

# --- 检查依赖 ---
if ! command -v tshark &> /dev/null; then
    echo "错误：未找到 tshark 命令。请先安装 tshark (通常在 wireshark-cli 或 tshark 包中)。"
    exit 1
fi

if ! command -v dig &> /dev/null && ! command -v nslookup &> /dev/null; then
    echo "错误：未找到 dig 或 nslookup 命令。请先安装 DNS 查询工具 (通常在 dnsutils 或 bind-utils 包中)。"
    exit 1
fi

# --- 检查权限 ---
if [ "$EUID" -ne 0 ]; then
  echo "警告：此脚本需要 root 权限才能捕获网络流量。请尝试使用 'sudo ./generate_and_capture_dns_random_interval.sh' 运行。"
  # 在某些配置下可能不需要 root，但通常需要，继续尝试但也发出警告
fi

# --- 确定网络接口 ---
if [ -z "$INTERFACE" ]; then
    echo "正在尝试自动检测默认网络接口..."
    # 尝试使用 ip route 获取默认路由的接口
    INTERFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n 1)
    if [ -z "$INTERFACE" ]; then
        echo "错误：无法自动检测到默认网络接口。请在脚本中手动设置 INTERFACE 变量。"
        # 列出可用接口供用户参考
        echo "可用接口："
        ip -br link show | awk '{print $1}' | grep -v '^lo$'
        exit 1
    else
        echo "检测到接口: $INTERFACE"
    fi
fi

# --- 计算总秒数 ---
CAPTURE_DURATION_SECONDS=$((CAPTURE_DURATION_MINUTES * 60))

# --- 启动 Tshark 抓包 ---
echo "将在接口 '$INTERFACE' 上启动 Tshark 抓包，持续 $CAPTURE_DURATION_MINUTES 分钟..."
echo "抓包过滤器: 'port 53'"
echo "输出文件: $OUTPUT_FILE"

# -i: 指定接口
# -f: 指定捕获过滤器 (BPF 语法)
# -w: 指定输出文件
# -a duration: 指定自动停止的秒数
# & : 在后台运行
tshark -i "$INTERFACE" -f "port 53" -w "$OUTPUT_FILE" -a duration:"$CAPTURE_DURATION_SECONDS" &
TSHARK_PID=$!

# 检查 tshark 是否成功启动 (简单检查 PID)
if [ -z "$TSHARK_PID" ] || ! ps -p $TSHARK_PID > /dev/null; then
    echo "错误：Tshark 似乎未能成功启动。"
    exit 1
fi
echo "Tshark 进程已启动 (PID: $TSHARK_PID)。"

# 给 tshark 一点时间来初始化
sleep 2

# --- 启动 DNS 查询生成器 ---
echo "开始生成 DNS 查询，持续约 $CAPTURE_DURATION_MINUTES 分钟，查询间隔为 $MIN_QUERY_INTERVAL_SECONDS-$MAX_QUERY_INTERVAL_SECONDS 秒随机..."

generate_dns_queries() {
    local end_time=$((SECONDS + CAPTURE_DURATION_SECONDS))
    local domain_count=${#DOMAINS_TO_QUERY[@]}
    local query_cmd=""

    # 计算随机范围
    local interval_range=$((MAX_QUERY_INTERVAL_SECONDS - MIN_QUERY_INTERVAL_SECONDS + 1))

    # 优先使用 dig
    if command -v dig &> /dev/null; then
        query_cmd="dig"
    else
        query_cmd="nslookup"
    fi
    echo "使用 '$query_cmd' 生成查询。"

    while [ $SECONDS -lt $end_time ]; do
        # 随机选择一个域名
        local random_index=$((RANDOM % domain_count))
        local domain=${DOMAINS_TO_QUERY[$random_index]}

        echo "[$(date +%H:%M:%S)] 正在查询: $domain"
        # 执行查询，并将输出重定向到 /dev/null 以保持终端清洁
        if [ "$query_cmd" == "dig" ]; then
            dig @8.8.8.8 +time=1 +tries=1 "$domain" > /dev/null 2>&1
             # 或者使用系统默认解析器： dig "$domain" > /dev/null 2>&1
        else
            nslookup "$domain" > /dev/null 2>&1
        fi

        # 生成随机等待时间 (秒)
        local random_interval=$((MIN_QUERY_INTERVAL_SECONDS + RANDOM % interval_range))
        echo "[$(date +%H:%M:%S)] 下次查询将在 $random_interval 秒后..."

        # 检查时间是否已到 (避免 sleep 过长时间)
        if [ $SECONDS -ge $end_time ]; then
            break
        fi
        sleep "$random_interval"
    done
    echo "DNS 查询生成已停止。"
}

# 在后台运行查询生成器函数
generate_dns_queries &
GENERATOR_PID=$!
echo "DNS 查询生成器已启动 (PID: $GENERATOR_PID)。"

# --- 等待 Tshark 结束 ---
echo "等待 Tshark 完成抓包 (最多 $CAPTURE_DURATION_MINUTES 分钟)..."
# 使用 wait 命令等待指定的后台进程结束
wait $TSHARK_PID

# Tshark 结束后，可能生成器还在运行最后一次sleep，主动停止它 (可选)
if ps -p $GENERATOR_PID > /dev/null; then
   echo "正在停止 DNS 查询生成器 (PID: $GENERATOR_PID)..."
   kill $GENERATOR_PID > /dev/null 2>&1
fi

echo "脚本执行完毕。"
echo "抓包文件已保存为: $OUTPUT_FILE"

exit 0