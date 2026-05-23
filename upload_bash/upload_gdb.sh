#!/bin/bash

# 1. 定义 ClientMain 工具所在的 bin 目录绝对路径
BIN_DIR="$HOME/edrstore/EDRStore/bin"
CLIENT_MAIN_EXE="${BIN_DIR}/ClientMain"

# 2. 定义文件所在的绝对路径目录（末尾加斜杠）
BASE_DIR="/data/shared_datasets/tar/gdb/"

# 3. 需要上传的文件列表
FILES=(
    "gdb-8.1.tar"  "gdb-8.3.tar"  "gdb-9.1.tar"  "gdb-9.2.tar"  "gdb-10.1.tar"
    "gdb-10.2.tar" "gdb-11.1.tar" "gdb-11.2.tar" "gdb-13.1.tar" "gdb-13.2.tar"
    "gdb-14.1.tar" "gdb-14.2.tar" "gdb-15.1.tar" "gdb-15.2.tar" "gdb-16.1.tar"
    "gdb-16.3.tar" "gdb-17.1.tar"
)

# 4. 检查上传工具是否存在
if [ ! -f "$CLIENT_MAIN_EXE" ]; then
    echo "错误: 未找到上传工具，请检查路径是否正确: $CLIENT_MAIN_EXE"
    exit 1
fi

# 5. 循环遍历并执行上传命令
echo "开始批量上传 gdb 文件..."
for FILE in "${FILES[@]}"; do
    FULL_PATH="${BASE_DIR}${FILE}"
    
    # 检查待上传文件是否存在
    if [ -f "$FULL_PATH" ]; then
        echo "正在上传: ${FILE}..."
        
        # 【核心修复】利用 ( ) 放入子 Shell 中执行
        # 先 cd 到工具目录，这样 ClientMain 就能在同级目录下找到 config.json 了
        (
            cd "$BIN_DIR" || exit 1
            ./ClientMain -t u -i "$FULL_PATH" -m 2
        )
        
    else
        echo "警告: 文件不存在 -> $FULL_PATH，跳过此文件。"
    fi
    
    echo "----------------------------------------"
done

echo "所有文件处理完毕！"