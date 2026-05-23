#!/bin/bash

# 1. 定义 ClientMain 工具所在的 bin 目录绝对路径
BIN_DIR="$HOME/edrstore/EDRStore/bin"
CLIENT_MAIN_EXE="${BIN_DIR}/ClientMain"

# 2. 定义文件所在的绝对路径目录（末尾加斜杠）
BASE_DIR="/data/shared_datasets/tar/binutils/"

# 3. 需要上传的文件列表
FILES=(
    "binutils-2.22.tar"   "binutils-2.23.tar"   "binutils-2.23.1.tar" "binutils-2.23.2.tar" "binutils-2.27.tar"
    "binutils-2.28.tar"   "binutils-2.28.1.tar" "binutils-2.29.tar"   "binutils-2.29.1.tar" "binutils-2.30.tar"
    "binutils-2.34.tar"   "binutils-2.35.tar"   "binutils-2.35.1.tar" "binutils-2.35.2.tar" "binutils-2.36.1.tar"
    "binutils-2.38.tar"   "binutils-2.39.tar"   "binutils-2.40.tar"   "binutils-2.41.tar"   "binutils-2.42.tar"
    "binutils-2.43.tar"   "binutils-2.44.tar"   "binutils-2.45.tar"   "binutils-2.45.1.tar" "binutils-2.46.0.tar"
)

# 4. 检查上传工具是否存在
if [ ! -f "$CLIENT_MAIN_EXE" ]; then
    echo "错误: 未找到上传工具，请检查路径是否正确: $CLIENT_MAIN_EXE"
    exit 1
fi

# 5. 循环遍历并执行上传命令
echo "开始批量上传 binutils 文件..."
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