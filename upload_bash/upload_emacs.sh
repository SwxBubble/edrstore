#!/bin/bash

# 1. 定义 ClientMain 工具所在的 bin 目录绝对路径
BIN_DIR="$HOME/edrstore/EDRStore/bin"
CLIENT_MAIN_EXE="${BIN_DIR}/ClientMain"

# 2. 定义文件所在的绝对路径目录（末尾加斜杠）
BASE_DIR="/data/shared_datasets/tar/emacs/"

# 3. 需要上传的文件列表
FILES=(
    "emacs-22.1.tar" "emacs-22.2.tar" "emacs-22.3.tar" "emacs-23.1.tar" "emacs-23.4.tar"
    "emacs-24.1.tar" "emacs-24.3.tar" "emacs-24.5.tar" "emacs-25.1.tar" "emacs-25.3.tar"
    "emacs-26.1.tar" "emacs-26.3.tar" "emacs-27.1.tar" "emacs-27.2.tar" "emacs-28.1.tar"
    "emacs-28.2.tar" "emacs-29.1.tar" "emacs-29.3.tar" "emacs-30.1.tar" "emacs-30.2.tar"
)

# 4. 检查上传工具是否存在
if [ ! -f "$CLIENT_MAIN_EXE" ]; then
    echo "错误: 未找到上传工具，请检查路径是否正确: $CLIENT_MAIN_EXE"
    exit 1
fi

# 5. 循环遍历并执行上传命令
echo "开始批量上传 emacs 文件..."
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