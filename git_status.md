目前代码状态是：
加密路径仍是 EDRStore 原来的两层加密：AES-CTR -> AES-ECB。
如果编译时开了 EDRSTORE_PLAIN_MODE，会绕过加密。
当前密文 m0 下，客户端 CipherSimilarThd 对密文重新提 CDFE 特征。
服务端收到 UNIQUE_CHUNK 后，也对密文数据重新提 CDFE 特征。
不是之前那个“把明文 CDFE 特征上传给服务端”的版本。

可以写进实验记录的说明
当前版本是在“CDFE 明文对齐 Muti”的基础上，继续做密文 m0 下的候选筛选实验：
将 CDFE jaccard_proxy 阈值从 0.15 提高到 0.25。
服务端只接受 delta size 小于原块 20% 的 similar chunk。
目的是减少 CDFE 在密文上产生的低质量 similar candidate，降低无效 delta 对 storage 的影响。
上传脚本 upload_gdb.sh 当前固定使用 m0 模式。