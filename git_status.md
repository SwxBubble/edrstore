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


对于非相似块
A. 未压缩加密块 + raw cipher features
   类型：FULL_EDR_CACHE_CHUNK
   用途：放进云端 cache，作为以后 local delta 的 base
B. 压缩明文块 -> 加密
   类型：COMPRESSED_NORMAL_CHUNK
   用途：精确去重、全局相似检测和最终存储
1. 未压缩加密块
云端：
计算它的 SHA-256。
接收客户端上传的 raw cipher features。
标记为 CACHE_INSERT_CHUNK。
放入云端 local cache。
它不会直接进入全局相似检测，也不会作为正常块写入 container。
2. 压缩加密块
云端：
计算压缩加密块的 SHA-256。
与未压缩加密块指纹组合成 dual_fp。
使用 dual_fp 做精确去重。
如果重复，停止处理。
如果唯一，云端对压缩加密块本身重新计算特征。
然后压缩加密块绕过 local cache 检测，直接进入全局检测。

对于相似块
他会上传压缩和未压缩加密块 他会先用未压缩块去做相似检测 如果增量小于<30% 则丢弃其压缩加密块 存储增量  如果增量大于30% 则将其放入local cache作为base  对其加密压缩块提取特征 做全局相似性检测 这里不做增量大小的阈值 按找cdfe相似性检测逻辑来 也就是特征命中数大于阈值就在做增量压缩 如果该加密压缩块没有找到相似块 则存储该加密压缩块 将其特征放入索引 也就是后面的逻辑与非相似块全局处理逻辑一样