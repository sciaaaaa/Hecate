# Hecate 完整 aEnc 离线实验（AES-CTR v2）

## 本次实现的范围

主文件 aenc.py 保留原 aEnc 的三分量隐藏密文、两次配对、共享秘密和密钥派生、AES-GCM 普通消息加密、CapsEnc、签名及密文编码。CapsEnc 改为 AES-128-CTR，em 补齐16字节、K随机16字节，密文32字节；非法签名标量及 r2=0 直接终止，不悄悄重试或取模。CTR计数器由ctx带域标识哈希派生、最低位清零；每次生成新alpha，进而派生新上下文和密钥。CTR不自带认证，代码测试不替代完整协议安全证明。

这次专门生成独立的离线实验 Setup/联盟/接收者/批次身份，默认 B=4096，新 profile 为 hecate-aenc-aesctr-offline-v2。它不是已经上链的 dr01、node6 或旧 SHAKE256 profile。完整发送端计算使用公开输入；准备阶段用临时秘密执行独立授权恢复检查，之后不保存这些秘密。生成的实验密文不能直接拿去旧部署解密或上链，正式接入需要统一新 profile 和真实身份；可以复用同一份im文件清单重新加密。当前单例授权恢复用于验证代数正确性，不代表授权策略服务。

无需 Geth、RPC、以太坊账户或原 init-v1/batch-v1 目录。随包的两个 hecate_bench 模块来自现有核心算法，使用独立名称。上传 aenc.py、hecate_bench_core.py、hecate_bench_batch.py 到同一个 aenc-v1 目录。原 aenc_test_em.py 可保留。若已有 aenc.py，替换前自行保留旧版本。

## 1. 安装与准备

```bash
cd /home/Hecate_2/hecate-app/aenc-v1
/home/Hecate_2/.venv-chain/bin/python -m pip install -r requirements.txt
/home/Hecate_2/.venv-chain/bin/python aenc.py prepare --B 4096 --out fixtures/aesctr-B4096-v2
```

prepare只运行一次，生成public.json和srs.bin，并执行独立恢复检查。准备时间不计入加密实验。输出目录已存在时不会覆盖；准备失败留下不完整目录，应使用新的输出目录并在后续命令用--bundle指定。所有路径相对于当前工作目录。

## 2. 受控实验

默认固定rd为64KiB合成字节；固定em=urgent；im长度为128、512、1024、4096、16384、65536、262144、1048576、4194304字节。每个长度预热3次，正式30次，正式执行顺序交错。种子只固定测试数据和执行顺序，密码学随机数始终由secrets生成。

```bash
/home/Hecate_2/.venv-chain/bin/python aenc.py bench-controlled --out results/im-controlled-v2
```

可先跑小规模预实验：

```bash
/home/Hecate_2/.venv-chain/bin/python aenc.py bench-controlled --sizes 128 1024 --repeats 2 --warmups 1 --out results/im-pilot-v2
```

若需要固定真实rd，在两类实验命令中都加 --rd-file /绝对路径/已在Pre中的原始文件。发送者不查Pre，成员关系由实验准备方保证；默认合成rd不声称属于既有Pre。rd在实验开始读入内存一次，哈希仍在每次aEnc内部执行。im也不需要登记在Pre。

## 3. 下载真实数据并冻结1000文件清单

```bash
/home/Hecate_2/.venv-chain/bin/python aenc.py dataset --download --archives 010 011 --count 1000 --seed 2026 --out datasets/govdocs-im-1000-v1
```

官方来源：https://digitalcorpora.org/corpora/file-corpora/files/
ZIP地址：https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/010.zip 和同路径011.zip。

程序检查ZIP CRC，从编号文档中固定抽取1000个，原始内容不截断、不转码，以0001.bin等名称保存，同时保存来源、字节数、SHA256、固定顺序。后续不再重新抽样。SHA256用于本地复现，并非官方签名验证。官方删除过部分文档；若候选文件不足1000可增加--archives 010 011 012。1000指文件数，不保证1000种不同内容；manifest中另报不同内容数。

网络下载失败时，在浏览器下载官方010.zip和011.zip并上传至aenc-v1/downloads/，然后去掉--download再运行。只完整的ZIP使用.zip后缀；下载中断的.part文件不会被当作完整ZIP。程序只按字节读取文件，不打开或执行文档内容。官方指出语料中可能含恶意文件。

也可以在服务器用curl下载（成功后再导入）：

```bash
mkdir -p downloads
curl -fL --connect-timeout 20 --max-time 3600 --retry 3 -o downloads/010.zip https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/010.zip
curl -fL --connect-timeout 20 --max-time 3600 --retry 3 -o downloads/011.zip https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/011.zip
/home/Hecate_2/.venv-chain/bin/python aenc.py dataset --archives 010 011 --out datasets/govdocs-im-1000-v1
```

## 4. 1000文件完整加密实验

```bash
/home/Hecate_2/.venv-chain/bin/python aenc.py bench-real --dataset datasets/govdocs-im-1000-v1 --count 1000 --step 100 --repeats 1 --warmups 3 --out results/govdocs-1000-v2
```

正式阶段恰好1000次，每个文件一次；另有3次不入统计的预热。100、200……1000是同一轮的累计检查点，不是10次从头运行。默认不保存全部密文到磁盘，但实际生成和序列化了全部密文；每条保存密文SHA256。如需落盘，加--save-ciphertexts，写盘不计入compute或serialize，包含在elapsed中。

多轮论文实验可设置--repeats 3。每轮重新加密1000次、累计值重置，repeat列区分轮次。不要把不同轮拼成一轮。输出不覆盖；重跑使用新的--out目录。中断留下的raw/cumulative是部分数据，只有存在COMPLETE.json才表示完成。

## 5. 文件和指标

- raw.csv：逐次正式加密结果；不包含预热。
- cumulative.csv：真实实验每100文件检查点；受控实验此文件只有表头。
- summary.csv：按精确im字节数分组的统计；受控实验主要看此文件，真实1000文件主要看cumulative。
- run.json：参数、硬件平台、依赖版本、代码SHA256、rd来源、Setup标识。
- input_manifest.json：真实实验使用的清单副本。

raw指标：compute_wall_ms为随机数生成、rd哈希、群/配对运算、密钥派生、两种对称加密、签名及算法内部必要编码的总墙钟时间；compute_cpu_ms为相同范围CPU时间。serialize_wall_ms包括输出字典、二进制及JSON序列化。aenc_wall_ms=compute_wall_ms+serialize_wall_ms。input_validation_wall_ms为每条都执行的公开材料校验，不计入前述两者。rd首次读取时间和公开材料首次加载时间在run.json；im文件读取时间在raw。

通讯指标：tx_serialized_bytes是完整二进制输出长度（包含profile）；tx_raw_field_bytes是裸字段合计；tx_json_bytes是格式化JSON大小。主要使用二进制输出指标。签名中嵌入胶囊，因此不再额外加32字节；ctx可由共享公开材料和已传字段重建，CTR IV可由ctx派生，不重复加入。数据不含HTTP/TCP、ABI、gas。接收者已获得Setup/批次/公钥等共享公开材料是前提；这些一次性通信不计入逐条密文。

cumulative指标：compute_ms_total为累计compute_wall_ms；compute_cpu_ms_total为CPU累计；serialize_ms_total为序列化累计；aenc_ms_total为二者之和；payload_bytes_total为累计tx_serialized_bytes；plaintext_bytes_total为累计明文；validation_ms_total和input_read_ms_total单列；elapsed_ms包含验证、读盘、完整性哈希、结果写盘等真实循环耗时，但不含此前准备与预热。因此不要把elapsed_ms称为纯加密时间。

1000文件大小不同，累计通信曲线反映文件数量和文件大小两个因素，应同时报告plaintext_bytes_total。尚未提供云服务器实测数值，需在那里运行后获取。单次端到端恢复只在准备阶段执行，正式跑分不包含接收端解密、授权或Pre查询。
