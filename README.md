# 🔐 Hecate — Experiments & Reproduction

![Python](https://img.shields.io/badge/Python-3.10-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20AWS%20EC2-E95420?logo=ubuntu&logoColor=white)
![Cryptography](https://img.shields.io/badge/Pairing-BLS12--381-6750A4)
![Blockchain](https://img.shields.io/badge/Ethereum-Private%20Clique%20PoA-3C3C3D?logo=ethereum&logoColor=white)
![Implementation](https://img.shields.io/badge/Implementation-Research%20Prototype-287D60)

Hecate is a blockchain-assisted anamorphic encryption scheme for **retrospective covert recovery under deferred batch authorization**. Senders prepare submissions without prior secret coordination with receivers. The alliance subsequently authorizes a set of submissions, while receiver-bound recovery prevents a recipient from recovering covert records intended for others.

This repository documents the Hecate experiments associated with the manuscript above. The experimental workflow covers local cryptographic costs, communication overhead, blockchain gas consumption, concurrent uploading and retrieval, detection of hidden-information presence.

**📖 [Experiment guide](docs/README.md) · ⚙️ [Experiment profiles](configs/experiments.json) · 🖧 [Connection template](configs/hosts.example.json)**

> **Reproduction scope.** Hecate uses versioned experiment packages rather than a single universal launcher. The commands below retain their original application-directory layout. Distributed runs require an initialized private chain, registered keys, and the supporting services.

---

## 📋 1. System requirements

| Component | Reference study configuration |
|---|---|
| Operating system | Ubuntu on AWS EC2 |
| Python | Python 3.10 |
| Blockchain client | Geth v1.13.15 |
| Consensus | Private Ethereum network using Clique PoA |
| Chain host | Three validator processes; 2 vCPUs and 8 GiB RAM |
| Sender host — node4 | 8 Intel Xeon Platinum vCPUs and 64 GiB RAM |
| Receiver host — node5 | 2 Intel Xeon Platinum vCPUs and 8 GiB RAM |
| Alliance host — node6 | 2 Intel Xeon Platinum vCPUs and 8 GiB RAM |
| Connectivity | Private VPC; application hosts in distinct availability zones within one region |
| Application interfaces | HTTP JSON-RPC for blockchain access; SSH for capability delivery and record queries |
| Private repository | SQLite, maintained off-chain by the alliance |

**Cryptographic components.** The implementation uses `py-ecc` for BLS12-381 group operations and pairings, `cryptography` for symmetric cryptography, `coincurve` for secp256k1 operations, and `Web3.py` for contract interaction. Compressed G1 and G2 elements occupy 48 and 96 bytes, respectively; GT encodings occupy 576 bytes, and scalars occupy 32 bytes.

### 1.1 Prepare the Python environment

The following commands assume Python 3.10 and its virtual-environment support are installed and the reference directory is writable:

```bash
python3.10 -m venv /home/Hecate_2/.venv-chain
source /home/Hecate_2/.venv-chain/bin/activate
python --version
```

Install dependencies from the selected packages. For the initialization package:

```bash
python -m pip install -r requirements.txt
python test_hecate_init.py
```

This installs the initialization dependencies, not necessarily every distributed or machine-learning dependency. Use the versions recorded with the reference runs and the Solidity compiler settings specified by each contract package. Preserve separate machine-learning environments where required by the detection scripts.

### 1.2 Configure the experiment hosts

Use [configs/hosts.example.json](configs/hosts.example.json) to identify the connection fields and fill them into each driver's local configuration. All four experiment profiles are documented in **one file**, [configs/experiments.json](configs/experiments.json).

The manifest is an experiment index: existing `pilot.py` drivers still read their native `pilot.json`, while the detection study uses `plan.json`. It does not introduce a new configuration loader. See [configuration instructions](configs/README.md) for the mapping.

## 🗂️ 2. Dataset and experiment preparation

Hecate evaluates controlled byte-string inputs and selected real files. Ordinary messages, hidden messages, and private records are distinct inputs; their lengths should not be conflated.

| Evaluation | Input settings |
|---|---|
| Setup capacity | B = 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096 |
| AKeyGen — record count | Vary the record count up to 4,096, with 4 KiB records |
| AKeyGen — record size | 256 B–16 MiB per record, with 32 records |
| aEnc — message size | 128 B–16 MiB regular messages, with 64 KiB private records |
| Real-file evaluation | Selected 1,000-file collection; preserve the exact selection manifest |
| Scalability | 32 KiB ordinary messages; 10–100 senders |
| 576-byte workload | 576-byte ordinary inputs; 10/5/5 configuration |
| Hidden-information detection | 1 KiB ordinary messages; 2,000 labeled samples |

In manuscript notation, `msg` is the regular message, `amsg` is a private record recovered through the covert path, and `em` is the embedded short message (`urgent`, 6 bytes). Legacy scripts may call the regular-message input `im` and private records `rd`.

In the scalability experiments, the receiver count and the number of authorized submissions each equal half the sender count. Each receiver is assigned two submissions, of which one is authorized. The selected distributed profiles use B=4096 and the hidden-message setting `urgent`; private-record sizes remain independent of the ordinary-message size.

Preserve dataset filenames, relative paths, selection rules, and hashes when preparing inputs. Use the selected package's dataset arguments to point to the uploaded dataset; no universal dataset path is assumed by this README. For real-file reproduction, retain the acquisition source, redistribution terms, and preprocessing steps alongside the file manifest.

## 🚀 3. End-to-end reproduction workflow

```text
Input records + experimental configuration
                  │
                  ▼
Setup + receiver/alliance keys + public registration
                  │
                  ▼
BatchGen → public batch information
                  │
                  ▼
Sequential aEnc → concurrent ciphertext uploads
                  │
                  ▼
Digest → authorization registration → ComputeKey
                  │
                  ▼
Concurrent capability delivery to designated receivers
                  │
                  ▼
Sequential verification/decryption → concurrent RD queries
                  │
                  ▼
Correctness checks → raw metrics → summaries
```

### Step 1 — Initialize and validate the deployment

Establish the private chain, verify block progression, and initialize fresh experimental keys and public parameters. The source packages separate local initialization (`init-v1`), public-parameter publication (`ppk-v1`), system registration (`register-v1`), and receiver registration. Prepare the alliance repository and sender account pool before starting a distributed run.

Use the original package instructions for these operations. Historical contract addresses and private keys are not portable to a new chain. Save deployment receipts separately from publication and registration receipts.

### Step 2 — Select a distributed profile

| Profile | Legacy application directory | Scale |
|---|---|---|
| `concurrency-10-5-5` | `aws-concurrent-v1` | 10 senders / 5 receivers / 5 authorized submissions |
| `concurrency-100-50-50` | `aws-concurrent-v11` | 100 senders / 50 receivers / 50 authorized submissions |
| 576-byte workload (`comparison-576B` configuration key) | `hecate-im576-n10-v1` | 10/5/5 with 576-byte ordinary messages |
| `presence-detection` | `presence-study2000` | 2,000 samples for detection evaluation |

The following commands illustrate the **100/50/50 workflow on an initialized deployment**. On every application host, configure the selected package and run:

```bash
PY=/home/Hecate_2/.venv-chain/bin/python
export HECATE_RPC_HOST='REPLACE_WITH_CHAIN_PRIVATE_HOST'
"$PY" -u pilot.py doctor
```

Replace the RPC placeholder before execution. All host checks must pass before proceeding. Re-establish these shell variables in each new terminal.

### Step 3 — Prepare receivers, batch information, and ciphertexts

Execute each command on the indicated host, in this order:

```bash
# node5 — receiver preparation
"$PY" -u pilot.py receivers

# node6 — batch generation and publication
"$PY" -u pilot.py batch

# node4 — sequential encryption and saved ciphertext preparation
"$PY" -u pilot.py prepare
```

Wait for successful completion of each phase. Preparation produces saved ciphertexts; it is distinct from the subsequent concurrent upload stage.

### Step 4 — Fund test accounts and upload ciphertexts

```bash
# node6 — fund the private-chain sender accounts as required
"$PY" -u pilot.py fund --amount-eth 0.1

# node4 — concurrent ciphertext uploading
"$PY" -u pilot.py upload
```

The funding amount is the package example, not a guaranteed sufficient balance. Follow its balance and recovery checks before repeating funding. Funding is excluded from protocol-operation gas. A ciphertext upload may contain multiple transactions; count the completed ciphertext as one upload task.

### Step 5 — Authorize submissions and recover data

```bash
# node6 — authorization registration and capability generation/delivery
"$PY" -u pilot.py authorize

# node5 — verification, decryption, and private-record queries
"$PY" -u pilot.py receive-all
```

The reference driver performs sequential encryption and decryption, with concurrent uploads, capability delivery, and record queries. The concurrency parameter therefore does not mean every cryptographic phase runs in parallel.

### Step 6 — Collect and validate the results

```bash
# node6 — collect reports and run the package audit
"$PY" -u pilot.py collect
"$PY" audit.py
```

Check completion status, expected task counts, correctness outcomes, and audit reports. Export reviewed metrics and public receipts for analysis. A process ID or an empty process list alone does not establish successful completion. The 576-byte driver uses the same phase names in `hecate-im576-n10-v1`. 


## 📊 4. Local algorithm evaluation

Local measurements separate cryptographic computation from blockchain execution. For example, the initialization package provides a small Setup pre-run:

```bash
PY=/home/Hecate_2/.venv-chain/bin/python

"$PY" hecate_init.py bench-setup \
  --values 8 16 --repeats 2 --warmups 1 \
  --receiver-params config/receiver_params.json \
  --out results/setup-pilot
```

The receiver-parameter file must already exist and match the initialized receiver profile. Use a new output directory if the example has already been run. For the ten-point capacity sweep:

```bash
"$PY" run_experiments.py setup \
  --receiver-params config/receiver_params.json \
  --repeats 10 --warmups 1 \
  --out results/setup-r10
```

These commands measure local initialization and do not send blockchain transactions. The AKeyGen and aEnc packages provide their own record-count, record-size, and real-file experiments. Preserve their input manifests and distinguish core computation, serialization, and file persistence according to the timers used by each package.

## 📈 5. Scalability and network evaluation

The scalability series increases the number of senders from 10 to 100, with receivers and authorized submissions each equal to half that number. Ordinary-message length is fixed at **32 KiB**.

| Sender count | Driver version |
|---|---|
| 10 | `aws-concurrent-v1` |
| 20, 30, 40 | `aws-concurrent-v3`, `v4`, `v5` |
| 50, 60, 70 | `aws-concurrent-v6`, `v7`, `v8` |
| 80, 90, 100 | `aws-concurrent-v9`, `v10`, `v11` |

Report upload, capability-delivery, and RD-query latency and throughput separately. 

## 🔎 6. Hidden-information detection

The detection study asks whether public on-chain observations distinguish regular submissions from submissions carrying hidden information. It evaluates logistic regression, random forest, and XGBoost using three nested feature sets:

| Feature set | Public observations |
|---|---|
| C1 — Gas | Transaction-level and operation-level gas statistics |
| C2 — Gas + Structure | C1 plus transaction counts, calldata/event-log statistics, and ciphertext lengths |
| C3 — All Public Statistics | C2 plus selected byte lengths, zero-byte counts, and byte entropy |

The dataset contains **1,000 regular and 1,000 anamorphic samples**, partitioned into 1,000 training, 400 validation, and 600 test samples. Paired samples remain within the same batch-level split. Model selection uses validation AUC with a fixed classification threshold of 0.5.

Follow `presence-study2000` and its package README for the historical workflow. Its initialization reuses the first two batches; it is not a stand-alone generator for a fresh 2,000-sample experiment. Exact reanalysis requires the feature table, labels, split membership, and model settings. Labels are training/evaluation metadata and are not classifier features.

## 📐 7. Evaluation metrics

| Metric | Definition |
|---|---|
| Core computation | Local algorithm wall time or CPU time, explicitly identified |
| Core + serialization | Sum of disjoint computation and serialization intervals |
| Native communication | Encoded protocol-object bytes, before JSON or ABI overhead |
| Application communication | Serialized files/envelopes, reported separately |
| Calldata | ABI-encoded transaction-input bytes |
| Gas | Actual receipt `gasUsed`, aggregated over the specified transaction set |
| Task latency | Completion time minus start time within the driver's timing boundary; mean and P95 |
| Throughput | Successful tasks divided by stage makespan, in tasks/s |
| Success rate | Successful tasks divided by attempted tasks under the stated policy |

Upload latency includes RPC handling and required confirmation waits; capability delivery and RD queries include SSH and remote processing. These measurements are **application task latencies**, not isolated network delay. Success rate is not packet-loss rate.

Keep per-task means, task-time sums, and stage makespans distinct. Do not count SRS bytes twice when they are already included in a public bundle. Separate deployment gas from protocol-operation gas, and retain missing measurements as missing rather than zero.

## 📁 8. Source and documentation map

The repository-level documentation uses the following layout:

```text
README.md                      # Repository overview and reproduction entry points
.gitignore                     # Local environments, credentials, and runtime exclusions
configs/
├── experiments.json           # All four reference profiles in one file
├── hosts.example.json         # Connection placeholders
docs/
└── README.md                  # Single experiment guide and evaluation protocol
```

The uploaded experiment directories are organized as follows. Directory names are case-sensitive on Linux.

```text
1_Setup_AKeyGen/
2_Setup_blockchain/
3_R_AKeyGen_blockchain/
4_BatchGen_blockchain/
5_aEnc_im/
6_Digest_ComputeKey/
7_aDec/
8_concurrent_10/
9_concurrent_20/
10_concurrent_30/
11_concurrent_40/
12_concurrent_50/
13_concurrent_60/
14_concurrent_70/
15_concurrent_80/
16_concurrent_90/
17_concurrent_100/
18_presence_2000/
19_im576_10/
receiver_registry.py
```

| Uploaded directory | Purpose | Legacy runtime reference |
|---|---|---|
| `1_Setup_AKeyGen` | Setup and AKeyGen; capacity and private-record experiments | `init-v1` |
| `2_Setup_blockchain` | Public-parameter publication | `ppk-v1` |
| `3_R_AKeyGen_blockchain` | Key-registration components | `Check the included registration scripts` |
| `4_BatchGen_blockchain` | Batch generation and publication | `batch-v1` |
| `5_aEnc_im` | Regular-message encryption experiments | `aenc-v1 / encryption benchmark dependencies` |
| `6_Digest_ComputeKey` | Authorization, digest and capability operations | `authorization-v2` |
| `7_aDec` | Receiver-side decryption and recovery | `adec-v1` |
| `8_concurrent_10` | 10 senders / 5 receivers / 5 authorized submissions | `aws-concurrent-v1` |
| `9_concurrent_20` | 20 senders / 10 receivers / 10 authorized submissions | `aws-concurrent-v3` |
| `10_concurrent_30` | 30 senders / 15 receivers / 15 authorized submissions | `aws-concurrent-v4` |
| `11_concurrent_40` | 40 senders / 20 receivers / 20 authorized submissions | `aws-concurrent-v5` |
| `12_concurrent_50` | 50 senders / 25 receivers / 25 authorized submissions | `aws-concurrent-v6` |
| `13_concurrent_60` | 60 senders / 30 receivers / 30 authorized submissions | `aws-concurrent-v7` |
| `14_concurrent_70` | 70 senders / 35 receivers / 35 authorized submissions | `aws-concurrent-v8` |
| `15_concurrent_80` | 80 senders / 40 receivers / 40 authorized submissions | `aws-concurrent-v9` |
| `16_concurrent_90` | 90 senders / 45 receivers / 45 authorized submissions | `aws-concurrent-v10` |
| `17_concurrent_100` | 100 senders / 50 receivers / 50 authorized submissions | `aws-concurrent-v11` |
| `18_presence_2000` | Hidden-information detection study | `presence-study2000` |
| `19_im576_10` | Hecate-only 576-byte workload, 10/5/5 | `hecate-im576-n10-v1` |

The screenshot displays `receiver_registry` with its extension hidden; use the actual filename when invoking it. The table identifies package families, not a verified import mapping for every uploaded file.

**Repository names versus runtime paths.** The numbered directories organize the public artifact. Existing drivers may still import sibling packages or launch scripts under their legacy names. The commands above use those legacy runtime paths intentionally. Restore the expected application layout when deploying, or update and validate every affected import, subprocess path, shell wrapper, and configuration before running from the numbered directories. Renaming a folder alone does not adapt the driver.

Include required helpers such as `hecate_keys.py`, sender-account utilities, and the chain-upload implementation referenced by the chosen driver. 

## 🧾 9. Results and reproducibility

Retain the run identifier, source revision, dependency versions, hardware configuration, input manifest, and aggregation procedure with every result set. Link each paper figure or table to its raw measurements and numerical plotting data. Independent reruns should use fresh output directories and preserve the reference results.

Initialization may be reused across several runs; report its cost separately and record that reuse. Repeat measurements under fixed conditions when estimating variability. Timings depend on the hardware, software environment, chain state, and network/service load and need not exactly match a previous run.

---

**📖 Continue with the [Experiment Guide and Evaluation Protocol](docs/README.md).**
