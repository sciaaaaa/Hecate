# Experiment Guide and Evaluation Protocol

## A. Inputs and shared settings

Hecate is implemented in Python 3.10 using py-ecc for BLS12-381 operations, cryptography for symmetric cryptography, coincurve for secp256k1 operations, and Web3.py for blockchain interaction. The reference deployment uses four AWS EC2 instances: one hosts three Geth v1.13.15 Clique PoA validators; the others host the data sender (DS, node4), data receiver (DR, node5), and alliance (AL, node6). The DS uses 8 vCPUs and 64 GiB memory; the remaining hosts each use 2 vCPUs and 8 GiB memory. Application hosts communicate across availability zones within the same region through the private VPC, using HTTP JSON-RPC for blockchain access and SSH for capability delivery and private-record retrieval.

The four reference profiles are collected in [configs/experiments.json](../configs/experiments.json). This file documents experiment settings. Apply the selected settings to the corresponding driver and replace host placeholders using [hosts.example.json](../configs/hosts.example.json). Preserve the application-root directory structure and record exact dependency versions, compiler settings, chain configuration, and source revision for each run.

| Experiment | Input and scale |
|---|---|
| Capacity evaluation | B = 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096 |
| Concurrency evaluation | 10–100 senders; receivers and authorized submissions each equal half the sender count; 32 KiB ordinary messages |
| Matched-size comparison | 10 senders, 5 receivers, 5 authorized submissions; 576-byte ordinary inputs |
| Hidden-information detection | 2,000 samples; 1 KiB ordinary messages; 1,000 regular and 1,000 anamorphic samples |

The concurrency and comparison profiles use B=4096 and the hidden-message setting `urgent`. Private-record sizes are independent of ordinary-message sizes. 

## B. From input data to an initialized deployment

Install the dependencies specified by the selected source packages in an isolated environment. Initialize a private chain using the released genesis and validator configuration, verify block progression, and generate fresh experimental keys. Use `init-v1` for Setup and alliance-key experiments, `ppk-v1` for public-parameter publication, and the registration packages for system and receiver registration. Save deployment receipts separately from parameter-publication and registration receipts. Before executing a distributed run, prepare the alliance's private SQLite repository, registered receivers, and funded sender test accounts. 

For real-file experiments, identify the exact input collection using a manifest of relative paths, sizes, and hashes, together with acquisition and preprocessing instructions. Seeds for input selection do not reproduce OS-generated cryptographic randomness. Generate fresh secrets for independent reproductions rather than distributing the original private state.

## C. Formal experiment execution

The following sequence applies to `17_concurrent_100` and `19_im576_10` on an initialized deployment. Earlier driver versions must follow their own package instructions. On each participating application host, select the appropriate directory and configure the local connection settings before running:

```bash
cd /home/Hecate_2/hecate-app/aws-concurrent-v11
PY=/home/Hecate_2/.venv-chain/bin/python
export HECATE_RPC_HOST='REPLACE_WITH_CHAIN_PRIVATE_HOST'
"$PY" -u pilot.py doctor
```

Replace the RPC placeholder with the deployment's private host. For the 576-byte experiment, use the `19_im576_10` directory instead. After all host checks pass, execute the stages in order, waiting for each stage to complete successfully:

| Order | Host | Command | Purpose |
|---|---|---|---|
| 1 | node5 | `"$PY" -u pilot.py receivers` | Prepare receiver information for the run |
| 2 | node6 | `"$PY" -u pilot.py batch` | Generate and publish batch information |
| 3 | node4 | `"$PY" -u pilot.py prepare` | Prepare ciphertexts sequentially |
| 4 | node6 | `"$PY" -u pilot.py fund --amount-eth 0.1` | Fund sender test accounts as needed |
| 5 | node4 | `"$PY" -u pilot.py upload` | Upload ciphertexts concurrently |
| 6 | node6 | `"$PY" -u pilot.py authorize` | Register authorization and generate/deliver capabilities |
| 7 | node5 | `"$PY" -u pilot.py receive-all` | Verify/decrypt and query private records |
| 8 | node6 | `"$PY" -u pilot.py collect` | Collect experiment reports |

The funding amount is the package example, not a guarantee of sufficient balance; inspect balances and recovery rules before repeating a transfer. Funding gas is excluded from protocol-operation gas. The reference workflow uses sequential encryption and decryption, concurrent ciphertext uploads, concurrent capability delivery, and concurrent private-record queries. Thus, increasing concurrency does not imply parallel execution of every cryptographic algorithm.

## D. Evaluation metrics

| Metric | Definition and reporting unit |
|---|---|
| Core computation | Local algorithm time, in ms or s; identify wall time versus CPU time |
| Computation plus serialization | Sum of separately measured, non-overlapping core and serialization intervals |
| Aggregate computation | Sum across the specified tasks; distinguish it from a per-task mean and stage makespan |
| Native communication | Bytes of protocol objects under the stated group/scalar encoding |
| Serialized communication | Application-file or envelope bytes, reported separately from native bytes |
| Calldata | ABI-encoded transaction-input bytes; not equivalent to network traffic |
| Gas | Receipt `gasUsed`, summed over the explicitly identified transactions |
| Task latency | Application task completion time minus start time; report mean and P95 |
| Throughput | Successful task count divided by the recorded stage makespan, in tasks/s |
| Task success rate | Successful tasks divided by attempted tasks under the stated timeout/recovery policy |

BLS12-381 encodings occupy 48 bytes for G1, 96 bytes for G2, 576 bytes for GT, and 32 bytes for scalars. Native bytes, JSON sizes, calldata, and measured transport traffic are different quantities and must not be combined in a single communication column.

Upload latency includes orchestration, RPC handling, and required transaction confirmations. Capability-delivery and record-query latency includes SSH establishment and remote processing within the driver's timing boundary. These are task latencies, not isolated network delays. Throughput counts complete ciphertexts or completed delivery/query tasks, not individual transactions, and is not the reciprocal of mean task latency. Task success rate does not measure packet loss.

Report deployment, Setup publication, receiver registration, batch publication, ciphertext uploading, and authorization gas separately. A joint registration/deployment receipt must not be counted in full under two different phases. Missing values remain missing rather than becoming zero. Separate ordinary decryption, hidden recovery, and external private-record retrieval.

## E. Local algorithm and hidden-information experiments

The local algorithm experiments vary Setup capacity, private-record count or size, and ordinary-message size, and also evaluate selected real files. For private-record controls, vary the number of records with 4 KiB records, or vary record size with 32 records. Keep input generation, serialization policy, repeated-run count, and timing boundaries fixed within each sweep. 

The detection experiment evaluates logistic regression, random forest, and XGBoost over three nested public-feature sets: gas statistics; gas plus transaction structure; and all selected public statistics. Its 2,000 samples are split into 1,000 training, 400 validation, and 600 test samples by batch. Paired ordinary/anamorphic samples remain in the same split. Model selection uses validation AUC, with a fixed decision threshold of 0.5; report all detector combinations rather than selecting by test performance.

The historical `presence-study2000` driver reuses batches 01 and 02 and therefore requires those inputs. It is not a fresh-deployment generator. Exact reanalysis uses the released feature table and split membership; an independent rerun must generate new samples while preserving the documented evaluation protocol. Labels are provided for training and evaluation, not as model input features. Report AUC, accuracy, precision, recall, F1, FPR, and MCC; near-chance detection supports a conclusion only for the tested features, models, and observation setting.

## F. Repeated runs and provenance

Use a distinct run identifier for each independent execution. Record source revisions, environment versions, hardware, chain settings, input manifests, timing units, failures, and recovery attempts. Do not overwrite an active run or merge resumed-attempt timings into first-attempt measurements without disclosure. Repeat measurements under fixed conditions and report variability when repeated runs are available.
