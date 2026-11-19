import argparse
import json
import time
from pathlib import Path

import requests
import solcx
from eth_account import Account
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

from hecate_keys import (
    load_parameters,
    check_receiver,
    receiver_directory,
    decode_and_validate_g2,
)


ROOT = Path(__file__).resolve().parent
CHAIN = ROOT.parent / "blockchain-geth"
DEPLOYMENT = ROOT / "deployment" / "receiver_registry.json"
ZERO_ADDRESS = "0x" + "00" * 20


def client(port=18545):
    session = requests.Session()
    session.trust_env = False

    w3 = Web3(Web3.HTTPProvider(
        f"http://127.0.0.1:{port}",
        session=session,
        request_kwargs={"timeout": 10}
    ))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    if not w3.is_connected():
        raise RuntimeError(f"无法连接端口 {port}")
    if w3.eth.chain_id != 20261005:
        raise RuntimeError("连接到了错误的链")
    return w3


def account(node):
    paths = list((CHAIN / node / "keystore").glob("UTC--*"))
    if len(paths) != 1:
        raise RuntimeError(f"{node} 的初始 keystore 数量不正确")

    password = (CHAIN / node / "password.txt").read_text().strip()
    keyfile = json.loads(paths[0].read_text())
    result = Account.from_key(Account.decrypt(keyfile, password))

    expected = json.loads((CHAIN / "accounts.json").read_text())[node]
    if result.address.lower() != expected.lower():
        raise RuntimeError(f"{node} 账户地址不一致")
    return result


def send(w3, signer, operation, label):
    base_fee = int(w3.eth.get_block("latest").get("baseFeePerGas", 0))
    gas_price = max(
        int(w3.eth.gas_price),
        2 * base_fee + Web3.to_wei(1, "gwei")
    )

    estimate = operation.estimate_gas({
        "from": signer.address,
        "gasPrice": gas_price
    })

    tx = operation.build_transaction({
        "from": signer.address,
        "chainId": 20261005,
        "nonce": w3.eth.get_transaction_count(signer.address, "pending"),
        "gasPrice": gas_price,
        "gas": int(estimate * 1.2) + 10000
    })

    signed = signer.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    tx_hex = Web3.to_hex(tx_hash)

    records = ROOT / "records"
    records.mkdir(exist_ok=True)
    record_file = records / f"{label}-{tx_hex}.json"
    record = {"operation": label, "tx_hash": tx_hex, "state": "submitted"}
    record_file.write_text(json.dumps(record, indent=2))

    print("已提交交易:", tx_hex, flush=True)
    receipt = w3.eth.wait_for_transaction_receipt(
        tx_hash, timeout=180, poll_latency=1
    )

    if receipt["status"] != 1:
        raise RuntimeError("交易执行失败")

    record.update({
        "state": "included",
        "block_number": receipt["blockNumber"],
        "gas_used": receipt["gasUsed"]
    })
    record_file.write_text(json.dumps(record, indent=2))

    print("入块高度:", receipt["blockNumber"])
    print("gasUsed:", receipt["gasUsed"])
    return receipt


def deploy():
    if DEPLOYMENT.exists():
        raise RuntimeError("已有部署记录，请勿重复部署")

    params = load_parameters()
    parameter_id = bytes.fromhex(params["params_id"][2:])

    source = (ROOT / "contracts" / "ReceiverRegistry.sol").read_text()
    compiled = solcx.compile_source(
        source,
        output_values=["abi", "bin"],
        solc_binary="/home/Hecate_2/hecate-app/tools/solc-0.8.24",
        evm_version="london",
        optimize=True,
        optimize_runs=200
    )
    artifact = compiled["<stdin>:ReceiverRegistry"]

    w3 = client()
    factory = w3.eth.contract(
        abi=artifact["abi"],
        bytecode=artifact["bin"]
    )

    receipt = send(
        w3,
        account("node6"),
        factory.constructor(parameter_id),
        "deploy-registry"
    )

    address = receipt["contractAddress"]
    code = w3.eth.get_code(address)
    if not code:
        raise RuntimeError("部署地址没有合约代码")

    data = {
        "address": address,
        "abi": artifact["abi"],
        "params_id": params["params_id"],
        "chain_id": w3.eth.chain_id,
        "genesis_hash": Web3.to_hex(w3.eth.get_block(0)["hash"]),
        "runtime_code_hash": Web3.to_hex(Web3.keccak(code)),
        "deployment_tx": Web3.to_hex(receipt["transactionHash"]),
        "compiler": "0.8.24",
        "evm_version": "london"
    }

    DEPLOYMENT.parent.mkdir(exist_ok=True)
    with DEPLOYMENT.open("x") as handle:
        json.dump(data, handle, indent=2)

    print("注册合约地址:", address)
    print("部署记录:", DEPLOYMENT)


def load_contract(w3):
    data = json.loads(DEPLOYMENT.read_text())
    params = load_parameters()

    if data["params_id"] != params["params_id"]:
        raise RuntimeError("本地参数与部署参数不一致")
    if data["genesis_hash"] != Web3.to_hex(w3.eth.get_block(0)["hash"]):
        raise RuntimeError("创世区块与部署记录不一致")

    code = w3.eth.get_code(data["address"])
    if not code or Web3.to_hex(Web3.keccak(code)) != data["runtime_code_hash"]:
        raise RuntimeError("合约代码与部署记录不一致")

    contract = w3.eth.contract(address=data["address"], abi=data["abi"])
    expected = bytes.fromhex(params["params_id"][2:])
    if bytes(contract.functions.paramsId().call()) != expected:
        raise RuntimeError("链上参数标识不一致")

    return contract


def public_record(name):
    path = receiver_directory(name) / "public.json"
    data = json.loads(path.read_text())
    if data["receiver_name"] != name:
        raise RuntimeError("接收者名称不一致")
    if data["params_id"] != load_parameters()["params_id"]:
        raise RuntimeError("接收者参数不一致")
    decode_and_validate_g2(bytes.fromhex(data["public_key_hex"]))
    return data


def verify(name):
    data = public_record(name)
    owner = Web3.to_checksum_address(data["owner_eth_address"])
    public_key = bytes.fromhex(data["public_key_hex"])

    # 给其他节点一些同步时间；这里只读，不会重复发交易。
    for port in (18545, 18546, 18547):
        w3 = client(port)
        contract = load_contract(w3)
        rid = contract.functions.receiverId(owner, name).call()
        deadline = time.monotonic() + 30

        while True:
            actual_owner, actual_key = contract.functions.getReceiver(rid).call()
            if actual_owner.lower() != ZERO_ADDRESS:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{port} 未查到 {name} 的注册记录")
            time.sleep(1)

        if actual_owner.lower() != owner.lower():
            raise RuntimeError("链上控制账户不一致")
        if bytes(actual_key) != public_key:
            raise RuntimeError("链上公钥与本地公钥不一致")

        print(f"{port}: {name} 注册记录及96字节公钥核对通过")
        print("receiverId:", Web3.to_hex(rid))


def register(name):
    check_receiver(name)
    data = public_record(name)
    signer = account("node5")

    if signer.address.lower() != data["owner_eth_address"].lower():
        raise RuntimeError("当前签名账户不是接收者记录中的控制账户")

    w3 = client()
    contract = load_contract(w3)
    rid = contract.functions.receiverId(signer.address, name).call()
    current_owner, current_key = contract.functions.getReceiver(rid).call()
    public_key = bytes.fromhex(data["public_key_hex"])

    if current_owner.lower() != ZERO_ADDRESS:
        if (
            current_owner.lower() != signer.address.lower()
            or bytes(current_key) != public_key
        ):
            raise RuntimeError("已有注册记录与本地记录冲突")
        print("已注册且内容一致，不重复发送交易")
    else:
        send(
            w3,
            signer,
            contract.functions.registerReceiver(name, public_key),
            f"register-{name}"
        )

    verify(name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["deploy", "register", "check"])
    parser.add_argument("--name", default="dr01")
    args = parser.parse_args()

    if args.command == "deploy":
        deploy()
    elif args.command == "register":
        register(args.name)
    else:
        verify(args.name)


if __name__ == "__main__":
    main()