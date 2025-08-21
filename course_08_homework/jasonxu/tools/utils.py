import hashlib
import requests

def hash160(data):
    """Calculate the hash160 (RIPEMD160(SHA256(data))) of the input data"""
    sha256 = hashlib.sha256(data).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    return ripemd160.digest()

def broadcast_tx_by_mempoolspace(tx):
    if not tx:
        print("❌ 没有有效的COMMIT交易")
        return False
    
    print("\n广播交易...")
    mempool_api = "https://mempool.space/testnet/api/tx"
    try:
        response = requests.post(mempool_api, data=tx)
        if response.status_code == 200:
            txid = response.text
            print(f"交易成功！")
            print(f"交易ID: {txid}")
            print(f"查看交易: https://mempool.space/testnet/tx/{txid}")
        else:
            print(f"广播失败: {response.text}")
            return False
    except Exception as e:
        print(f"错误: {e}")
        return False
    return True   


def broadcast_tx_by_blockstream(tx):
    if not tx:
        print("❌ 没有有效的COMMIT交易")
        return False
    
    print("\n广播交易...")
    mempool_api = "https://blockstream.info/testnet/api/tx"
    try:
        response = requests.post(mempool_api, data=tx)
        if response.status_code == 200:
            txid = response.text
            print(f"交易成功！")
            print(f"交易ID: {txid}")
            print(f"查看交易: https://mempool.space/testnet/tx/{txid}")
        else:
            print(f"广播失败: {response.text}")
            return False
    except Exception as e:
        print(f"错误: {e}")   
        return False
    return True
