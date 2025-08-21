from bitcoinutils.setup import setup
from bitcoinutils.utils import ControlBlock
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput, Sequence
from bitcoinutils.keys import PrivateKey
from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK
import hashlib
import os, sys
import configparser
import requests
from tools.utils import hash160, broadcast_tx_by_mempoolspace, broadcast_tx_by_blockstream
from tools.utxo_scanner import select_best_utxo

conf = configparser.ConfigParser()
conf_file = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "wa_info.conf")
conf.read(conf_file)


def main():
    setup('testnet')

    secret_bytes_1 = bytes.fromhex('62')
    secret_bytes_2 = bytes.fromhex('63')
    hash_1 = hash160(secret_bytes_1)
    hash_2 = hash160(secret_bytes_2)
    const_value_1 = bytes.fromhex('01')
    const_value_0 = bytes.fromhex('00')
    
    # Alice 的内部私钥
    alice_priv = PrivateKey(conf.get("testnet3", "private_key_wif"))
    alice_pub = alice_priv.get_public_key()
    print(f"alice's pubkey:{alice_pub.to_hex()}, len:{len(alice_pub.to_hex())}")

    bitvalue_script = Script(['OP_IF',
                              'OP_HASH160', 
                              hash_1.hex(), 
                              'OP_EQUALVERIFY', 
                              'OP_1', #const_value_1.hex(),
                              'OP_ELSE',
                              'OP_HASH160',
                              hash_2.hex(),
                              'OP_EQUALVERIFY',
                              'OP_0',#const_value_0.hex(),
                              'OP_ENDIF'])
    print(f"1st script str:{bitvalue_script.to_hex()}")

    p2pk_script = Script([alice_pub.to_x_only_hex(), 
                          'OP_CHECKSIG'])
    # 构建 Merkle Tree
    tree = [bitvalue_script, p2pk_script]
    
    taproot_address = alice_pub.get_taproot_address(tree)
    
    print(f"Taproot 地址: {taproot_address.to_string()}")

    selected_utxo = select_best_utxo(taproot_address.to_string(), 2000)
    if not selected_utxo:
        print(f"❌ 没有足够的UTXO支付1000 sats")
        return
    input_amount = selected_utxo['amount']
    input_txid = selected_utxo['txid']
    print(f"selected utxo tx {input_txid}, amount {input_amount}")
    
   # 构建交易
    txin = TxInput(input_txid, selected_utxo['vout'])
    # 输出到 Alice 的normal taproot地址
    txout = TxOutput(input_amount-1200, alice_pub.get_taproot_address().to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    cb = ControlBlock(alice_pub, tree, 0, is_odd=taproot_address.is_odd())

    tx.witnesses.append(
        TxWitnessInput([
            secret_bytes_2.hex(),        # preimage (hex str)
            bytes().hex(),
            bitvalue_script.to_hex(),          # script 本体
            cb.to_hex()                # control block
        ])
    )

    print(f"TxId: {tx.get_txid()}")
    print(f"交易大小: {tx.get_size()} bytes")
    print(f"虚拟大小: {tx.get_vsize()} vbytes")

    signed_tx = tx.serialize()
    print(f"Raw Tx: {signed_tx}")

    broadcast_tx_by_blockstream(signed_tx)

if __name__ == "__main__":
    main()

  