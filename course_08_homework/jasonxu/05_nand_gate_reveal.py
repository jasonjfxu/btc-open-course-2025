from bitcoinutils.setup import setup
from bitcoinutils.utils import ControlBlock
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput, Sequence
from bitcoinutils.keys import PrivateKey, P2trAddress
from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK
import hashlib
import os, sys
import configparser
import requests
from tools.utils import hash160, broadcast_tx_by_mempoolspace, broadcast_tx_by_blockstream
from tools.utxo_scanner import select_best_utxo
from tools.script_helper import generate_bitcommitment_script

conf = configparser.ConfigParser()
conf_file = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "wa_info.conf")
conf.read(conf_file)


def main():
    setup('testnet')

    C0 = bytes.fromhex('64')
    C1 = bytes.fromhex('65')
    B0 = bytes.fromhex('66')
    B1 = bytes.fromhex('67')
    A0 = bytes.fromhex('68')
    A1 = bytes.fromhex('69')

    C0_hash = hash160(C0)
    C1_hash = hash160(C1)
    B0_hash = hash160(B0)
    B1_hash = hash160(B1)
    A0_hash = hash160(A0)
    A1_hash = hash160(A1)

    # construct NAND gate script
    C_bitvalue_script = generate_bitcommitment_script(C0_hash, C1_hash)
    B_bitvalue_script = generate_bitcommitment_script(B0_hash, B1_hash)
    A_bitvalue_script = generate_bitcommitment_script(A0_hash, A1_hash)
    
    # Alice 的内部私钥
    alice_priv = PrivateKey(conf.get("testnet3", "private_key_wif"))
    alice_pub = alice_priv.get_public_key()
    from_addr = alice_pub.get_address()
    print(f"alice's pubkey:{alice_pub.to_hex()}, len:{len(alice_pub.to_hex())}")

    nand_gate_script = Script(C_bitvalue_script + ['OP_TOALTSTACK'] + 
                              B_bitvalue_script + ['OP_TOALTSTACK'] + 
                              A_bitvalue_script + 
                              ['OP_FROMALTSTACK', 'OP_BOOLAND', 'OP_NOT', 
                                       'OP_FROMALTSTACK', 'OP_EQUALVERIFY', 'OP_1']
                              )
    print(f"1st script str:{nand_gate_script.to_hex()}")

    p2pk_script = Script([alice_pub.to_x_only_hex(), 
                          'OP_CHECKSIG'])
    # 构建 Merkle Tree
    tree = [nand_gate_script, p2pk_script]

    # taproot_address = alice_pub.get_taproot_address(tree)
    taproot_address = P2trAddress("tb1p503gqf5p947jajydnl2kweu3ht7jre3s6a2gzeuc4sx0xppuz6hq4dv9rp")
    selected_utxo = select_best_utxo(taproot_address.to_string(), 2500)
    if not selected_utxo:
        print(f"❌ 没有足够的UTXO支付1000 sats")
        return
    input_amount = selected_utxo['amount']
    input_txid = selected_utxo['txid']
    print(f"selected utxo tx {input_txid}, amount {input_amount}")
    
   # 构建交易
    txin = TxInput(input_txid, selected_utxo['vout'])
    # 输出到 Alice 的normal taproot地址
    txout = TxOutput(input_amount-1900, alice_pub.get_taproot_address().to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    cb = ControlBlock(alice_pub, tree, 0, is_odd=taproot_address.is_odd())

    tx.witnesses.append(
        TxWitnessInput([
            A1.hex(),        # A = 1
            bytes.fromhex('01').hex(),
            B0.hex(),       # B = 0
            bytes().hex(),
            C1.hex(),       # C = 1
            bytes.fromhex('01').hex(),
            nand_gate_script.to_hex(),          # script 本体
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

  