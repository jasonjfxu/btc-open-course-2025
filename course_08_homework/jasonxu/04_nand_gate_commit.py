from bitcoinutils.setup import setup
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput, Sequence
from bitcoinutils.keys import PrivateKey, P2trAddress

import os, sys
import configparser
from tools.utils import hash160, broadcast_tx_by_mempoolspace
from tools.script_helper import generate_bitcommitment_script

conf = configparser.ConfigParser()
conf_file = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "wa_info.conf")
conf.read(conf_file)

#   // OP_BOOLAND if both a and b are not 0, the output is 1.Otherwise 0.
#   // 1 1 1
#   // 0 1 0
#   // 0 0 0
#   // 0 1 0

#   // NAND gate
#   // 1 1 0
#   // 1 0 1
#   // 0 1 1
#   // 0 0 1

#   // we can use OP_BOOLAND OP_NOT to implement NAND gate

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
    
    #taproot_address = P2trAddress("tb1pdxd79reesa7m0x8mvu09d8wxeafzvphgyzl6zdt6m7gu55u525cstmsv0h") 
    taproot_address = alice_pub.get_taproot_address(tree)
    
    print(f"Taproot 地址: {taproot_address.to_string()}")
    print(f"Alice 私钥: {alice_priv.to_wif()}")
    print(f"Alice 公钥: {alice_pub.to_hex()}")

    # UTXO's info
    txid = "4b36828c153db0d536ffe1a7527db64f726cec56843a96b6c1e039be101b4eaa"
    vout = 1
    input_amount = 167030
    output_amount = 2500
    fee = 600

    txin = TxInput(txid, vout)
    txout = TxOutput(output_amount, taproot_address.to_script_pub_key())
    txout_change = TxOutput(input_amount-output_amount-fee, from_addr.to_script_pub_key())
    tx = Transaction([txin], [txout, txout_change])

    sig = alice_priv.sign_input(tx, 0, from_addr.to_script_pub_key())

    txin.script_sig = Script([sig, alice_priv.get_public_key().to_hex()])

    signed_tx = tx.serialize()

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())

    broadcast_tx_by_mempoolspace(signed_tx)

if __name__ == "__main__":
    main()

  