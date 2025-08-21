from bitcoinutils.setup import setup
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput, Sequence
from bitcoinutils.keys import PrivateKey, P2trAddress

import os, sys
import configparser
from tools.utils import hash160, broadcast_tx_by_mempoolspace


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
    from_addr = alice_pub.get_address()
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
                              'OP_0', #const_value_0.hex(),
                              'OP_ENDIF'])
    print(f"1st script str:{bitvalue_script.to_hex()}")

    p2pk_script = Script([alice_pub.to_x_only_hex(), 
                          'OP_CHECKSIG'])
    # 构建 Merkle Tree
    tree = [bitvalue_script, p2pk_script]
    
    #taproot_address = P2trAddress("tb1pdxd79reesa7m0x8mvu09d8wxeafzvphgyzl6zdt6m7gu55u525cstmsv0h") 
    taproot_address = alice_pub.get_taproot_address(tree)
    
    print(f"Taproot 地址: {taproot_address.to_string()}")
    print(f"Alice 私钥: {alice_priv.to_wif()}")
    print(f"Alice 公钥: {alice_pub.to_hex()}")

    # UTXO's info
    txid = "0541a2a53c60b209d67bae3934dfd87e28c6a968e6366a51764b5304a9ad3159"
    vout = 1
    input_amount = 172430
    output_amount = 1200
    fee = 1200

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

  