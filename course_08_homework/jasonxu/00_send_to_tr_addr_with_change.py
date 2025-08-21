from bitcoinutils.keys import P2shAddress, PrivateKey, P2trAddress
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
from bitcoinutils.hdwallet import HDWallet
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, Sequence
from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK

import os, sys
import configparser
import requests


conf = configparser.ConfigParser()
conf_file = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "wa_info.conf")
conf.read(conf_file)

setup("testnet")

#
# Send from a P2PKH UTXO and send to P2SH, 
# Change back to the same address (not recommended for privacy reasons)
#


from_priv = PrivateKey(conf.get("testnet3", "private_key_wif"))
from_addr = from_priv.get_public_key().get_address()

to_addr = P2trAddress("tb1p9mlkwmd8akypvmc89d7q96xvan0qmp66wah7ms65lsk9tudv76pq0gm8a6")
print("To address:", to_addr.to_string())

# UTXO's info
txid = "cd613342b85aee82757cf75e134451682df738a239ce51d8e8698602ce0dcd65"
vout = 1

txin = TxInput(txid, vout)
txout = TxOutput(10000, to_addr.to_script_pub_key())
txout_change = TxOutput(236000, from_addr.to_script_pub_key())
tx = Transaction([txin], [txout, txout_change])
#tx_size = tx.get_size() # looks send to p2sh tx size is wrong
#fee = int(tx_size*1.01)
#print(f"Tx size: {tx_size}, fee: {fee}")
#txout = TxOutput(4468 - fee, p2sh_address.to_script_pub_key())
#tx = Transaction([txin], [txout, txout_change])

sig = from_priv.sign_input(tx, 0, from_addr.to_script_pub_key())

txin.script_sig = Script([sig, from_priv.get_public_key().to_hex()])

signed_tx = tx.serialize()

# print raw signed transaction ready to be broadcasted
print("\nRaw signed transaction:\n" + signed_tx)
print("\nTxId:", tx.get_txid())

# 6. 广播交易
print("\n广播交易...")
mempool_api = "https://mempool.space/testnet/api/tx"
try:
    response = requests.post(mempool_api, data=signed_tx)
    if response.status_code == 200:
        txid = response.text
        print(f"交易成功！")
        print(f"交易ID: {txid}")
        print(f"查看交易: https://mempool.space/testnet/tx/{txid}")
    else:
        print(f"广播失败: {response.text}")
except Exception as e:
    print(f"错误: {e}")   
