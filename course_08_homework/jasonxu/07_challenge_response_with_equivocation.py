from bitcoinutils.setup import setup
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput, Sequence
from bitcoinutils.keys import PrivateKey, P2trAddress
from bitcoinutils.utils import ControlBlock

import os, sys, time
import configparser
from tools.utils import hash160, broadcast_tx_by_mempoolspace
from tools.script_helper import generate_equivocation_script, generate_NAND_gate_script
from tools.script_helper import generate_hash_lock_script
from tools.utxo_scanner import select_best_utxo


conf = configparser.ConfigParser()
conf_file = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "wa_info.conf")
conf.read(conf_file)

# Alice is verifier
alice_priv = PrivateKey(conf.get("testnet3", "private_key_wif"))
alice_pub = alice_priv.get_public_key()
punish_addr = alice_pub.get_address()

# Bob is prover
bob_priv = PrivateKey(conf.get("testnet3_source", "private_key_wif"))
bob_pub = bob_priv.get_public_key()   

# // A NAND B = E; C NAND D = F; E NAND F = G; G NAND F = H;
# // 1 NAND 0 = 1; 1 NAND 1 = 0; 1 NAND 0 = 1; 0 NAND 0 = 1

def main():
    setup('testnet')

    C0 = bytes.fromhex('64')
    C1 = bytes.fromhex('65')
    B0 = bytes.fromhex('66')
    B1 = bytes.fromhex('67')
    A0 = bytes.fromhex('68')
    A1 = bytes.fromhex('69')
    D0 = bytes.fromhex('63')
    D1 = bytes.fromhex('62')
    E0 = bytes.fromhex('70')
    E1 = bytes.fromhex('71')
    F0 = bytes.fromhex('72')
    F1 = bytes.fromhex('73')
    G0 = bytes.fromhex('74')
    G1 = bytes.fromhex('75')    
    H0 = bytes.fromhex('76')
    H1 = bytes.fromhex('77')   

    C0_hash = hash160(C0)
    C1_hash = hash160(C1)
    B0_hash = hash160(B0)
    B1_hash = hash160(B1)
    A0_hash = hash160(A0)
    A1_hash = hash160(A1)
    D0_hash = hash160(D0)
    D1_hash = hash160(D1)
    E0_hash = hash160(E0)
    E1_hash = hash160(E1)
    F0_hash = hash160(F0)
    F1_hash = hash160(F1)
    G0_hash = hash160(G0)
    G1_hash = hash160(G1)
    H0_hash = hash160(H0)
    H1_hash = hash160(H1)    

    # NAND script construct
    NAND_1_script = generate_NAND_gate_script(A0_hash,A1_hash,B0_hash,B1_hash,E0_hash,E1_hash)
    NAND_2_script = generate_NAND_gate_script(C0_hash,C1_hash,D0_hash,D1_hash,F0_hash,F1_hash)
    NAND_3_script = generate_NAND_gate_script(E0_hash,E1_hash,F0_hash,F1_hash,G0_hash,G1_hash)
    NAND_4_script = generate_NAND_gate_script(G0_hash,G1_hash,F0_hash,F1_hash,H0_hash,H1_hash)
    
    # equivocation_script
    A_equivocation_script = generate_equivocation_script(A0_hash, A1_hash)
    B_equivocation_script = generate_equivocation_script(B0_hash, B1_hash)
    C_equivocation_script = generate_equivocation_script(C0_hash, C1_hash)
    D_equivocation_script = generate_equivocation_script(D0_hash, D1_hash)
    E_equivocation_script = generate_equivocation_script(E0_hash, E1_hash)
    F_equivocation_script = generate_equivocation_script(F0_hash, F1_hash)
    G_equivocation_script = generate_equivocation_script(G0_hash, G1_hash)
    H_equivocation_script = generate_equivocation_script(H0_hash, H1_hash)

    # hash lock script
    NAND_1_challenge_preimage = bytes.fromhex('01')
    NAND_1_challenge_hash = hash160(NAND_1_challenge_preimage)
    NAND_2_challenge_preimage = bytes.fromhex('02')
    NAND_2_challenge_hash = hash160(NAND_2_challenge_preimage)
    NAND_3_challenge_preimage = bytes.fromhex('03')
    NAND_3_challenge_hash = hash160(NAND_3_challenge_preimage)
    NAND_4_challenge_preimage = bytes.fromhex('04')
    NAND_4_challenge_hash = hash160(NAND_4_challenge_preimage)    

    NAND_1_hash_lock_script = generate_hash_lock_script(NAND_1_challenge_hash)
    NAND_2_hash_lock_script = generate_hash_lock_script(NAND_2_challenge_hash)
    NAND_3_hash_lock_script = generate_hash_lock_script(NAND_3_challenge_hash)
    NAND_4_hash_lock_script = generate_hash_lock_script(NAND_4_challenge_hash)
    # construct challenge taproot tree
    challenge_tree = [[[ [Script(NAND_1_hash_lock_script),
                      Script(NAND_2_hash_lock_script)],
                      [Script(NAND_3_hash_lock_script),
                      Script(NAND_4_hash_lock_script)] ],
                      [[Script(A_equivocation_script),
                      Script(B_equivocation_script)],
                      [Script(C_equivocation_script),
                      Script(D_equivocation_script)] ]],
                      [[Script(E_equivocation_script),
                      Script(F_equivocation_script)],
                      [Script(G_equivocation_script),
                      Script(H_equivocation_script)] ]
                    ]

    # construct Responses taproot tree
    hash_lock_and_NAND_1_script = NAND_1_hash_lock_script + NAND_1_script
    hash_lock_and_NAND_2_script = NAND_2_hash_lock_script + NAND_2_script
    hash_lock_and_NAND_3_script = NAND_3_hash_lock_script + NAND_3_script
    hash_lock_and_NAND_4_script = NAND_4_hash_lock_script + NAND_4_script
    response_taptree = [[Script(hash_lock_and_NAND_1_script),
                        Script(hash_lock_and_NAND_2_script)],
                        [Script(hash_lock_and_NAND_3_script),
                         Script(hash_lock_and_NAND_4_script)]
                       ]

    # construct equivocation_script taproot tree
    # equivocation_taptree = [[[Script(A_equivocation_script),
    #                         Script(B_equivocation_script)], 
    #                         [Script(C_equivocation_script),
    #                         Script(D_equivocation_script)] ],
    #                         [[Script(E_equivocation_script),
    #                         Script(F_equivocation_script)],
    #                         [Script(G_equivocation_script),
    #                         Script(H_equivocation_script)] ]
    #                        ]
    
    challenge_p2tr_addr = alice_pub.get_taproot_address(challenge_tree)
    print(f"challenge 地址: {challenge_p2tr_addr.to_string()}")
    response_p2tr_addr = bob_pub.get_taproot_address(response_taptree)
    print(f"response 地址: {response_p2tr_addr.to_string()}")
  

#   // --- challenge and response process with equivocation_happen ---
#   // A,B,C,D is the inputs for the program and the G is the output for the program
#   // 1. verifer challenge NAND1 through revealing the `NAND_1_challenge_preimage`
#   // 2. prover response NAND1 through enter the `NAND_1_challenge_preimage` and `reveal the input and output for NAND1`
#   // 3. verifer challenge NAND2 through revealing the `NAND_2_challenge_preimage`
#   // 4. prover response NAND2 through enter the `NAND_2_challenge_preimage` and `reveal the input and output for NAND2`
#   // 5. verifer challenge NAND3 through revealing the `NAND_3_challenge_preimage`
#   // 6. prover response NAND3 through enter the `NAND_3_challenge_preimage` and `reveal the input and output for NAND3`
#   // 7. verifer challenge NAND4 through revealing the `NAND_4_challenge_preimage`
#   // 8. prover response NAND4 through enter the `NAND_4_challenge_preimage` and `reveal the input and output for NAND4`
#   // >>> equivocation_happen <<<

    # ======== the first round =======
    # the challenge NAND1 transaction
    NAND_1_challenge_inputs = [bytes.fromhex('01').hex(), NAND_1_challenge_preimage.hex()]

    # prover response the challenge by the preimage found from challenge tx, reveal the input and output for the NAND gate
    NAND1_response_inputs = [
        A1.hex(), # A = 1
        bytes.fromhex('01').hex(), # OP_IF solution
        B0.hex(), # B = 0
        bytes().hex(), # OP_ELSE solution
        E1.hex(), # C = 1
        bytes.fromhex('01').hex()] + [NAND_1_challenge_preimage.hex()]
    
    # initial UTXO
    # selected_utxo = select_best_utxo(challenge_p2tr_addr.to_string(), 10000)
    # if not selected_utxo:
    #     print(f"❌ 没有足够的UTXO支付10000 sats")
    #     return
    # input_amount = selected_utxo['amount']
    # input_txid = selected_utxo['txid']
    input_txid = "cd613342b85aee82757cf75e134451682df738a239ce51d8e8698602ce0dcd65"
    input_amount = 10000
    vout = 0
    print(f"selected utxo tx {input_txid}, amount {input_amount}")
    fee = 500

    # 1st challenge tx
    txin = TxInput(input_txid, vout)
    txout = TxOutput(input_amount-fee, response_p2tr_addr.to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    cb = ControlBlock(alice_pub, challenge_tree, 0, is_odd=challenge_p2tr_addr.is_odd())
    tx.witnesses.append(
        TxWitnessInput(NAND_1_challenge_inputs + 
                       [Script(NAND_1_hash_lock_script).to_hex()] + [cb.to_hex()] )
    )

    signed_tx = tx.serialize()
    print("\n1st challenge transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())    
    if not broadcast_tx_by_mempoolspace(signed_tx):
       return
    txid = tx.get_txid()
    vout = 0
    input_amount -= fee
    time.sleep(10)

    # 1st response tx
    txin = TxInput(txid, vout)
    txout = TxOutput(input_amount-fee, challenge_p2tr_addr.to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    cb = ControlBlock(bob_pub, response_taptree, 0, is_odd=response_p2tr_addr.is_odd())
    tx.witnesses.append(
        TxWitnessInput(NAND1_response_inputs + 
                       [Script(hash_lock_and_NAND_1_script).to_hex()] + [cb.to_hex()] )
    )

    signed_tx = tx.serialize()
    print("\n1st response transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())    
    if not broadcast_tx_by_mempoolspace(signed_tx):
       return
    txid = tx.get_txid()
    vout = 0 
    input_amount -= fee
    time.sleep(10)
  
    # ======== the second round =======
    NAND_2_challenge_inputs = [bytes.fromhex('01').hex(), NAND_2_challenge_preimage.hex()]

    # prover response the challenge by the preimage found from challenge tx, reveal the input and output for the NAND gate
    NAND2_response_inputs = [
        C1.hex(), # C = 1
        bytes.fromhex('01').hex(), # OP_IF solution
        D1.hex(), # D = 1
        bytes.fromhex('01').hex(), # OP_IF solution
        F0.hex(), # F = 0
        bytes().hex()] + [NAND_2_challenge_preimage.hex()]
    
    # 2nd challenge tx
    txin = TxInput(txid, vout)
    txout = TxOutput(input_amount-fee, response_p2tr_addr.to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    cb = ControlBlock(alice_pub, challenge_tree, 1, is_odd=challenge_p2tr_addr.is_odd())
    tx.witnesses.append(
        TxWitnessInput(NAND_2_challenge_inputs + 
                       [Script(NAND_2_hash_lock_script).to_hex()] + [cb.to_hex()] )
    )

    signed_tx = tx.serialize()
    print("\n2nd challenge transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())    
    if not broadcast_tx_by_mempoolspace(signed_tx):
       return
    txid = tx.get_txid()
    vout = 0
    input_amount -= fee
    time.sleep(10)

    # 2nd response tx
    txin = TxInput(txid, vout)
    txout = TxOutput(input_amount-fee, challenge_p2tr_addr.to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    cb = ControlBlock(bob_pub, response_taptree, 1, is_odd=response_p2tr_addr.is_odd())
    tx.witnesses.append(
        TxWitnessInput(NAND2_response_inputs + 
                       [Script(hash_lock_and_NAND_2_script).to_hex()] + [cb.to_hex()] )
    )

    signed_tx = tx.serialize()
    print("\n2nd response transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())    
    if not broadcast_tx_by_mempoolspace(signed_tx):
       return
    txid = tx.get_txid()
    vout = 0 
    input_amount -= fee
    time.sleep(10)
    
    # ======== the third round =======
    NAND_3_challenge_inputs = [bytes.fromhex('01').hex(), NAND_3_challenge_preimage.hex()]

    # prover response the challenge by the preimage found from challenge tx, reveal the input and output for the NAND gate
    NAND3_response_inputs = [
        E1.hex(), # E = 1
        bytes.fromhex('01').hex(), # OP_IF solution
        F0.hex(), # F = 0
        bytes().hex(), # OP_ELSE solution
        G1.hex(), # G = 1
        bytes.fromhex('01').hex()] + [NAND_3_challenge_preimage.hex()]
    
    # 3th challenge tx
    txin = TxInput(txid, vout)
    txout = TxOutput(input_amount-fee, response_p2tr_addr.to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    cb = ControlBlock(alice_pub, challenge_tree, 2, is_odd=challenge_p2tr_addr.is_odd())
    tx.witnesses.append(
        TxWitnessInput(NAND_3_challenge_inputs + 
                       [Script(NAND_3_hash_lock_script).to_hex()] + [cb.to_hex()] )
    )

    signed_tx = tx.serialize()
    print("\n3th challenge transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())    
    if not broadcast_tx_by_mempoolspace(signed_tx):
       return
    txid = tx.get_txid()
    vout = 0
    input_amount -= fee
    time.sleep(10)

    # 3th response tx
    txin = TxInput(txid, vout)
    txout = TxOutput(input_amount-fee, challenge_p2tr_addr.to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    cb = ControlBlock(bob_pub, response_taptree, 2, is_odd=response_p2tr_addr.is_odd())
    tx.witnesses.append(
        TxWitnessInput(NAND3_response_inputs + 
                       [Script(hash_lock_and_NAND_3_script).to_hex()] + [cb.to_hex()] )
    )

    signed_tx = tx.serialize()
    print("\n3th response transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())    
    if not broadcast_tx_by_mempoolspace(signed_tx):
       return
    txid = tx.get_txid()
    vout = 0 
    input_amount -= fee
    time.sleep(10)

    # ======== the forth round =======
    NAND_4_challenge_inputs = [bytes.fromhex('01').hex(), NAND_4_challenge_preimage.hex()]

    # prover response the challenge by the preimage found from challenge tx, reveal the input and output for the NAND gate
    NAND4_response_inputs = [
        G0.hex(), # G = 0
        bytes().hex(), # OP_IF solution
        F0.hex(), # F = 0
        bytes().hex(), # OP_ELSE solution
        H1.hex(), # H = 1
        bytes.fromhex('01').hex()] + [NAND_4_challenge_preimage.hex()]
    # 4th challenge tx
    txin = TxInput(txid, vout)
    txout = TxOutput(input_amount-fee, response_p2tr_addr.to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    cb = ControlBlock(alice_pub, challenge_tree, 3, is_odd=challenge_p2tr_addr.is_odd())
    tx.witnesses.append(
        TxWitnessInput(NAND_4_challenge_inputs + 
                       [Script(NAND_4_hash_lock_script).to_hex()] + [cb.to_hex()] )
    )

    signed_tx = tx.serialize()
    print("\n4th challenge transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())    
    if not broadcast_tx_by_mempoolspace(signed_tx):
       return
    txid = tx.get_txid()
    vout = 0
    input_amount -= fee
    time.sleep(10)

    # 4th response tx
    txin = TxInput(txid, vout)
    txout = TxOutput(input_amount-fee, challenge_p2tr_addr.to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    cb = ControlBlock(bob_pub, response_taptree, 3, is_odd=response_p2tr_addr.is_odd())
    tx.witnesses.append(
        TxWitnessInput(NAND4_response_inputs + 
                       [Script(hash_lock_and_NAND_4_script).to_hex()] + [cb.to_hex()] )
    )

    signed_tx = tx.serialize()
    print("\n4th response transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())    
    if not broadcast_tx_by_mempoolspace(signed_tx):
       return
    txid = tx.get_txid()
    vout = 0 
    input_amount -= fee
    time.sleep(10)

#   // ======== The fifth round =========
#   // verifier already known G0 and G1, he can unlock the utxo by providing the inputs[G0,G1] and `G_equivocation_script`
#   // verifier punish the prover's equivocation behavior by taking away the BTC
    fee = 5000
    punish_equivocation_inputs = [
        G0.hex(), # G = 0 preimage
        G1.hex(), # G = 1 preimage
        ] 
    # punish tx
    txin = TxInput(txid, vout)
    txout = TxOutput(input_amount-fee, punish_addr.to_script_pub_key())
    tx = Transaction([txin], [txout], has_segwit=True)

    cb = ControlBlock(alice_pub, challenge_tree, 10, is_odd=challenge_p2tr_addr.is_odd())
    tx.witnesses.append(
        TxWitnessInput(punish_equivocation_inputs + 
                       [Script(G_equivocation_script).to_hex()] + [cb.to_hex()] )
    )

    signed_tx = tx.serialize()
    print("\nG_equivocation transaction:\n" + signed_tx)
    print("\nTxId:", tx.get_txid())    
    if not broadcast_tx_by_mempoolspace(signed_tx):
       return
    txid = tx.get_txid()
    vout = 0
    input_amount -= fee
    time.sleep(10)


if __name__ == "__main__":
    main()

  