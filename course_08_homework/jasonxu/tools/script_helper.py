from .utils import hash160
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput, Sequence
from bitcoinutils.keys import PrivateKey, P2trAddress

def generate_bitcommitment_script(hash0, hash1):
    return ['OP_IF',
                              'OP_HASH160', 
                              hash1.hex(), 
                              'OP_EQUALVERIFY', 
                              'OP_1', #const_value_1.hex(),
                              'OP_ELSE',
                              'OP_HASH160',
                              hash0.hex(),
                              'OP_EQUALVERIFY',
                              'OP_0', #const_value_0.hex(),
                              'OP_ENDIF']

def generate_NAND_gate_script(left_operator_0_hash, left_operator_1_hash,
  right_operator_0_hash, right_operator_1_hash, result_0_hash, result_1_hash):
    C_bitvalue_script = generate_bitcommitment_script(result_0_hash, result_1_hash)
    B_bitvalue_script = generate_bitcommitment_script(right_operator_0_hash, right_operator_1_hash)
    A_bitvalue_script = generate_bitcommitment_script(left_operator_0_hash, left_operator_1_hash)
    return (C_bitvalue_script + ['OP_TOALTSTACK'] + \
        B_bitvalue_script + ['OP_TOALTSTACK'] + \
        A_bitvalue_script + \
        ['OP_FROMALTSTACK', 'OP_BOOLAND', 'OP_NOT',  'OP_FROMALTSTACK', 'OP_EQUALVERIFY', 'OP_1'])

def generate_equivocation_script(hash0, hash1):
    # the verifier can unlock the utxo with preimages for hash1 and hash0
    # the input is [preimage0, preimage1]
    return ['OP_HASH160', hash1.hex(), 'OP_EQUALVERIFY',
            'OP_HASH160', hash0.hex(), 'OP_EQUALVERIFY', 'OP_1']

def generate_hash_lock_script(hash):
    return ['OP_HASH160', hash.hex(), 'OP_EQUALVERIFY']

