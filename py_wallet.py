import thriftpy2
import json
import base58check
import math

import hashlib

import ed25519
import time

from struct import *
from thriftpy2.rpc import make_client
from thriftpy2.thrift import TPayload, TException, TType

# from thriftpy2.protocol.binary import TBinaryProtocolFactory
# from thriftpy2.transport.buffered import TBufferedTransportFactory
# from thriftpy2.transport.framed import TFramedTransportFactory
from thriftpy2.protocol import TBinaryProtocol
from thriftpy2.transport import TMemoryBuffer
from csutils import Utils

import PySimpleGUI as sg

kTensPows = [1e-18, 1e-17, 1e-16, 1e-15, 1e-14, 1e-13, 1e-12, 1e-11, 1e-10, 1e-9, 1e-8, 1e-7, 1e-6, 1e-5, 1e-4, 1e-3,
                        1e-2,  1e-1,  1.,    1e1,   1e2,   1e3,   1e4,   1e5,   1e6,   1e7,  1e8,  1e9,  1e10, 1e11, 1e12, 1e13]

themes = ['Black', 'BlueMono', 'BluePurple', 'BrightColors', 'BrownBlue', 'Dark', 'Dark2', 'DarkAmber', 'DarkBlack', 'DarkBlack1'
, 'DarkBlue', 'DarkBlue1', 'DarkBlue10', 'DarkBlue11', 'DarkBlue12', 'DarkBlue13', 'DarkBlue14', 'DarkBlue15', 'DarkBlue16'
, 'DarkBlue17', 'DarkBlue2', 'DarkBlue3', 'DarkBlue4', 'DarkBlue5', 'DarkBlue6', 'DarkBlue7', 'DarkBlue8', 'DarkBlue9', 'DarkBrown'
, 'DarkBrown1', 'DarkBrown2', 'DarkBrown3', 'DarkBrown4', 'DarkBrown5', 'DarkBrown6', 'DarkGreen', 'DarkGreen1', 'DarkGreen2'
, 'DarkGreen3', 'DarkGreen4', 'DarkGreen5', 'DarkGreen6', 'DarkGrey', 'DarkGrey1', 'DarkGrey2', 'DarkGrey3', 'DarkGrey4', 'DarkGrey5'
, 'DarkGrey6', 'DarkGrey7', 'DarkPurple', 'DarkPurple1', 'DarkPurple2', 'DarkPurple3', 'DarkPurple4', 'DarkPurple5', 'DarkPurple6'
, 'DarkRed', 'DarkRed1', 'DarkRed2', 'DarkTanBlue', 'DarkTeal', 'DarkTeal1', 'DarkTeal10', 'DarkTeal11', 'DarkTeal12', 'DarkTeal2'
, 'DarkTeal3', 'DarkTeal4', 'DarkTeal5', 'DarkTeal6', 'DarkTeal7', 'DarkTeal8', 'DarkTeal9', 'Default', 'Default1'
, 'DefaultNoMoreNagging', 'Green', 'GreenMono', 'GreenTan', 'HotDogStand', 'Kayak', 'LightBlue', 'LightBlue1', 'LightBlue2'
, 'LightBlue3', 'LightBlue4', 'LightBlue5', 'LightBlue6', 'LightBlue7', 'LightBrown', 'LightBrown1', 'LightBrown10', 'LightBrown11'
, 'LightBrown12', 'LightBrown13', 'LightBrown2', 'LightBrown3', 'LightBrown4', 'LightBrown5', 'LightBrown6', 'LightBrown7'
, 'LightBrown8', 'LightBrown9', 'LightGray1', 'LightGreen', 'LightGreen1', 'LightGreen10', 'LightGreen2', 'LightGreen3'
, 'LightGreen4', 'LightGreen5', 'LightGreen6', 'LightGreen7', 'LightGreen8', 'LightGreen9', 'LightGrey', 'LightGrey1'
, 'LightGrey2', 'LightGrey3', 'LightGrey4', 'LightGrey5', 'LightGrey6', 'LightPurple', 'LightTeal', 'LightYellow', 'Material1'
, 'Material2', 'NeutralBlue', 'Purple', 'Reddit', 'Reds', 'SandyBeach', 'SystemDefault', 'SystemDefault1', 'SystemDefaultForReal'
, 'Tan', 'TanBlue', 'TealMono', 'Topanga']

settings_ = {'thrift_file_path' : './thrift-interface-definitions/api.thrift'
, 'theme' : 'SystemDefault1'
, 'API_host' : ''
, 'last_key_file' : ''
, 'last_target' : ''
, 'last_amount' : ''
, 'last_fee' : ''
, 'last_uf' : ''
, 'last_search' : ''
, 'last_delegated_date' : ''
}

deploy_addr = ""

node_dict_ = {}
node_dict_base58_ = {}
current_contract_parameters = {}
using_default = False
try:
    settings_file = open('settings.json', 'r')
except:
    sg.Popup('Warning', 'Settings file doesn\'t exist. Default created')
    with open("settings.json", "w") as settings_file:
        json.dump(settings_, settings_file)
    settings_file.close()
    using_default = True

if not using_default:
    settings_.clear()
    settings_ = json.load(settings_file)

without_dict = False
try:
    node_dict_file = open('dict.json', 'r')
except:
    sg.Popup('Warning', 'Node dictionary file can\'t be loaded. Proceed without it.')
    without_dict = True

if not without_dict:
    try:
        node_dict_ = json.load(node_dict_file)
    except:
        sg.Popup('Warning', 'Node dictionary file can\'t be processed. Try to correct it. Now proceed without it.')
        without_dict = True


for it in node_dict_:
    hex_data = bytes.fromhex(it)
    b = base58check.b58encode(hex_data).decode('ascii')
    node_dict_base58_[b] = node_dict_[it]

current_theme = settings_['theme']
api_thrift = thriftpy2.load(settings_['thrift_file_path'], module_name="api_thrift")

last_contract = 'import ...'
node_address = settings_['API_host'].split(':')[0]
port = 0 if not len(settings_['API_host']) else int(settings_['API_host'].split(':')[1])

currencies = []
src = ''
src_priv = ''
sourceKey = bytes()
sourcePrivKey = bytes()
if len(settings_['last_key_file']) > 0:
    try:
        rff = open(settings_['last_key_file'], 'r')
        # line = rff.readline()
        pkey_dct = json.load(rff)
        src = pkey_dct['key']['public']
        src_priv = pkey_dct['key']['private']
        sourceKey = base58check.b58decode(src)
        sourcePrivKey =  base58check.b58decode(src_priv)
        rff.close()
    except:
        print("use no default public key")


sg.theme(current_theme)
dct = {'add_bootstrap': b'\x02\x00'
, 'change_startnode': b'\x01\x00'
, 'change_stage1_timeout': b'\x09\x00'
, 'change_contract_execution_time': b'\x0B\x00'
, 'change_transaction_life_time': b'\x0A\x00'
, 'remove_blocks_to': b'\x0f\x00'
, 'min_compatible_version' : b'\x05\x00'
, 'set_s1_max_size': b'\x15\x00'
, 'set_min_stake_value': b'\x16\x00'
, 'set_hash_collect_time': b'\x17\x00'
, 'set_gray_list_punishment': b'\x18\x00'
, 'set_s1_hashes': b'\x19\x00'
, 'set_transaction_size': b'\x1a\x00'
, 'set_s1_transactions': b'\x1b\x00'
, 'set_block_size': b'\x1c\x00'
, 'set_max_packets': b'\x1d\x00'
, 'set_packet_transactions': b'\x1e\x00'
, 'set_queue_size': b'\x1f\x00'
}

def m_client():
    try:
        client = make_client(api_thrift.API, node_address, port,  timeout=None)
    except:
        sg.Popup('Error', 'Client can\'t connect to node')
        client = None
    return client

def diag_client():
    try:
        client = make_client(apidiag_thrift.API_DIAG, diag_node_address, diag_port)
    except:
        sg.Popup('Error', 'Client can\'t connect to node')
        client = None
    return client
    
def fee_to_double(fee):
    sign = -1. if int(fee / 32768) != 0 else 1.
    fee_double_ = sign * float(fee % 1024) * 1. / 1024.  * kTensPows[int(fee % 32768 / 1024)] 
    return fee_double_

def double_to_fee(value):
    fee_comission = 0
    a = True
    if value < 0.:
        fee_comission += 32768
    else:
        fee_comission += (32768 if value < 0. else 0)
        value = math.fabs(value)
        expf = (0. if value == 0. else math.log10(value))
        expi = int(expf + 0.5 if expf >= 0. else expf - 0.5)
        value /= math.pow(10, expi)
        if value >= 1.:
            value *= 0.1
            expi += 1
        fee_comission += int(1024*(expi + 18))
        fee_comission += int(value * 1024)
    return fee_comission

def initilizeCurrecyList():
    currencies.clear()
    currencies.append('CS')

def updateCurrecyList(currencyList):
    for a in currencyList:
        if a not in currencies:
            currencies.append(a)

def sendAmount(src, src_priv, dst, aInteger, aFraction, m_fee, userField_bytes, sUserFields):
    client = m_client()
    if client == None:
        return
    tr = api_thrift.Transaction()

    tr.source = base58check.b58decode(src)
    w = client.WalletTransactionsCountGet(tr.source)
    lastInnerId = bytearray((w.lastTransactionInnerId + 1).to_bytes(6,'little'))
    tr.id = int.from_bytes(lastInnerId,byteorder='little', signed=False)
    tr.target = base58check.b58decode(dst)
    tr.amount = api_thrift.general.Amount()
    tr.amount.integral = aInteger
    tr.amount.fraction = aFraction
    tr.balance = api_thrift.general.Amount()
    tr.balance.integral = 0
    tr.balance.fraction = 0
    tr.currency = 1
    tr.fee = api_thrift.AmountCommission()
    tr.fee.commission = m_fee
    tr.userFields = bytes(userField_bytes)
    ms = int(0)
    ufNum1 = bytearray(b'\x00')
    if len(userField_bytes) == 0:
        sUserFields.append(0)
    sMap = '=6s32s32slqhb' + str(len(sUserFields)) + 's' #len(userField_bytes)
    serial_transaction_for_sign = pack(sMap,  #'=' - without alignment
                       lastInnerId,     #6s - 6 byte InnerID (char[] C Type)
                       tr.source,       #32s - 32 byte source public key (char[] C Type)
                       tr.target,       #32s - 32 byte target pyblic key (char[] C Type)
                       tr.amount.integral, #i - 4 byte integer(int C Type)
                       tr.amount.fraction, #q - 8 byte integer(long long C Type)
                       tr.fee.commission,  #h - 2 byte integer (short C Type)
                       tr.currency,        #b - 1 byte integer (signed char C Type)
                       sUserFields)            #b - 1 byte userfield_num

    #print('Serialized transaction: ', serial_transaction.hex())
    senderPKey =  base58check.b58decode(src_priv)
    signing_key = ed25519.SigningKey(senderPKey) # Create object for calulate signing
    tr.signature = signing_key.sign(serial_transaction_for_sign)
    try:
        res = client.TransactionFlow(tr)
    except: 
        sg.Popup('API Message',
         'TimeOut during connection.') # 'The button clicked was "{}"'.format(event), 'The values are', values
        client.close()
        return 
    client.close()
    sg.Popup('API Message', res.status.message if not('Success' in  res.status.message) else ('Success: id: '+ str(res.id.poolSeq) + '.' + str(res.id.index) + ', fee: ' + ''.join(str(res.fee.integral) + "." + str(res.fee.fraction).zfill(18))))
    return res

def sendToken(src, recv, src_priv, m_fee, token_addr, uf_text):
    sUserFields = bytearray()
    client = m_client()
    if client == None:
        return
    tr = api_thrift.Transaction()
    tr.source = base58check.b58decode(src)
    w = client.WalletTransactionsCountGet(tr.source)
    lastInnerId = bytearray((w.lastTransactionInnerId + 1).to_bytes(6,'little'))
    tr.id = int.from_bytes(lastInnerId,byteorder='little', signed=False)

#
def deployContract(src, src_priv, m_fee, contract, uf_text, mul):
    sUserFields = bytearray()
    client = m_client()
    if client == None:
        return
    tr = api_thrift.Transaction()

    tr.smartContract = contract

    tr.source = base58check.b58decode(src)
    w = client.WalletTransactionsCountGet(tr.source)
    lastInnerId = bytearray((w.lastTransactionInnerId + 1).to_bytes(6,'little'))
    tr.id = int.from_bytes(lastInnerId,byteorder='little', signed=False)
    tr.target = createContractAddress(tr.source, lastInnerId, contract)
    tr.amount = api_thrift.general.Amount()
    tr.amount.integral = 0
    tr.amount.fraction = 0
    tr.balance = api_thrift.general.Amount()
    tr.balance.integral = 0
    tr.balance.fraction = 0
    tr.currency = 1
    tr.fee = api_thrift.AmountCommission()
    tr.fee.commission = m_fee
    tr.userFields = uf_text
    userField_bytes = bytearray()
    ms = int(0)
    ufNum1 = bytearray(b'\x01')
    if len(userField_bytes) == 0:
        sUserFields.append(0)
    codeLength = len(contract.smartContractDeploy.byteCodeObjects[0].byteCode)
    codeNameLength = len(contract.smartContractDeploy.byteCodeObjects[0].name)
    scriptLength = len(contract.smartContractDeploy.sourceCode)
    ufLength = codeLength + codeNameLength + scriptLength

  
    contract._tspec['method'] = (True, 11)
    contract._tspec['params'] = (True, 15)
    contract._tspec['forgetNewState'] = (True, 2)
    contract._tspec['smartContractDeploy'] = (True, 12)
    contract._tspec['usedContracts'] = (True, (15,11))
    contract._tspec['version'] = (True, 6)
    contract.smartContractDeploy._tspec['byteObjects'] = (True, 15)
    contract.smartContractDeploy._tspec['hashState'] = (True, 11)
    contract.smartContractDeploy._tspec['sourceCode'] = (True, 11)
    contract.smartContractDeploy._tspec['tokenStandard'] = (True, 8)
    contract.smartContractDeploy.hashState = ""
    contract.smartContractDeploy.tokenStandard = 0
    contract.method = ""
    contract.params = []
    contract.usedContracts = []
    contract.forgetNewState = False

    transportOut = TMemoryBuffer()
    protocolOut = TBinaryProtocol(transportOut)
    contract.write(protocolOut)
    scBytes = transportOut.getvalue()

    sMap = '=6s32s32slqhb1s4s' + str(len(scBytes)) +'s' #4s' + str(scriptLength) + 's4s' + str(codeNameLength) + 's4s' + str(codeLength) + 's' #len(userField_bytes)
    serial_transaction_for_sign = pack(sMap,  #'=' - without alignment
                        lastInnerId,     #6s - 6 byte InnerID (char[] C Type)
                        tr.source,       #32s - 32 byte source public key (char[] C Type)
                        tr.target,       #32s - 32 byte target pyblic key (char[] C Type)
                        tr.amount.integral, #i - 4 byte integer(int C Type)
                        tr.amount.fraction, #q - 8 byte integer(long long C Type)
                        tr.fee.commission,  #h - 2 byte integer (short C Type)
                        tr.currency,        #b - 1 byte integer (signed char C Type)
                        ufNum1,
                        bytes(len(scBytes).to_bytes(4, byteorder="little")),
                        scBytes
                        # bytes(scriptLength.to_bytes(4, byteorder="big")),
                        # bytes(contract.smartContractDeploy.sourceCode.encode('utf-8')),
                        # bytes(codeNameLength.to_bytes(4, byteorder="big")), #code name length
                        # bytes(contract.smartContractDeploy.byteCodeObjects[0].name.encode('utf-8')), #code name
                        # bytes(codeLength.to_bytes(4, byteorder="big")), #code length
                        # bytes(contract.smartContractDeploy.byteCodeObjects[0].byteCode) #b - 1 byte userfield_num

                        )            
                       

    # print('Serialized transaction: ', serial_transaction_for_sign.hex().upper())
    senderPKey =  base58check.b58decode(src_priv)
    signing_key = ed25519.SigningKey(senderPKey) # Create object for calulate signing
    tr.signature = signing_key.sign(serial_transaction_for_sign)
    try:
        res = client.TransactionFlow(tr)
    except: 
        sg.Popup('API Message',
         'TimeOut during connection.') # 'The button clicked was "{}"'.format(event), 'The values are', values
        client.close()
        return 
    client.close()
    msg = ''
    try: 
        ls = res.status.message.split(' ')
        msg += ls[0] + ' ' + str(base58check.b58encode(tr.target)).split('\'')[1]
        if(ls[0] == 'Success:'):
            msg += ' deployed'
        else:
            msg += ' not deployed'
    except:
        sg.Popup('Error','Some errors')
    
    if not mul:
        sg.Popup('API Message:', msg)
        print(msg)

    return [res, str(base58check.b58encode(tr.target)).split('\'')[1]]

def deployMultiple(times, src, src_priv, m_fee, contract, uf_text):
    lst = []
    for i in range(0,times):
        res = deployContract(src, src_priv, m_fee, contract, uf_text, True)
        ls = res[0].status.message.split(' ')
        if (ls[0] == 'Success:'):
            lst.append(res[1])
    print('Deployed contracts: ', 'none' if (len(lst) == 0) else '')       
    for a in lst:
        print(a)

    


def getVariant(variant):
    if variant.v_int != None:
        return variant.v_int
    if variant.v_string != None:
        return variant.v_string

def sendContract(src, src_priv, trg, contractMethod, methodParameters, m_fee, uf_text, used_contracts, save_to_bc):
    sUserFields = bytearray()
    client = m_client()
    if client == None:
        return
    tr = api_thrift.Transaction()
    tr.source = base58check.b58decode(src)
    w = client.WalletTransactionsCountGet(tr.source)
    lastInnerId = bytearray((w.lastTransactionInnerId + 1).to_bytes(6,'little'))
    tr.id = int.from_bytes(lastInnerId,byteorder='little', signed=False)
    tr.target = base58check.b58decode(trg)
    tr.amount = api_thrift.general.Amount()
    tr.amount.integral = 0
    tr.amount.fraction = 0
    tr.balance = api_thrift.general.Amount()
    tr.balance.integral = 0
    tr.balance.fraction = 0
    tr.currency = 1
    tr.fee = api_thrift.AmountCommission()
    tr.fee.commission = m_fee
    tr.userFields = uf_text
    tr.smartContract = api_thrift.SmartContractInvocation()
    tr.smartContract.method = contractMethod
    tr.smartContract.forgetNewState = not(save_to_bc)
    tr.smartContract.params = []
    tr.smartContract.usedContracts = []
    tr.smartContract.version = 1
    tr.smartContract._tspec['method'] = (True, 11)
    tr.smartContract._tspec['params'] = (True, 15)
    tr.smartContract._tspec['forgetNewState'] = (True, 2)
    tr.smartContract._tspec['usedContracts'] = (True, (15,11))
    tr.smartContract._tspec['version'] = (True, 6)
    ufNum1 = bytearray(b'\x01')
    paramsLen = len(methodParameters)

    for a in methodParameters:
        for b in methodParameters[a]:
            r = api_thrift.general.Variant()
            if b == 'String':
                r.v_string = methodParameters[a][b]
            if b == 'int':
                r.v_int = methodParameters[a][b]
            if b == 'double':
                r.v_double = methodParameters[a][b]
            tr.smartContract.params.append(r)
        paramsLen -= 1
        if paramsLen == 0:
            break

    if uf_text == '':
        ufNum1.extend(bytearray(b'\x01'))
    else:
        ufNum1.extend(bytearray(b'\x02'))
    csBytes = bytearray()
    csBytes.extend(b'\x0b\x00\x01')
    if contractMethod == '':
        csBytes.extend(b'\x00\x00\x00\x00')
    else:
        csBytes.extend(len(contractMethod).to_bytes(4, byteorder="big")) #VVV
        csBytes.extend(bytearray(contractMethod.encode('utf-8')))

    # contract parameters    
    if len(tr.smartContract.params) == 0:
        csBytes.extend(b'\x0f\x00\x02\x0c\x00\x00\x00\x00')
    else:
        csBytes.extend(b'\x0f\x00\x02\x0c')
        csBytes.extend(len(tr.smartContract.params).to_bytes(4, byteorder="big"))
        for a in methodParameters:
            if a != 'status_':
                for aa in methodParameters[a]:
                    if(aa == 'String'):
                        csBytes.extend(b'\x0b\x00\x11')
                        csBytes.extend(len(methodParameters[a][aa]).to_bytes(4, byteorder="big"))
                        csBytes.extend(bytearray(methodParameters[a][aa].encode('utf-8')))
                        csBytes.extend(b'\x00')
                    elif(aa == 'double'):
                        csBytes.extend(b'\x04\x00\x0f')
                        csBytes.extend(bytearray(struct.pack("d",(methodParameters[a][aa]))))
                        csBytes.extend(b'\x00')
                    elif(aa== 'int'):
                        csBytes.extend(b'\x08\x00\x09')
                        csBytes.extend(bytearray((methodParameters[a][aa]).to_bytes(4, byteorder="big")))
                        csBytes.extend(b'\x00')
                    elif(aa == 'boolean'):
                        if(methodParameters[a][aa]):
                            csBytes.extend(b'\x02\x00\x03\x01\x00')
                        else:
                            csBytes.extend(b'\x02\x00\x03\x00\x00')
    # used contracts
    if len(used_contracts) == 0:
        csBytes.extend(b'\x0f\x00\x03\x0b\x00\x00\x00\x00')
    else:
        csBytes.extend(b'\x0f\x00\x03\x0c')
        csBytes.extend(len(used_contracts).to_bytes(4, byteorder="little"))

    # forget new state
    if save_to_bc:
        csBytes.extend(b'\x02\x00\x04\x00')
    else:
        csBytes.extend(b'\x02\x00\x04\x01')

    csBytes.extend(b'\x06\x00\x06')
    csBytes.extend(bytearray(tr.smartContract.version.to_bytes(2, byteorder="big"))) #VVV
    csBytes.extend(b'\x00')

    sMap = '=6s32s32slqhb1s4s' + str(len(csBytes)) +'s' #4s' + str(scriptLength) + 's4s' + str(codeNameLength) + 's4s' + str(codeLength) + 's' #len(userField_bytes)
    serial_transaction_for_sign = pack(sMap,  #'=' - without alignment
                        lastInnerId,     #6s - 6 byte InnerID (char[] C Type)
                        tr.source,       #32s - 32 byte source public key (char[] C Type)
                        tr.target,       #32s - 32 byte target pyblic key (char[] C Type)
                        tr.amount.integral, #i - 4 byte integer(int C Type)
                        tr.amount.fraction, #q - 8 byte integer(long long C Type)
                        tr.fee.commission,  #h - 2 byte integer (short C Type)
                        tr.currency,        #b - 1 byte integer (signed char C Type)
                        ufNum1,
                        bytes(len(csBytes).to_bytes(4, byteorder="little")),
                        csBytes
    )
    print(serial_transaction_for_sign.hex())
    senderPKey = base58check.b58decode(src_priv)
    signingKey = ed25519.SigningKey(senderPKey) # Create object for calulate signing
    tr.signature = signingKey.sign(serial_transaction_for_sign)
    try:
        res = client.TransactionFlow(tr)
    except res: 
        sg.Popup('API Message',
         'TimeOut during connection.') # 'The button clicked was "{}"'.format(event), 'The values are', values
        client.close()
        return 
    client.close()
    msg = ''
    try: 
        ls = res.status.message.strip()
        msg += (ls if len(ls) > 0 else str(base58check.b58encode(tr.target)).split('\'')[1] + ' executed')
        if res.smart_contract_result != None:
            msg += ' Result: ' + str(getVariant(res.smart_contract_result))
    except:
        sg.Popup('Error','Some errors')
    
    sg.Popup('API Message:', msg)
    print(msg)
    return res

def createContractAddress(source, tId, contract):
    tmpBytes = bytearray()
    tmpBytes.extend(source)
    tmpBytes.extend(tId)
    for a in contract.smartContractDeploy.byteCodeObjects:
        tmpBytes.extend(a.byteCode)
    res = hashlib.blake2s()
    res.update(tmpBytes)
    return res.digest()

def get_balance(sKey):
    #signing_key = ed25519.SigningKey(senderPKey) # Create object for calulate signing
    client = m_client()
    if client == None:
        return None
    res = client.WalletBalanceGet(sKey)
    client.close()
    return res

def get_tokens(sKey):
    client = m_client()
    if client == None:
        return None
    res = client.TokenBalancesGet(sKey)
    client.close()
    return res


def get_contracts():
    client = m_client()
    if client == None:
        return None
    res = client.SmartContractsListGet()
    client.close()
    return res

def get_transactions(n):
     #signing_key = ed25519.SigningKey(senderPKey) # Create object for calulate signing
    client = m_client()
    if client == None:
        return None
    res = client.TransactionsListGet(n)
    client.close()
    return res

def parseUserFields(ufText, delegate_check, delegate, withdraw, date):
    ufBytes = bytearray(b'\x00')            
    ufBytes.extend(b'\x01')    # number of user fields
    sfBytes = bytearray(b'\x01')  # number of user fields
    tmpBytes = bytearray()
    sLen = 0
    mTrx = False
    if len(ufText) > 0: #adding string uf(1)
        ufBytes.extend(b'\x01\x00\x00\x00') # text user field
        ufBytes.extend(b'\x02')             # ufType = string 
        tm = bytearray(ufText.encode('utf-8'))
        tmpBytes.extend(tm)

    if len(tmpBytes):
        ufBytes.extend(len(tmpBytes).to_bytes(4, byteorder="little"))
        sfBytes.extend(len(tmpBytes).to_bytes(4, byteorder="little"))
        ufBytes.extend(tmpBytes)
        sfBytes.extend(tmpBytes)

    if delegate_check and not mTrx:
        ufBytes.extend(b'\x05\x00\x00\x00') # ufID delegate transaction
        ufBytes.extend(b'\x01')             # ufType = unsigned integet 64 bits
        if delegate:
            if date == 0:
                val = 1
                tmpBytes.extend(val.to_bytes(8, byteorder="little"))
            else:
                if date < 3:
                    date += 2 #free first three values as keys (0, 1, 2)
                tmpBytes.extend(date.to_bytes(8, byteorder="little"))
        elif withdraw:
                val = 2
                tmpBytes.extend(val.to_bytes(8, byteorder="little"))
        ufBytes.extend(tmpBytes)
        sfBytes.extend(tmpBytes)

    return [ufBytes, sfBytes]

def print_balance(sKey, isCurrent):
    curs = []
    wInfo = get_balance(sKey)
    if wInfo == None:
        res = 'Connection error'
        return res
    zLen = 18 - len(str(wInfo.balance.fraction))
    res = ''
    if isCurrent:
        res = res + 'Current balance:'
    else:
        res + res + ''.join('{:02x}'.format(x).upper() for x in sKey)
    res = res + ''.join(str(wInfo.balance.integral) + "." + str(wInfo.balance.fraction).zfill(18))
    tokenInfo = get_tokens(sKey)
    if tokenInfo == None:
        res = 'Connection error'
        return res
    if len(tokenInfo.balances) > 0:
        res = res + '\nTokens:'
    for bal in tokenInfo.balances:
        # res + res + ''.join('{:02x}'.format(x).upper() for x in sKey)
        res = res + '\n' + bal.code + '\t\t' + str(bal.balance)
        curs.append(bal.code)
    # updateCurrecyList(curs)
    return res

def walletTransactions(src):
    client = make_client(api_thrift.API, node_address, port)
    w = client.WalletTransactionsCountGet(src)
    return w

def getBlock(seq):
    client = make_client(api_thrift.API, node_address, port)
    res = client.WalletBalanceGet(sKey)
    client.close()
    return res

def getLastTransactions(addr):
    client = m_client()
    if client == None:
        return None
    res = client.TransactionsGet(addr, 0 ,20)
    client.close()
    return res

def getWalletData(addr):
    client = make_client(api_thrift.API, node_address, port)
    res = client.WalletDataGet(addr)
    client.close()
    #print('Standard Balance: ', ''.join(str(res.walletData.balance.integral) + "." + str(res.walletData.balance.fraction).zfill(18)))
    #client_diag = make_client(apidiag_thrift.API_DIAG, node_address, 9060)
    #try:
    #    res1 = client_diag.GetWalletData(addr) # here the programm shuts down!!!
    #except: 
    #    sg.Popup('API Message',
    #     '.') # 'The button clicked was "{}"'.format(event), 'The values are', values
    #    return
    #client_diag.close()
    return res

def getPool(seq):
    client = m_client()
    if client == None:
        return None
    res = client.PoolInfoGet(seq)
    client.close()
    return res

def getTransaction_(seq, idx):
    tId = api_thrift.TransactionId()
    tId.poolSeq = seq
    tId.index = idx
    client = m_client()
    if client != None:
        res = client.TransactionGet(tId)
        client.close()
    else:
        res = None
    return res

def translate(item):
    it = node_dict_[item] if item in node_dict_ else item
    it = node_dict_base58_[item] if item in node_dict_base58_ else it
    return it

def getTransaction(seq, ind):
    tId = api_thrift.TransactionId()
    tId.poolSeq = seq
    tId.index = ind
    client = diag_client()
    res = client.TransactionGet(tId)
    client.close()
    return res

def getWallets():
    client = make_client(api_thrift.API, node_address, port)
    res = client.WalletsGet(0, 10 ,0 , True)
    client.close()
    return res

def currentContracts():
    lst = []
    addresses = []
    if len(sourceKey) == 32:
        if getUserContracts(sourceKey):
            lst.extend(getUserContracts(sourceKey).smartContractsList)
        for a in lst:
            addresses.append(str(base58check.b58encode(bytes(a.address))).split('\'')[1])
    return addresses 

def readDateInput(raw_date):
    date = 0
    if raw_date == '':
        date = 0
    else:
        date = int(time.mktime(time.strptime(raw_date, '%Y-%m-%d %H:%M:%S')))
    return date
# reverse: m =  time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(date))

def ms_to_hms(value):
    hours, remainder = divmod(value / 1000, 3600)
    minutes, seconds = divmod(remainder, 60)
    return '{:02}:{:02}:{:02}'.format(int(hours), int(minutes), int(seconds))

def parse_platform(value):
    if value == 2:
        return 'Windows'
    if value == 1:
        return 'MacOS'
    return 'Linux'

def compile(contract_body):
    client = m_client()
    if client == None:
        return None
    res = client.SmartContractCompile(contract_body)
    client.close()
    return res

def getAllContracts():
    client = m_client()
    if client == None:
        return None
    res = client.SmartContractsAllListGet(0, 20)
    client.close()
    for a in res.smartContractsList:
        sm = base58check.b58encode(a.address).decode('ASCII')
        dep = base58check.b58encode(a.deployer).decode('ASCII')
        print(sm,'\t', dep, '\t', a.transactionsCount)
    return res

def deployersContracts(pKey):
    client = m_client()
    if client == None:
        return None
    res = client.SmartContractAddressesListGet(pKey)
    client.close()
    return res


def getUserContracts(sKey):
    client = m_client()
    if client == None:
        return None
    res = client.SmartContractsListGet(sKey,0, 50)
    client.close()
    return res

def getContractMethods(contract_address):
    contract = getContract(contract_address)
    client = m_client()
    if client == None:
        return None
    res = client.ContractAllMethodsGet(contract.smartContract.smartContractDeploy.byteCodeObjects)
    return res

def getContract(sample):
    client = m_client()
    if client == None:
        return None
    addr = base58check.b58decode(sample)
    res = client.SmartContractGet(addr)
    client.close()
    return res

def getBlocks():
    client = m_client()
    if client == None:
        return None
    res = client.PoolListGet(0, 500)
    client.close()
    return res

def getBlockTransactions():
    client = m_client()
    if client == None:
        return None
    res = client.PoolTransactionsGet(99, 0, 500)
    client.close()
    return res

def normalizeCode(javaText):
    javaText = javaText.replace('\r', ' ').replace('\t', ' ').replace('{', ' {')
    while '  ' in javaText:
        javaText = javaText.replace('  ', ' ')
    return javaText

def getMethodParameters(args):
    argsResult = []
    argsTmp = (args.split('(')[1]).replace(')','')
    if argsTmp == '':
        return argsResult
    argsOnly = argsTmp.split(', ')
    if(len(argsOnly) == 0):
        return argsResult


wallet_col3 = [
    [sg.Checkbox('Additional:', enable_events=True, key = 'check_box_delegate')
     ],
    [sg.Radio('Delegate', "RAD01", default=True, disabled=True, key = 'r1_delegate')
     ],
    [sg.Radio('Withdraw Delegated', "RAD01" , disabled=True, key = 'r1_withdraw')
    ],
    [sg.Radio('Release Delegated', "RAD01", disabled=True, key = 'r1_04')
     ],
    [sg.InputText(size=(18,1), key='date_input', disabled=True, default_text = settings_['last_delegated_date']), sg.CalendarButton('Pick Date', target='date_input', key='date', disabled=True)
     ]
]

wallet_col2 = [
    [sg.InputText(size=(50,1), key='key_file_name', default_text = settings_['last_key_file']), sg.FileBrowse(enable_events = True), sg.Button('Apply', key='public_open')
     ],
    [sg.InputText(default_text = src, size=(50,1), key='source_public_key'), #sender
     ],
    [sg.InputText(default_text = settings_['last_target'], size=(50,1), key='target') #target base58
     ],
    [sg.InputText(default_text = settings_['last_amount'], size=(30,1), key='amount') #Amount
     ],
    [sg.Combo(values = [], size=(30,1), enable_events=True, key = 'choose_currency')
     ],
    [sg.InputText(default_text = settings_['last_fee'], size=(30,1), key='fee'), sg.Text('', size=(20,1), key='actual_comission'), sg.Button('Actual fee')#Fee
     ],
    [sg.InputText(default_text = settings_['last_uf'], size=(50,3), key='user_fields') #UserFields
     ],    
]

wallet_col1 = [
    [sg.Text('Sender keys File:')
     ],
    [sg.Text('Sender:')
     ],
    [sg.Text('Target ') 
     ],
    [sg.Text('Amount ') 
     ],
    [sg.Text('Currency ') 
     ],
    [sg.Text('Max Fee')
     ],
    [sg.Text('User Fields')
     ],
]

wallet_layout = [
    [sg.Column(wallet_col1), sg.Column(wallet_col2) , sg.VerticalSeparator(pad=None), sg.Column(wallet_col3)
     ],
    [sg.Submit(), sg.Button('Check balance') 
     ]
]

tab2_1_layout = [
    [sg.Text('Under Construction')
     ],
]

col2_2_1 = [
    [sg.Text('Fields to be displayed:') 
     ], 
    [sg.Checkbox('Source', default = True, key = 'check_box_tr_source')
     ],
    [sg.Checkbox('Amount', default = True, key = 'check_box_tr_amount') 
     ],
    [sg.Checkbox('Currency', default = True, key = 'check_box_tr_currency')
    ]
]

col2_2_2 = [
    [sg.Checkbox('Trx ID', default = True, key = 'check_box_tr_id')
     ], 
    [sg.Checkbox('Target', default = True, key = 'check_box_tr_target')
     ],
    [sg.Checkbox('Counted Fee', default = True, key = 'check_box_tr_fee')
     ], 
    [sg.Checkbox('User Fields', default = True, key = 'check_box_tr_uf')
     ]
]

col2_2_3 = [
    [sg.Button('Get Transactions')
     ],
    [sg.Checkbox('Hex:', default = False, key = 'check_box_tr_hex')
     ]
]
tab2_2_layout = [
    [sg.Column(col2_2_1), sg.Column(col2_2_2), sg.VerticalSeparator(), sg.Column(col2_2_3)
     ]
]

col2_3_1 = [
    [sg.Text('Fields to be displayed:') 
     ], 
    [sg.Checkbox('Balance:', default = True, key = 'check_box_wa_05')
     ],
    [sg.Checkbox('Delegated:', default = True, key = 'check_box_wa_06') 
     ],
    [sg.Checkbox('Delegats:', default = True, key = 'check_box_wa_07')
    ]
]

col2_3_2 = [
    [sg.Checkbox('Wallet ID:', default = True, key = 'check_box_wa_01')
     ], 
    [sg.Checkbox('Public Key:', default = True, key = 'check_box_wa_02')
     ],
    [sg.Checkbox('Last trx No:', default = True, key = 'check_box_wa_03')
     ], 
    [sg.Checkbox('Tail:', default = True, key = 'check_box_wa_04')
     ]
]

tab2_3_layout = [
    [sg.Column(col2_3_1), sg.Column(col2_3_2), sg.VerticalSeparator()
     ]
]

col2_4_1 = [
    [sg.Text('Info to request:') 
     ], 
    [sg.Checkbox('State:', default = True, key = 'chk_node_state')
     ],
    [sg.Checkbox('Gray list:', default = True, key = 'chk_node_gray') 
     ],
    [sg.Checkbox('Block list:', default = True, key = 'chk_node_black')
    ]
]

col2_4_2 = [
    [sg.Checkbox('Session stat:', default = True, key = 'chk_node_session')
     ]
]

col2_4_3 = [
    [sg.Button('Get info')
     ],
    [sg.Checkbox('Hex:', default = False, key = 'check_box_gi_hex')
     ]
]

tab2_4_layout = [
    [sg.Column(col2_4_1), sg.Column(col2_4_2), sg.VerticalSeparator(), sg.Column(col2_4_3)
     ]
]

tab2_layout = [
    [sg.Text('Input: '), sg.InputText(size=(50,1), default_text=settings_['last_search'], key = 'value_input'), sg.Button('Go', key='go')
     ],
    [sg.TabGroup([[sg.Tab('Transactions', tab2_2_layout), sg.Tab('Accounts', tab2_3_layout)]], key = 'tab_sel')
     ]
]

tab_settings_layout = [
    [sg.Text('Connection settings: ')
     ],
    [sg.Text('Standard API (IP:Port)  : '), sg.InputText(size=(15,1), default_text=settings_['API_host'], key='ip'), sg.Text('Port: ')
    , sg.Text(size=(5,1), text=str(port), key ='port'), sg.Text('Description: '), sg.InputText(size=(20,1), key='con_description')
     ],
    [sg.Button('Apply', key='apply_settings'), sg.Button('Save', key='save_settings'), sg.FileBrowse(enable_events = True, key='settings_open')
     ],
    [sg.Combo(themes, default_value=current_theme, key='theme_change', enable_events=True)
     ],
]

tab_contracts_layout = [
    [sg.Button('New contract', key ='new_contract')
     ],
    [sg.Button('Find contract', key='find_contract', size=(20,1)), sg.InputText(size=(50,1), key = 'name_find_contract'), sg.Checkbox('Show all account\'s contracts', key ='all_contracts')
     ],
    [sg.Text('Choose contract: ', size = (20,1)), sg.Combo(values = [], size=(50,1), disabled=True, enable_events=True, key = 'value_input_contracts')
     ],
    [sg.Text('Chosen contract: ',size = (20,1)), sg.Text(size = (50,1), key = 'chosen_contract_key')         
     ], 
    [sg.Text('Method:  ', size = (20,1)), sg.Combo(values = [], disabled=True, size=(50,1), key = 'value_input_method', enable_events=True), sg.Button('Parameters', key = 'contract_parameters',  disabled=True)
     ],
    [sg.Text('Fee:', size = (20,1)), sg.InputText(size=(20,1), key = 'contract_fee', disabled=True), sg.Checkbox('Save to BC', key ='save_bc', disabled = True), sg.Button('Execute', key = 'execute_contract', disabled=True)
     ]
]
#sg.Button('Build', key = 'build_contract'),sg.Button('Deploy', key='deploy_contract'), sg.Button('Open', key='open_contract'), sg.Button('Adjust', 'adjust_execution'), 

main_layout = [
    [sg.Text('Current Account: '), sg.Text('', size=(50,1), key='current_account')
     ],
    [sg.TabGroup([[sg.Tab('Wallet', wallet_layout), sg.Tab('Check', tab2_layout), sg.Tab('Contracts', tab_contracts_layout), sg.Tab('Settings', tab_settings_layout)]])
     ],
    [sg.Output(size=(130, 20), key='out1')
     ],
    [sg.Button('Save'), sg.Button('Store Fields', key='store_fields'), sg.Button('Clear'), sg.Text('', size=(86,1), key ='status'),sg.Cancel()
     ]
]

initilizeCurrecyList()
window = sg.Window('Wallet', main_layout)



#preset window elements


while True:                             # The Event Loop
    event, values = window.read()
    if event in (None, 'Exit', 'Cancel'):
        with open("settings.json", "w") as settings_file:
            json.dump(settings_, settings_file)
        settings_file.close()
        break

    if event == 'check_box_delegate':
        if(values['check_box_delegate'] == True):
            print('Delegating transaction mode switched ON')
            window.FindElement('r1_delegate').Update(disabled=False)
            window.FindElement('r1_withdraw').Update(disabled=False)
            window.FindElement('date').Update(disabled=False)
            window.FindElement('date_input').Update(disabled=False)
        else:
            print('Delegating transaction mode switched OFF')
            window.FindElement('r1_delegate').Update(disabled=True)
            window.FindElement('r1_withdraw').Update(disabled=True)
            window.FindElement('date').Update(disabled=True)
            window.FindElement('date_input').Update(disabled=True)

    if event in ('Get Accounts'):

        res = getWallets()
        if res:
            for a in res.wallets:
                if values['check_box_wa_hex']:
                    print((a.address if type(a.address)!=str else a.address.encode()).hex(), '\t\t', ''.join(str(a.balance.integral) + "." + str(a.balance.fraction).zfill(18)))
                else:
                    tmp = str(base58check.b58encode(a.address if type(a.address)!=str else a.address.encode())).split('\'')[1]
                    print(tmp, '\t\t', ''.join(str(a.balance.integral) + "." + str(a.balance.fraction).zfill(18)))
        else:
            print('No wallets')

    if event in ('Get Blocks'):
        getBlocks()

    if event in ('public_open'):
        if values['key_file_name']:
            rff = open(values['key_file_name'], 'r')
            #line = rff.readline()
            pkey_dct = json.load(rff)
            src = pkey_dct['key']['public'] 
            src_priv = pkey_dct['key']['private']
            sourceKey = base58check.b58decode(src)
            sourcePrivKey =  base58check.b58decode(src_priv)
            window.FindElement('source_public_key').Update(src)
            window.FindElement('current_account').Update(src)
            initilizeCurrecyList()
            window.FindElement('choose_currency').Update(values = currencies)

    if event in ('save_settings'):
        print('Saving settings - under construction: no result now')

    if event in ('apply_settings'):
        r = values['ip'].split(':')
        if len(r)> 2 or len(r) == 0:
            sg.Popup('Warning','Not correct IP Address or port')
            continue
        temp_list = r[0].split('.')
        cnt = 0
        for a in temp_list:
            try:
                p = int(a)
            except:
                continue
            cnt += 1
        if cnt != 4:
            sg.Popup('Warning','Not correct IP Address')
            continue
        node_address =  r[0]

        port = 0
        if len(r) == 1:
            port = 9090
        else :
            try:
                port = int(r[1])
            except:
                sg.Popup('Warning','Not correct Port')
                continue
            window.FindElement('port').Update(str(port))

 
    if event in ('Clear'):
        window.FindElement('out1').Update('')

    if event in ('Submit'):
        ub = bytearray()
        us = bytearray()
        # if values['choose_currency'] != 'CS':
        #     sendToken()
        if values['user_fields'] or values['check_box_delegate']:
            date = readDateInput(values['date_input'])
            lst = parseUserFields(values['user_fields'], values['check_box_delegate'], values['r1_delegate'], values['r1_withdraw'], date)
            ub.extend(lst[0])
            us.extend(lst[1])
            print('UF:  ', ub.hex())
            print('UFS: ', us.hex())
        if values['target'] and values['amount'] and values['fee']:
            trg = values['target']
            amt = values['amount']
            aInteger = 0
            aFraction = 0
            if '.' in amt:
                amount = amt.split('.')
                aInteger = int(amount[0])
                aFraction = int(str(amount[1]).ljust(18, '0'))
            elif ',' in amt:
                amount = amt.split(',')
                aInteger = int(amount[0])
                aFraction = int(str(amount[1]).ljust(18, '0'))
            else:
                aInteger = int(amt)
                aFraction = int(str('').ljust(18, '0'))

            print('Sending: ', ''.join(str(aInteger) + "." + str(aFraction).zfill(18)), 'to target:', trg, end='')
            try:
                fee = float(values['fee'])
            except:
                sg.Popup('Error', 'Fee value can\'t be read')
                continue
            print(', Max Fee:', fee)
            m_fee = double_to_fee(fee)
            result = sendAmount(src, src_priv, trg, aInteger, aFraction, m_fee, ub, us) 
  
    if event in ('theme_change'):
        sg.theme(values['theme_change'])
        sg.Popup('Info','Choosen layout will be applied after restart')
        settings_['theme'] = values['theme_change']
  
    if event in ('go'):
        if(window["tab_sel"].get() == 'Pools'):
            seq = int(values['value_input'])
            getPool(seq)

        if(window["tab_sel"].get() == 'Transactions'):
            if(not values['value_input']):
                sg.Popup('Warning','Can\'t find transaction without number')
                continue
            temp_list = values['value_input'].split('.')
            if(len(temp_list) != 2):
                sg.Popup('Warning','Not correct transaction ID')
                continue
            seq = int(temp_list[0])
            index = int(temp_list[1])
            res = getTransaction_(seq, index)
            output_string = 'Transaction'
            if res != None:
      
                if values['check_box_tr_id']:
                     output_string += ' #' +  str(res.transaction.id)

                if values['check_box_tr_amount']:
                    output_string +=  ', amount: ' + ''.join(str(res.transaction.sum.amount.integral) + "." + str(res.transaction.sum.amount.fraction).zfill(18))
                
                if values['check_box_tr_fee']:
                    output_string += ', max Fee: ' + str(res.transaction.max_fee.value) + '(' + str(res.transaction.max_fee.bits) + ')'

                output_string += ', Time: ' +  str(res.transaction.timestamp)
                if values['check_box_tr_source']:
                    tsource = bytearray()
                    if (type(res.transaction.source) != type('str')) :
                        tsource.extend(res.transaction.source)
                    else:
                        tsource.extend(bytes(res.transaction.source, 'utf-8'))
                    output_string += '\nSource: '  + str(tsource.hex()).upper()

                if values['check_box_tr_target']: 
                    ttarget = bytearray()
                    if (type(res.transaction.target) != type('str')) :
                        ttarget.extend(res.transaction.target)
                    else:
                        ttarget.extend(bytes(res.transaction.target, 'utf-8'))
                    output_string += '\nTarget: ' + str(ttarget.hex()).upper()

                uf_type = ''
                if res.transaction.userFields and values['check_box_tr_uf']:
                    for uf in res.transaction.userFields:
                        if uf.data.amount != None:
                            uf_type += 'amount: ' + str(uf.amount.data.integral) + '.' + str(amount.fraction)
                        if uf.data.bytes != None:
                            uf_type += 'bytes: ' + str(uf.data.bytes)
                        if uf.data.amount != None:
                            uf_type += 'amount: ' + str(uf.data.integer)
                        output_string +=  '\nUser Fields: id = ' + str(uf.id) + ': ' + uf_type
                
            else:
                output_string += ' not found'
            print(output_string)
          
        if(window["tab_sel"].get() == 'Accounts'):
            myAccount = False
            if values['value_input']:
                sKey = base58check.b58decode(values['value_input'])
            else:
                sKey = sourceKey
                myAccount = True
            wData = getWalletData(sKey)
        # if wData == Null:
            #    continue
            if wData != None:
                if myAccount:
                    print('Account: ', src)
                else:
                    print('Account: ', values['value_input'])
                prec = 3
                print('\tLast transaction:', wData.walletData.lastTransactionId) #'Wallet ID: ', wData.walletData.walletId, 
                print('\tBalance: ', ''.join(str(wData.walletData.balance.integral) + "." + str(wData.walletData.balance.fraction).zfill(18)[:prec]))
                if wData.walletData.delegated != None:
                    print('\tDelegations: ')
                    print('\t\tincoming: ' + ''.join(str(wData.walletData.delegated.incoming.integral) + "." + str(wData.walletData.delegated.incoming.fraction).zfill(18)[:prec]))
                    if wData.walletData.delegated.incoming.integral != 0 or wData.walletData.delegated.incoming.fraction != 0:
                        for r in wData.walletData.delegated.donors:
                            print('\t\t\t' + (str(r.sum.integral)) + '.' + str(r.sum.fraction).zfill(18)[:prec] +
                             ' <- ' + str(base58check.b58encode(r.wallet)).split('\'')[1])
                    print('\t\toutgoing: ' + ''.join(str(wData.walletData.delegated.outgoing.integral) + "." + str(wData.walletData.delegated.outgoing.fraction).zfill(18)[:prec]))
                    if wData.walletData.delegated.outgoing.integral != 0 or wData.walletData.delegated.outgoing.fraction != 0:
                        for r in wData.walletData.delegated.recipients:
                            print('\t\t\t' + (str(r.sum.integral)) + '.' + str(r.sum.fraction).zfill(18)[:prec] +
                             ' -> ' + str(base58check.b58encode(r.wallet)).split('\'')[1])
                else:
                    print('\tDelegations: none')
            else:
                print('\tNo wallet data')

    if event in ('Get Transactions'):
        if(not values['value_input']):
            sg.Popup('Warning','Can\'t find transaction without sender address')
            continue
        try:
            addr = base58check.b58decode(values['value_input'])
        except:
            sg.Popup('Warning','Incorrect address')
            continue
        res = getLastTransactions(addr)
        if res:
            for a in res.transactions:
                transaction_str = '#'

                if values['check_box_tr_hex']:
                    print(a.id.poolSeq, '.', a.id.index, '\t\t',(a.trxn.source if type(a.trxn.source)!=str else a.trxn.source.encode()).hex(), '\t\t', ''.join(str(a.trxn.amount.integral) + "." 
                    + str(a.trxn.amount.fraction).zfill(18)) + ' UF: ' + ('' if a.trxn.userFields == None else str(a.trxn.userFields)))
                else:
                    tmp = str(base58check.b58encode(a.trxn.source if type(a.trxn.source)!=str else a.trxn.source.encode())).split('\'')[1]
                    print(a.id.poolSeq, '.', a.id.index, '\t\t',tmp, '\t\t', ''.join(str(a.trxn.amount.integral) + "." 
                    + str(a.trxn.amount.fraction).zfill(18)) + ' UF: ' + ('' if a.trxn.userFields == None else str(a.trxn.userFields)))

    if event in ('Actual fee'):
        try:
            afee = float(values['fee'])
        except:
            sg.Popup('Warning','Incorrect floating point value')
            continue
        ifee = double_to_fee(afee)
        window.FindElement('actual_comission').Update(str(fee_to_double(ifee)))

    if event in ('Check balance'):
        #sg.Print = sg.Window.FindElement(key = 'out1')
        print(print_balance(sourceKey, True))
        window.FindElement('choose_currency').Update(values = currencies)

    if event in ('store_fields'):
        settings_['theme'] = values['theme_change']
        settings_['API_host'] = values['ip']
        settings_['Diag_API_host'] = values['ip_diag']
        settings_['last_key_file'] = values['key_file_name']
        settings_['last_target'] = values['target']
        settings_['last_amount'] = values['amount']
        settings_['last_fee'] = values['fee']
        settings_['last_uf'] = values['user_fields']
        settings_['last_search'] = values['value_input']
        settings_['last_delegated_date'] = values['date_input']

    if event in ('find_contract'):
        lst = []
        if values['all_contracts']:
            allContracts = getUserContracts(sourceKey)
            if len(allContracts.smartContractsList) == 0:
                continue
            for a in allContracts.smartContractsList:
                lst.append(str(base58check.b58encode(a.address if type(a.address)!=str else a.address.encode())).split('\'')[1])
        else:
            if values['name_find_contract'] !='':
                contract = getContract(values['name_find_contract'])
                if contract.smartContract == None or contract.smartContract.address == '' :
                    continue   
                lst.append(str(base58check.b58encode(contract.smartContract.address if type(contract.smartContract.address)!=str else contract.smartContract.address.encode())).split('\'')[1])
            else:
                continue



        window.FindElement('value_input_contracts').Update(values = lst, disabled = False)
        if(values['value_input_contracts'] != ''):
            window.FindElement('chosen_contract_key').Update(values['value_input_contracts'])
            mList = getContractMethods(values['value_input_contracts'])
            refinedMethods = []
            for a in mList.methods:
                refinedMethods.append(a.name + '()')

        # window.FindElement('value_input_method').Update(values = refinedMethods, disabled = False) #insert elements in dropping list

    if event in ('value_input_contracts'):
        if(values['value_input_contracts'] != ''):
            current_contract_parameters.clear()
            window.FindElement('chosen_contract_key').Update(values['value_input_contracts'])
            mList = getContractMethods(values['value_input_contracts'])
            refinedMethods = []
            for a in mList.methods:
                oneMethod = a.returnType.replace('java.lang.','') + ' ' + a.name + '('
                argCount = 0
                for arg in a.arguments:
                    if argCount > 0:
                        oneMethod += ', '
                    oneMethod += arg.type.replace('java.lang.','') + ' ' + arg.name
                    argCount += 1
                oneMethod += ')'
                refinedMethods.append(oneMethod)
            if len(refinedMethods) > 0:
                window.FindElement('value_input_method').Update(values = refinedMethods,  disabled = False)
                tmp = refinedMethods[0]
                if '(' in tmp:
                    argsOnly = (tmp.split('(')[1]).replace(')','')
                    if(len(argsOnly) > 0):
                        window.FindElement('contract_parameters').Update(disabled = False)
                        window.FindElement('contract_fee').Update(disabled = True)
                        window.FindElement('execute_contract').Update(disabled = True)
                        window.FindElement('save_bc').Update(disabled = True)
                    else:
                        window.FindElement('contract_parameters').Update(disabled = True)
                        window.FindElement('contract_fee').Update(disabled = False)
                        window.FindElement('execute_contract').Update(disabled = False)
                        window.FindElement('save_bc').Update(disabled = False)

    if event in ('value_input_method'):
        current_contract_parameters.clear()
        tmp = values['value_input_method']
        if '(' in tmp:
            argsOnly = (tmp.split('(')[1]).replace(')','')
            if(len(argsOnly) > 0):
                window.FindElement('contract_parameters').Update(disabled = False)
                window.FindElement('contract_fee').Update(disabled = True)
                window.FindElement('execute_contract').Update(disabled = True)
                window.FindElement('save_bc').Update(disabled = True)
            else:
                window.FindElement('contract_parameters').Update(disabled = True)
                window.FindElement('contract_fee').Update(disabled = False)
                window.FindElement('execute_contract').Update(disabled = False)
                window.FindElement('save_bc').Update(disabled = False)

    if event in ('new_contract'):
        layout_contract_new = [
            [sg.Multiline(size=(130, 20), key='contract_body', enable_events = True)
             ],
            [sg.Button('Build', key = 'build_contract', disabled = True), sg.Text('Fee:'), sg.InputText(size=(20,1), disabled = True, key = 'deploy_fee'), sg.Button('Deploy', disabled = True, key = 'deploy_contract'), sg.Text('Deploy Times:'), sg.InputText(size=(20,1), disabled = True, key = 'times_deploy'), sg.Button('Deploy Multiple', disabled = True, key = 'deploy_multiple')
             ]
        ]
        win_contracts = sg.Window('New Contract' , layout_contract_new)
        contract = api_thrift.SmartContractInvocation()
        contract.smartContractDeploy = api_thrift.SmartContractDeploy()

        while True:                             # The Event Loop
            ev2, val2 = win_contracts.read()
            if ev2 in (None, 'Exit', 'Cancel'):
                break

            if ev2 in ('contract_body'):
                if val2['contract_body'] != '':
                    win_contracts.FindElement('build_contract').Update(disabled=False)
                    win_contracts.FindElement('deploy_contract').Update(disabled=True)
                    win_contracts.FindElement('deploy_fee').Update(disabled=True)
                    win_contracts.FindElement('times_deploy').Update(disabled=True)
                    win_contracts.FindElement('deploy_multiple').Update(disabled=True)

            if ev2 in('deploy_contract'):
                if val2['deploy_fee'] != '':
                    try:
                        fee = float(val2['deploy_fee'])
                    except:
                        sg.Popup('Error', 'Fee value can\'t be read')
                        continue
                    m_fee = double_to_fee(fee)
                    uf_text = ''
                    deployContract(src, src_priv, m_fee, contract, uf_text, False)
                    win_contracts.Close()
                else:
                    sg.Popup('Info','Without fee the contract can\'t be deployed')
            
            if ev2 in('deploy_multiple'):
                if val2['deploy_fee'] != '':
                    try:
                        fee = float(val2['deploy_fee'])
                    except:
                        sg.Popup('Error', 'Fee value can\'t be read')
                        continue
                    m_fee = double_to_fee(fee)
                    uf_text = ''
                    times = int(val2['times_deploy'])
                    deployMultiple(times,src, src_priv, m_fee, contract, uf_text)
                    win_contracts.Close()
                else:
                    sg.Popup('Info','Without fee the contract can\'t be deployed')

            if ev2 in('build_contract'):
                contractText = val2['contract_body']
                contractText = normalizeCode(contractText)
                result = compile(contractText)
                print(result.status.message)
                if "Success" not in result.status.message:
                    sg.Popup('Info','Contract can\'t be build correctly. Check it more careflly')
                    continue
                if len(result.byteCodeObjects) == 0:
                    sg.Popup('Info','Contract can\'t be build correctly. Check it more careflly')
                    continue
                else:
                    win_contracts.FindElement('build_contract').Update(disabled=True)
                    win_contracts.FindElement('deploy_contract').Update(disabled=False)
                    win_contracts.FindElement('deploy_fee').Update(disabled=False)
                    win_contracts.FindElement('times_deploy').Update(disabled=False)
                    win_contracts.FindElement('deploy_multiple').Update(disabled=False)
                    contract.smartContractDeploy.byteCodeObjects = result.byteCodeObjects
                    contract.smartContractDeploy.sourceCode = contractText
                    sg.Popup('Info','Contract is built Sucessfully.\nYou can fill in fee box and deploy it.') 

    if event in ('contract_parameters'):
        tmp = values['value_input_method']
        if '(' not in tmp:
            continue
        argsOnly = (tmp.split('(')[1]).replace(')','')
        if(len(argsOnly) > 0):
            layout_contract_parameters = []
            listArgs = argsOnly.split(', ')
            pcount = 0
            for it in listArgs:
                tmp = it.split(' ')
                tmpText = tmp[1] + '(' + tmp[0] +')'
                layout_contract_parameters.append([sg.Text(tmpText, size=(30,1)), sg.InputText(size=(50,1), key = 'value_input_' + str(pcount))])
                pcount += 1

            layout_contract_parameters.append([sg.Button('Apply', key='parameters_apply')])
            win_parameters = sg.Window('Contract parameters' , layout_contract_parameters)
            while True:                             # The Event Loop
                event, values = win_parameters.read()
                if event in (None, 'Exit', 'Cancel'):
                    break
                if event in ('parameters_apply'):
                    for a in range(0,pcount):
                        paramVal = values['value_input_' + str(a)]
                        paramType = listArgs[a].split(' ')[0]
                        paramName = listArgs[a].split(' ')[1]
                        typeSet = False
                        curParam = {}
                        try:
                            if paramType == 'String':
                                curParam['String'] = paramVal
                                typeSet = True
                            if paramType == 'int':
                                curParam['int'] = int(paramVal)
                                typeSet = True
                            if paramType == 'bool':
                                curParam['bool'] = bool(paramVal)
                                typeSet = True
                            if paramType == 'int':
                                curParam['int'] = float(paramVal)
                                typeSet = True
                            if not typeSet:
                                raise
                        except:
                            current_contract_parameters.clear()
                            sg.Popup('Warning','Input parameters are not correct: ' + paramType + ' ' + paramName)
                            break
                        current_contract_parameters[paramName] = curParam
                    print('Parameters applied')
                    window.FindElement('contract_fee').Update(disabled = False)
                    window.FindElement('execute_contract').Update(disabled = False)
                    window.FindElement('save_bc').Update(disabled = False)
                    break
            win_parameters.Close()
            continue

                        

    if event in ('execute_contract'):
        floatFee = 0.
        feeError = 0
        try:
            floatFee = float(values['contract_fee'])
        except:
            feeError = 1
            sg.Popup('Error','Fee can\'t be transformed into float')    
        if floatFee < 0.03:
            feeError = 2
            sg.Popup('Warning','Insufficinent fee')
        if feeError == 0:
            uf = ''
            contractMethod = (values['value_input_method'].split('(')[0]).split(' ')[1]
            m_fee = Utils.double_to_fee(floatFee)
            used_contracts = []
            save_to_bc = values['save_bc']
            sendContract(src, src_priv, values['value_input_contracts'], contractMethod, current_contract_parameters, m_fee, uf, used_contracts, save_to_bc)