import * as bitcoin from 'bitcoinjs-lib';
const cashaddr = require('cashaddrjs');
import * as ecc from 'tiny-secp256k1';
import { BIP32Factory } from 'bip32';
const bip32 = BIP32Factory(ecc);
const bs58check = require('bs58check');
import { ECPairFactory } from 'ecpair';
// init ECC lib
bitcoin.initEccLib(ecc);
// init ECPair
const ECPair = ECPairFactory(ecc);

// 钱包标准协议（BIP 规范）
const purposeMap = {
    'p2pkh': 44,
    'p2sh': 49,
    'p2wpkh': 84,
    'p2tr': 86
}

// 币种类型编号（SLIP-44 标准）
const coinTypeMap = {
    'btc': 0,
    'ltc': 2,
    'doge': 3,
    'bch': 145,
    'bsv': 236
}

// Bitcoin（BTC）配置
const btcNetwork = {
    messagePrefix: '\x18Bitcoin Signed Message:\n', // 消息签名前缀
    bech32: 'bc', // Bech32地址(P2WPKH)前缀
    bip32: {
      public: 0x0488b21e, // BIP32扩展公钥版本 (xpub)
      private: 0x0488ade4 // BIP32 扩展私钥版本 (xprv)
    },
    pubKeyHash: 0x00, // Base58地址(P2PKH)前缀
    scriptHash: 0x05, // Base58地址(P2SH)前缀
    wif: 0x80 // WIF格式私钥前缀
  };

// Bitcoin Cash (BCH) 配置
const bchNetwork = {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: '',
    cashAddrPrefix: 'bitcoincash',
    bip32: {
        public: 0x0488b21e,
        private: 0x0488ade4
    },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80
};

// Bitcoin SV (BSV) 配置
const bsvNetwork = {
    messagePrefix: '\x18Bitcoin SV Signed Message:\n',
    bech32: '',
    bip32: {
        public: 0x0488b21e,
        private: 0x0488ade4
    },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80
};

// Litecoin (LTC) 配置
const ltcNetwork = {
    messagePrefix: '\x19Litecoin Signed Message:\n',
    bech32: 'ltc',
    bip32: {
        public: 0x019da462,
        private: 0x019d9cfe
    },
    pubKeyHash: 0x30,
    scriptHash: 0x32,
    wif: 0xb0
};

// Dogecoin (DOGE) 配置
const dogeNetwork = {
    messagePrefix: '\x19Dogecoin Signed Message:\n',
    bech32: '',
    bip32: {
        public: 0x02facafd,
        private: 0x02fac398
    },
    pubKeyHash: 0x1e,
    scriptHash: 0x16,
    wif: 0x9e
};

const testNetwork = {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
  };

function getChainConfig(chain: string) {
    switch (chain) {
        case 'btc':
            return btcNetwork;
        case 'bch':
            return bchNetwork;
        case 'bsv':
            return bsvNetwork;
        case 'ltc':
            return ltcNetwork;
        case 'doge':
            return dogeNetwork;
        case 'test':
            return testNetwork;
        default:
            throw new Error('Invalid chain');
    }
}

export function createBtcAddress(seedHex: string, addressType: string, chainType: string, change: string, addressIndex: string){
    const masterNode = bip32.fromSeed(Buffer.from(seedHex, 'hex'));
    const purpose = purposeMap[addressType as keyof typeof purposeMap];
    const coin_type = coinTypeMap[chainType as keyof typeof coinTypeMap];
    const childNode = masterNode.derivePath(`m/${purpose}'/${coin_type}'/0'/${change}/${addressIndex}`);
    const network = getChainConfig(chainType);
    let address;
    switch (addressType) {
        case "p2pkh":
            const p2pkhAddress = bitcoin.payments.p2pkh({
                pubkey: childNode.publicKey,
                network: network
            });    
            if (chainType === "bch") {
                address = cashaddr.encode('bitcoincash','P2PKH',p2pkhAddress.hash);
            } else {
                address = p2pkhAddress.address;
            }
            break;
        
        case "p2sh":
            let redeem;
            // P2SH-P2WPKH（Nested SegWit，嵌套隔离见证），不支持 SegWit 的钱包可接收
            if (chainType === "btc" || chainType === "ltc") {
                redeem = bitcoin.payments.p2wpkh({
                    pubkey: childNode.publicKey,
                    network: network
                });
            } else {
                // P2SH（原生 P2SH-P2MS，多签脚本）
                const pubkeys = [childNode.publicKey]; // 假设只使用一个公钥，实际应用中应根据需求添加多个公钥
                redeem = bitcoin.payments.p2ms({
                    m: 1, // m-of-n 多签（2-of-3，需要3个公钥中2个签名即可完成交易。）
                    pubkeys: pubkeys,
                    network: network
                });
            }
            const p2shAddress = bitcoin.payments.p2sh({
                redeem: redeem, // redeem script 赎回脚本
                network: network
            });
            if (chainType === "bch") {
                address = cashaddr.encode('bitcoincash','P2SH',p2shAddress.hash);
            } else {
                address = p2shAddress.address;
            }
            break;
        
        case "p2wpkh":
            if (chainType === "bch" || chainType === "bsv" || chainType === "doge") {
                throw new Error("Not support this chain type");
            }
            const p2wpkhAddress = bitcoin.payments.p2wpkh({
                pubkey: childNode.publicKey,
                network: network
            }); 
            address = p2wpkhAddress.address;
            break;

        case "p2tr":
            if (chainType !== "btc") {
                throw new Error("Not support this chain type");
            }
            const p2trAddress = bitcoin.payments.p2tr({
                internalPubkey: childNode.publicKey.slice(1,33), // 必须为 32 字节的 x-only 公钥（即压缩公钥去掉前缀 0x02/0x03，仅保留后 32 字节）
                network: network
            });
            address = p2trAddress.address;
            break;

        default:
            throw new Error("Invalid address type");
    }
    if (!childNode.privateKey) {
        throw new Error("Private key not available for this derivation path");
    }
    if (!address) {
        throw new Error('Address generation failed');
    }
    return {
        privateKey: Buffer.from(childNode.privateKey).toString('hex'),
        publicKey: Buffer.from(childNode.publicKey).toString('hex'),
        address: address
    }
}    

export function importBtcWallet(privateKey: string, addressType: string, chainType: string) {
    // bitcore-lib 仅适用于 BTC/BCH/BSV
    //if (!bitcore.privateKey.isValid(secretKey)) {
    //    throw new Error('Invalid secret key');
    //}
    // 所有链的私钥本质均为 32 字节的随机数
    // 版本号 + 32字节私钥 + 压缩标志（可选）
    const network = getChainConfig(chainType);
    const version = getChainConfig(chainType).wif;
    const decoded = bs58check.decode(privateKey);
    if (decoded[0] !== version) {
        throw new Error('Invalid secretKey');
    }
    let keypair;
    if (privateKey.length === 51 || privateKey.length === 52) { 
        // WIF 格式的私钥（51 或 52 字符）（压缩私钥为 52 字符）
        keypair = ECPair.fromWIF(privateKey, network);
    } else if (privateKey.length === 64) { 
        // 十六进制格式的私钥（64 字符）
        keypair = ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'), { 
            compressed: true,
            network
        });
    } else {
        throw new Error("Invalid private key format");
    }
    const publicKey = keypair.publicKey;

    let address;
    switch (addressType) {
        case "p2pkh":
            const p2pkhAddress = bitcoin.payments.p2pkh({
                pubkey: publicKey,
                network: network
            });    
            if (chainType === "bch") {
                address = cashaddr.encode('bitcoincash','P2PKH',p2pkhAddress.hash);
            } else {
                address = p2pkhAddress.address;
            }
            break;
        
        case "p2sh":
            let redeem;
            // P2SH-P2WPKH（Nested SegWit，嵌套隔离见证），不支持 SegWit 的钱包可接收
            if (chainType === "btc" || chainType === "ltc") {
                redeem = bitcoin.payments.p2wpkh({
                    pubkey: publicKey,
                    network: network
                });
            } else {
                // P2SH（原生 P2SH-P2MS，多签脚本）
                const pubkeys = [publicKey]; // 假设只使用一个公钥，实际应用中应根据需求添加多个公钥
                redeem = bitcoin.payments.p2ms({
                    m: 1, // m-of-n 多签（2-of-3，需要3个公钥中2个签名即可完成交易。）
                    pubkeys: pubkeys,
                    network: network
                });
            }
            const p2shAddress = bitcoin.payments.p2sh({
                redeem: redeem,
                network: network
            });
            if (chainType === "bch") {
                address = cashaddr.encode('bitcoincash','P2SH',p2shAddress.hash);
            } else {
                address = p2shAddress.address;
            }
            break;
        
        case "p2wpkh":
            if (chainType === "bch" || chainType === "bsv" || chainType === "doge") {
                throw new Error("Not support this chain type");
            }
            const p2wpkhAddress = bitcoin.payments.p2wpkh({
                pubkey: publicKey,
                network: network
            }); 
            address = p2wpkhAddress.address;
            break;

        case "p2tr":
            if (chainType !== "btc") {
                throw new Error("Not support this chain type");
            }
            const p2trAddress = bitcoin.payments.p2tr({
                internalPubkey: publicKey.subarray(1,33), // 必须为 32 字节的 x-only 公钥（即压缩公钥去掉前缀 0x02/0x03，仅保留后 32 字节）
                network: network
            });
            address = p2trAddress.address;
            break;

        default:
            throw new Error("Invalid address type");
    }
    if (!address) {
        throw new Error('Address generation failed');
    }
    return address;
}

interface TxInput {
    txid: string;
    vout: number;
    hex: string;
    amount: number;
}

interface TxOutput {
    address: string;
    amount: number;
}

export function signP2PKHTransaction(privateKey: string, txObj: any, chainType: string, enableRBF: boolean = true) {
    const network = getChainConfig(chainType);
    const keypair = ECPair.fromWIF(privateKey, network);
    // 构建 btc 交易
    // PSBT 格式（部分签名的比特币交易）(BIP-174)
    // PSBT 格式适用于所有比特币网络，支持所有类型的比特币交易，允许交易在不同参与者之间传递，逐步添加签名
    const psbt = new bitcoin.Psbt({network});
    txObj.inputs.forEach((input: TxInput) => {
        psbt.addInput({
            // 用户看到的 txid 通常以大端序（Big-Endian）的十六进制字符串形式展示
            // 比特币协议在序列化交易时，输入的 txid 字段要求使用小端序（Little-Endian）的字节数组。
            hash: Buffer.from(input.txid, "hex").reverse(),
            index: input.vout,
            // 启用 RBF（Replace-By-Fee，费用替换协议）（BIP-125）
            // nSequence < 0xfffffffe
            sequence: enableRBF ? 0xfffffffd : 0xffffffff,
            // 完整的原始交易数据（HEX格式）
            nonWitnessUtxo: Buffer.from(input.hex, "hex")
        })
    });
    txObj.outputs.forEach((output: TxOutput) => {
        psbt.addOutput({
            value: BigInt(output.amount),
            address: output.address
        })
    });
    psbt.signAllInputs(keypair);
    psbt.finalizeAllInputs();
    return psbt.extractTransaction().toHex();
}

export function signP2SHTransaction(privateKey: string, txObj: any, chainType: string, enableRBF: boolean = true) {
    const network = getChainConfig(chainType);
    const keypair = ECPair.fromWIF(privateKey, network);
    const psbt = new bitcoin.Psbt({network});
    const redeem = bitcoin.payments.p2wpkh({pubkey: keypair.publicKey, network});
    txObj.inputs.forEach((input: TxInput) => {
        psbt.addInput({
            hash: Buffer.from(input.txid, "hex").reverse(),
            index: input.vout,
            sequence: enableRBF ? 0xfffffffd : 0xffffffff,
            // 仅需 UTXO 的脚本和金额，节省存储空间并提升验证效率。
            witnessUtxo: {
                // （外层 P2SH 锁定脚本）
                script: bitcoin.payments.p2sh({redeem: redeem, network}).output!, 
                value: BigInt(input.amount)
            },
            // （内层 P2WPKH 赎回脚本）
            redeemScript: redeem.output!
        })
    });
    txObj.outputs.forEach((output: TxOutput) => {
        psbt.addOutput({
            value: BigInt(output.amount),
            address: output.address
        })
    });
    psbt.signAllInputs(keypair);
    psbt.finalizeAllInputs();
    return psbt.extractTransaction().toHex();
}

export function signP2WPKHTransaction(privateKey: string, txObj: any, chainType: string, enableRBF: boolean = true) {
    const network = getChainConfig(chainType);
    const keypair = ECPair.fromWIF(privateKey, network);
    const psbt = new bitcoin.Psbt({network});
    txObj.inputs.forEach((input: TxInput) => {
        psbt.addInput({
            hash: Buffer.from(input.txid, 'hex').reverse(),
            index: input.vout,
            sequence: enableRBF ? 0xfffffffd : 0xffffffff,
            witnessUtxo: {
                script: bitcoin.payments.p2wpkh({pubkey: keypair.publicKey, network}).output!, 
                value: BigInt(input.amount)
            },
        })
    });
    txObj.outputs.forEach((output: TxOutput) => {
        psbt.addOutput({
            value: BigInt(output.amount),
            address: output.address
        })
    });
    psbt.signAllInputs(keypair);
    psbt.finalizeAllInputs();
    return psbt.extractTransaction().toHex();
}