import * as bitcoin from 'bitcoinjs-lib';
const cashaddr = require('cashaddrjs');
import * as ecc from 'tiny-secp256k1';
import { BIP32Factory } from 'bip32';
const bip32 = BIP32Factory(ecc);
// init ECC lib
bitcoin.initEccLib(ecc);

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