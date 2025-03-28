import { createBtcAddress, importBtcWallet, signBtcTransaction } from "../wallet";
import * as bip39 from "bip39";

describe("btc wallet test", () => {

    test("create btc address", () => {
        const mnemonic = "";
        const seed = bip39.mnemonicToSeedSync(mnemonic, "");
        const result = createBtcAddress(seed.toString("hex"), "p2tr", "btc", "0", "0");
        console.log(result);
    })

    test("import btc wallet", () => {
        const result = importBtcWallet(
            "", 
            "p2sh", 
            "ltc"
            );
        console.log(result);
    })

    test('sign btc transaction', async () => {
        const addressType = 'p2wpkh';
        const data = {
            "inputs" : [
                {
                    "txid" : "",
                    "vout" : 0,
                    "hex" : "",
                    "amount" : 496500
                }
            ],
            "outputs" : [
                {
                    "amount" : 496000,
                    "address" : ""
                },
            ]
        };
        const params = {
            privateKey: "",
            txObj: data,
            chainType: "test"
        }
        const rawTx = signBtcTransaction(addressType, params.privateKey, params.txObj, params.chainType);
        console.log(rawTx);
    });
})