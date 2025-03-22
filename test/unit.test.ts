import { createBtcAddress, importBtcWallet } from "../wallet";
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
})