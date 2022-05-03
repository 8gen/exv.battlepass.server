import express from "express"
import cors from "cors"
import { errors } from "celebrate";
import * as dotenv from "dotenv";
import * as secp from "@noble/secp256k1";
import keccak256 from "keccak256";
import * as sigUtil from 'eth-sig-util'
import * as ethUtil from "ethereumjs-util";


dotenv.config();
const app = express()
const PORT = process.env.PORT || 3000
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const privateKey = Buffer.from(PRIVATE_KEY!, "hex");
const ETH_ADDRESS = '0x' + ethUtil.privateToAddress(privateKey).toString('hex')


app.use(express.json())
app.use(cors())
app.get("/api/v1/ethsign/:address", async (req, res) => {
    const messageToSign = `${req.params.address.toUpperCase()}:1`;

    console.log(`Sign test message: ${messageToSign} from ${req.header("x-real-ip")}`)
    // @ts-ignore
    const msgParams: sigUtil.MessageData<string> = { data: messageToSign };
    let signature = sigUtil.personalSign(privateKey, msgParams)
    // Test
    res.json({
        meta: {
            success: true
        },
        data: {
            permitted_amount: 1,
            address: ETH_ADDRESS,
            signature: signature.toString(),
        },
    });
});
app.get("/api/v1/sign/:address", async (req, res) => {
    let permitted_amount = 100;
    let messageToSign = `${req.params.address}:${permitted_amount}`;
    console.log(`Sign test message: ${messageToSign} from ${req.header("x-real-ip")}`)
    let hash = keccak256(messageToSign);
    let signature = secp.utils.bytesToHex(await secp.sign(hash, privateKey));
    res.json({
        meta: {
            success: true
        },
        data: {
            permitted_amount,
            pk: secp.utils.bytesToHex(secp.getPublicKey(privateKey, true)),
            signature: secp.Signature.fromHex(signature).toCompactHex(),
        },
    });
});

app.use("*", (req, res) => {
    res.sendStatus(404)
});
app.use(errors())
app.listen(PORT, () =>
    console.log(`REST API server ready at: http://localhost:${PORT}`),
)
