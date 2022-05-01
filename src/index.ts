import express from "express"
import cors from "cors"
import { errors } from "celebrate";
import * as dotenv from "dotenv";
import * as secp from "@noble/secp256k1";
import keccak256 from "keccak256";

dotenv.config();
const app = express()
const PORT = process.env.PORT || 3000
const PRIVATE_KEY = process.env.PRIVATE_KEY;

app.use(express.json())
app.use(cors())
app.get("/api/v1/sign/:address", async (req, res) => {
    let permitted_amount = 100;
    let hash = keccak256(`${req.params.address}:${permitted_amount}`);
    let privKey = Buffer.from(PRIVATE_KEY!, "hex");
    let signature = secp.utils.bytesToHex(await secp.sign(hash, privKey));
    res.json({
        meta: {
            success: true
        },
        data: {
            permitted_amount,
            pk: secp.utils.bytesToHex(secp.getPublicKey(privKey, true)),
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
