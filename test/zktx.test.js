const client = require("../");
var assert = require('assert');
var expect = require('chai');


const main = async() => {
  let circult_path = "/tmp/zkit_zktx/zktx_js/"
  let zktx = new client.ZKTX(circult_path);
  await zktx.initialize()

  let senderPvk = zktx.twistedElGamal.random(32);
  let senderPubk = zktx.twistedElGamal.pubkey(senderPvk);
  console.log(senderPubk)

  let receiverPvk = zktx.twistedElGamal.random(32);
  console.log(receiverPvk)
  let receiverPubk = zktx.twistedElGamal.pubkey(receiverPvk);

  let amount = 10;
  let ct = zktx.twistedElGamal.encrypt(senderPubk, amount);
  console.log(ct)

  let nonce = 1;
  let tokentype = 1;
  let tx = await zktx.createTX(amount, senderPvk, nonce, tokentype, receiverPubk, ct.c_l, ct.c_r)

  console.log(tx);
}


describe('ZKTX',async function() {
  describe('createTX', async function() {
    it('should be able to create tx', async function() {
      await main()
    });
  });
});
