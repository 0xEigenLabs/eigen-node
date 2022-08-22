pragma circom 2.0.0;
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

// check if low <= m < high;
template RangeProof (n) {
    signal input low; // [low,
    signal input high; // high)
    signal input m;
    signal output out;

    component lessor = LessThan(n);
    lessor.in[0] <== m;
    lessor.in[1] <== high;

    lessor.out === 1;

    component greater = GreaterEqThan(n);
    greater.in[0] <== m;
    greater.in[1] <== low;

    1 === greater.out;
    out <== lessor.out * greater.out;
}

template TEEncryption() {
    signal input amount;
    signal input r;
    signal input H[2];
    signal input pubkey[2];
    signal input C_S[2][2];
    signal input C_S_NEW[2][2];
    component escalarMul_rG;
    component escalarMul_vH;
    component escalarMul_pk;
    component n2b;
    component n2b_g;
    component n2b_h;
    component babyAdd;
    component babyAddCL;
    component babyAddCR;

    // babyjubjub base point
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    // pk^r
    n2b = Num2Bits(253);
    r ==> n2b.in;
    escalarMul_pk = EscalarMulAny(253);
    escalarMul_pk.p[0] <== pubkey[0]; // identity
    escalarMul_pk.p[1] <== pubkey[1];
    for  (var i=0; i<253; i++) {
        n2b.out[i] ==> escalarMul_pk.e[i];
    }
    log(escalarMul_pk.out[0]);
    log(escalarMul_pk.out[1]);
    log(C_S[0][0]);
    log(C_S[0][1]);
    log(C_S[1][0]);
    log(C_S[1][1]);

    // g^r
    n2b_g = Num2Bits(253);
    r ==> n2b_g.in;
    escalarMul_rG = EscalarMulAny(253);
    escalarMul_rG.p[0] <== BASE8[0];
    escalarMul_rG.p[1] <== BASE8[1];
    for  (var i=0; i<253; i++) {
        n2b_g.out[i] ==> escalarMul_rG.e[i];
    }

    // h^v
    n2b_h = Num2Bits(253);
    amount ==> n2b_h.in;
    escalarMul_vH = EscalarMulAny(253);
    escalarMul_vH.p[0] <== H[0];
    escalarMul_vH.p[1] <== H[1];
    for  (var i=0; i<253; i++) {
        n2b_h.out[i] ==> escalarMul_vH.e[i];
    }

    // g^r * h^v
    babyAdd = BabyAdd();
    babyAdd.x1 <== escalarMul_rG.out[0];
    babyAdd.y1 <== escalarMul_rG.out[1];
    babyAdd.x2 <== escalarMul_vH.out[0];
    babyAdd.y2 <== escalarMul_vH.out[1];

    log(babyAdd.xout);
    log(babyAdd.yout);

    // check if pk^r' * pk^r => pk^r
    babyAddCL = BabyAdd();
    babyAddCL.x1 <== C_S[0][0];
    babyAddCL.y1 <== C_S[0][1];
    babyAddCL.x2 <== escalarMul_pk.out[0];
    babyAddCL.y2 <== escalarMul_pk.out[1];

    log(babyAddCL.xout);
    log(C_S_NEW[0][0]);

    babyAddCL.xout === C_S_NEW[0][0];
    babyAddCL.yout === C_S_NEW[0][1];

    // check if g^r' h^v * g^r h^v => g^r * h^v
    babyAddCR = BabyAdd();
    babyAddCR.x1 <== C_S[1][0];
    babyAddCR.y1 <== C_S[1][1];
    babyAddCR.x2 <== babyAdd.xout;
    babyAddCR.y2 <== babyAdd.yout;

    babyAddCR.xout === C_S_NEW[1][0];
    babyAddCR.yout === C_S_NEW[1][1];
}

template EdDSAVerifier() {
    signal input Ax; //public
    signal input Ay; //public
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input M; // public

    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax <== Ax;
    verifier.Ay <== Ay;
    verifier.R8x <== R8x;
    verifier.R8y <== R8y;
    verifier.S <== S;
    verifier.M <== M;
}


template ZKTX() {
    signal input senderPubkey[2];
    signal input receiverPubkey[2];

    signal input Max;
    signal input r;
    signal input amount;
    signal input H[2];

    signal input C_S[2][2];
    signal input C_S_NEW[2][2];

    signal input Ax;
    signal input Ay;
    signal input S;
    signal input R8x;
    signal input R8y;
    signal input M;

    // check signature
    component sigVerifier = EdDSAVerifier();
    sigVerifier.Ax <== Ax;
    sigVerifier.Ay <== Ay;
    sigVerifier.S <== S;

    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== M;

    // check amount's range
    component rp = RangeProof(252);
    rp.low <== 0;
    rp.high <== Max;
    rp.m <== amount;
    1 === rp.out;

    // check if encryption executed correctly
    component tee = TEEncryption();
    tee.amount <== amount;
    tee.r <== r;
    tee.H[0] <== H[0];
    tee.H[1] <== H[1];
    tee.pubkey[0] <== senderPubkey[0];
    tee.pubkey[1] <== senderPubkey[1];

    for (var i=0; i<2; i ++) {
        for (var j = 0; j < 2; j ++) {
            tee.C_S[i][j] <== C_S[i][j];
            tee.C_S_NEW[i][j] <== C_S_NEW[i][j];
        }
    }
}


component main {
    public [
        senderPubkey,
        receiverPubkey,
        Max,
        H,
        C_S,
        C_S_NEW,
        Ax,
        Ay,
        M
    ]
} = ZKTX();
