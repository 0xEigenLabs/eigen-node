use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::collections::HashMap;

use std::sync::{Arc, RwLock};

lazy_static! {
    static ref POINT_TO_INDEX_MAP: RwLock<HashMap<CompressedRistretto, u32>> =
        RwLock::new(HashMap::new());
}

// Assume P = k * G, k \in [0, 2^31), solve k.
pub fn bsgs(P: &RistrettoPoint, G: &RistrettoPoint) -> Option<u32> {
    // only support x \in [0, 2^31)
    let MAX = 2147483647u32;
    let m = 65536u32;

    // Compute a table of [G,2.G,3.G,..,b.G,...,m.G]
    if POINT_TO_INDEX_MAP.read().unwrap().len() == 0 {
        for j in 1..=m {
            POINT_TO_INDEX_MAP
                .write()
                .unwrap()
                .insert((Scalar::from(j) * G).compress(), j);
        }
    }

    let mut step = 0u32;

    let mut S = P - G + G;

    while step < MAX {
        if POINT_TO_INDEX_MAP
            .read()
            .unwrap()
            .contains_key(&S.compress())
        {
            let b = POINT_TO_INDEX_MAP
                .read()
                .unwrap()
                .get(&S.compress())
                .unwrap()
                .clone();
            return Some(b + step);
        } else {
            S = S - Scalar::from(m) * G;
            step += m;
        }
    }
    None
}

/*
#[test]
fn test_bsgs() {
    let p: Vec<u32> = vec![
        1,
        2,
        3,
        5,
        6,
        7,
        2u32.pow(10),
        2u32.pow(11),
        2u32.pow(19),
        2u32.pow(20),
        2u32.pow(28),
    ];
    let r: Vec<bool> = p
        .into_iter()
        .map(|x| {
            let P = Scalar::from(x) * RISTRETTO_BASEPOINT_POINT;
            let r = bsgs(&P, &RISTRETTO_BASEPOINT_POINT).unwrap();
            println!("{} == {}", r, x);
            r == x
        })
        .collect();
    assert!(r.iter().all(|&x| x == true));
}
*/
