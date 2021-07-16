use secp256k1zkp::{constants, pedersen::Commitment, ContextFlag, PublicKey, Secp256k1, SecretKey};

use rand::{thread_rng, Rng};

pub const PUBLIC_KEY_F: [u8; 64] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e,
    0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
    0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68,
    0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
];

#[allow(non_snake_case)]
#[derive(Debug)]
pub struct PedersenWitness {
    W_L: Commitment,
    W_R: Commitment,
    W_O: Commitment,
}

#[derive(Debug, Clone)]
pub struct CommitAdd {
    r_b: SecretKey,
    b_commit: Commitment,
}

#[derive(Debug)]
pub struct CommitMul {
    t1: SecretKey,
    t2: SecretKey,
    t3: SecretKey,
    t4: SecretKey,
    t5: SecretKey,
    c1_commit: Commitment,
    c2_commit: Commitment,
    c3_commit: Commitment,
}

#[derive(Debug)]
pub struct Prover {
    r_l: SecretKey,
    r_r: SecretKey,
    r_o: SecretKey,
    value_l: SecretKey,
    value_r: SecretKey,
    value_o: SecretKey,
    witness: PedersenWitness,
    commit_add: Option<CommitAdd>,
    commit_mul: Option<CommitMul>,
}

pub struct Pedersen(Secp256k1);

pub fn tou8(value: &u64) -> Vec<u8> {
    let mut v = vec![0u8; 24];
    v.extend_from_slice(&value.to_be_bytes());
    v
}

pub fn mul_commit_secret(secp: &Secp256k1, w: &Commitment, r: &SecretKey) -> Commitment {
    let mut public_key = w.to_pubkey(secp).unwrap();

    public_key.mul_assign(secp, r).unwrap();

    Commitment::from_pubkey(secp, &public_key).unwrap()
}

impl Pedersen {
    pub fn new() -> Self {
        Pedersen(Secp256k1::with_caps(ContextFlag::Commit))
    }

    pub fn generate_prover(&self, value_l: u64, value_r: u64, value_o: u64) -> Prover {
        let r_l = SecretKey::new(&self.0, &mut thread_rng());
        let r_r = SecretKey::new(&self.0, &mut thread_rng());
        let r_o = SecretKey::new(&self.0, &mut thread_rng());

        let r_b = SecretKey::new(&self.0, &mut thread_rng());
        let commit_add = CommitAdd {
            r_b: r_b.clone(),
            b_commit: self.0.commit(0, r_b.clone()).unwrap(),
        };

        Prover {
            r_l: r_l.clone(),
            r_r: r_r.clone(),
            r_o: r_o.clone(),
            value_l: SecretKey::from_slice(&self.0, &tou8(&value_l)).unwrap(),
            value_r: SecretKey::from_slice(&self.0, &tou8(&value_r)).unwrap(),
            value_o: SecretKey::from_slice(&self.0, &tou8(&value_o)).unwrap(),
            witness: PedersenWitness {
                W_L: self.0.commit(value_l, r_l.clone()).unwrap(),
                W_R: self.0.commit(value_r, r_r.clone()).unwrap(),
                W_O: self.0.commit(value_o, r_o.clone()).unwrap(),
            },
            commit_add: Some(commit_add),
            commit_mul: None,
        }
    }

    pub fn generate_mul_prover(&self, value_l: u64, value_r: u64, value_o: u64) -> Prover {
        let r_l = SecretKey::new(&self.0, &mut thread_rng());
        let r_r = SecretKey::new(&self.0, &mut thread_rng());
        let r_o = SecretKey::new(&self.0, &mut thread_rng());

        let t1 = SecretKey::new(&self.0, &mut thread_rng());
        let t2 = SecretKey::new(&self.0, &mut thread_rng());
        let t3 = SecretKey::new(&self.0, &mut thread_rng());
        let t4 = SecretKey::new(&self.0, &mut thread_rng());
        let t5 = SecretKey::new(&self.0, &mut thread_rng());

        let p_witness = PedersenWitness {
            W_L: self.0.commit(value_l, r_l.clone()).unwrap(),
            W_R: self.0.commit(value_r, r_r.clone()).unwrap(),
            W_O: self.0.commit(value_o, r_o.clone()).unwrap(),
        };

        let F = Commitment::from_vec(PUBLIC_KEY_F.to_vec());

        let c3_commit = self
            .0
            .commit_sum(
                vec![
                    mul_commit_secret(&self.0, &p_witness.W_R, &t1),
                    mul_commit_secret(&self.0, &F, &t4),
                ],
                vec![],
            )
            .unwrap();

        let commit_mul = CommitMul {
            t1: t1.clone(),
            t2: t2.clone(),
            t3: t3.clone(),
            t4: t4.clone(),
            t5: t5.clone(),
            c1_commit: self.0.commit_blind(t1, t3.clone()).unwrap(), //𝐶1 = 𝐶𝑜𝑚(𝑡1,𝑡3),
            c2_commit: self.0.commit_blind(t2, t5.clone()).unwrap(), //𝐶2 = 𝐶𝑜𝑚(𝑡2,𝑡5)
            c3_commit: c3_commit,                                    //𝐶3 = 𝑡1×𝑊𝑅+𝑡4×𝐹
        };

        Prover {
            r_l: r_l.clone(),
            r_r: r_r.clone(),
            r_o: r_o.clone(),
            value_l: SecretKey::from_slice(&self.0, &tou8(&value_l)).unwrap(),
            value_r: SecretKey::from_slice(&self.0, &tou8(&value_r)).unwrap(),
            value_o: SecretKey::from_slice(&self.0, &tou8(&value_o)).unwrap(),
            witness: p_witness,
            commit_add: None,
            commit_mul: Some(commit_mul),
        }
    }

    //The prover then computes the opening value: 𝑧=𝑥(𝑟𝐿+𝑟𝑅−𝑟𝑂)+𝑟𝐵 and sends it to the verifier.
    pub fn generate_z(&self, x: u64, prover: &Prover) -> SecretKey {
        let mut z = self
            .0
            .blind_sum(
                vec![prover.r_l.clone(), prover.r_r.clone()],
                vec![prover.r_o.clone()],
            )
            .unwrap();

        let x = SecretKey::from_slice(&self.0, &tou8(&x)).unwrap();

        z.mul_assign(&self.0, &x).unwrap();

        let r_b = match prover.commit_add.clone() {
            Some(c) => c.r_b,
            None => panic!("No r_b"),
        };

        let z = self.0.blind_sum(vec![z, r_b], vec![]).unwrap();

        z
    }

    pub fn generate_mul_z(
        &self,
        x: u64,
        prover: &Prover,
    ) -> (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey) {
        let x = SecretKey::from_slice(&self.0, &tou8(&x)).unwrap();
        //𝑒1=𝑤𝐿𝑥+𝑡1
        let mut value_l = prover.value_l.clone();

        value_l.mul_assign(&self.0, &x).unwrap();

        let commit_mul = match &prover.commit_mul {
            Some(c) => c,
            None => panic!("No commit_mul"),
        };

        let e1 = self
            .0
            .blind_sum(vec![value_l, commit_mul.t1.clone()], vec![])
            .unwrap();
        //𝑒2=𝑤𝑅𝑥+𝑡2
        let mut value_r = prover.value_r.clone();

        value_r.mul_assign(&self.0, &x).unwrap();

        let e2 = self
            .0
            .blind_sum(vec![value_r, commit_mul.t2.clone()], vec![])
            .unwrap();
        //𝑧1=𝑟𝐿𝑥+𝑡3
        let mut r_l = prover.r_l.clone();
        r_l.mul_assign(&self.0, &x).unwrap();

        let z1 = self
            .0
            .blind_sum(vec![r_l, commit_mul.t3.clone()], vec![])
            .unwrap();
        //𝑧2=𝑟𝑅𝑥+𝑡5
        let mut r_r = prover.r_r.clone();
        r_r.mul_assign(&self.0, &x).unwrap();

        let z2 = self
            .0
            .blind_sum(vec![r_r, commit_mul.t5.clone()], vec![])
            .unwrap();
        //𝑧3=(𝑟𝑂−𝑤𝐿𝑟𝑅)𝑥+𝑡4
        let mut value_l = prover.value_l.clone();
        value_l.mul_assign(&self.0, &prover.r_r.clone()).unwrap();

        let mut r_tmp = self
            .0
            .blind_sum(vec![prover.r_o.clone()], vec![value_l])
            .unwrap();
        r_tmp.mul_assign(&self.0, &x).unwrap();

        let z3 = self
            .0
            .blind_sum(vec![r_tmp, commit_mul.t4.clone()], vec![])
            .unwrap();

        (e1, e2, z1, z2, z3)
    }

    pub fn verify_add(
        &self,
        x: u64,
        witness: &PedersenWitness,
        b_commit: Commitment,
        z: SecretKey,
    ) -> bool {
        let w_sum_tmp = self
            .0
            .commit_sum(
                vec![witness.W_L.clone(), witness.W_R.clone()],
                vec![witness.W_O.clone()],
            )
            .unwrap();

        let x = SecretKey::from_slice(&self.0, &tou8(&x)).unwrap();

        let w_sum = mul_commit_secret(&self.0, &w_sum_tmp, &x);

        let w_right = self.0.commit_sum(vec![w_sum, b_commit], vec![]).unwrap();

        let w_left = self.0.commit(0, z.clone()).unwrap();

        w_left == w_right
    }

    pub fn verify_mul(
        &self,
        x: u64,
        witness: &PedersenWitness,
        commits: &CommitMul,
        (e1, e2, z1, z2, z3): (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey), /*(e1, e2, z1, z2, z3) */
    ) -> bool {
        let x = SecretKey::from_slice(&self.0, &tou8(&x)).unwrap();
        //𝐶𝑜𝑚(𝑒1,𝑧1)=𝑥×𝑊𝐿+𝐶1
        let w_left = self.0.commit_blind(e1.clone(), z1.clone()).unwrap();
        let w_right = self
            .0
            .commit_sum(
                vec![
                    mul_commit_secret(&self.0, &witness.W_L.clone(), &x),
                    commits.c1_commit,
                ],
                vec![],
            )
            .unwrap();
        assert_eq!(w_left, w_right);

        // 𝐶𝑜𝑚(𝑒2,𝑧2)=𝑥×𝑊𝑅+𝐶2
        let w_left = self.0.commit_blind(e2.clone(), z2.clone()).unwrap();
        let w_right = self
            .0
            .commit_sum(
                vec![
                    mul_commit_secret(&self.0, &witness.W_R.clone(), &x),
                    commits.c2_commit,
                ],
                vec![],
            )
            .unwrap();
        assert_eq!(w_left, w_right);

        //𝑒1×𝑊𝑅+𝑧3×𝐹=𝑥×𝑊𝑂+𝐶3
        // 𝐶3 = 𝑡1×𝑊𝑅+𝑡4×𝐹

        let F = Commitment::from_vec(PUBLIC_KEY_F.to_vec());

        let w_left = self
            .0
            .commit_sum(
                vec![
                    mul_commit_secret(&self.0, &witness.W_R.clone(), &e1.clone()),
                    mul_commit_secret(&self.0, &F, &z3.clone()),
                ],
                vec![],
            )
            .unwrap();

        let w_right = self
            .0
            .commit_sum(
                vec![
                    mul_commit_secret(&self.0, &witness.W_O.clone(), &x.clone()),
                    commits.c3_commit,
                ],
                vec![],
            )
            .unwrap();

        assert_eq!(w_left, w_right);

        true
    }
}

fn main() {
    let pederson = Pedersen::new();
    // 4 = 1 + 3
    let prover = pederson.generate_prover(1, 3, 4);
    println!("prover: {:?}", prover);

    let b_commit = match prover.commit_add.clone() {
        Some(c) => c.b_commit,
        None => panic!("No b_commit"),
    };

    println!("b_commit: {:?}", b_commit);

    // x is challenge
    let x = 1;
    let z = pederson.generate_z(x, &prover);

    println!("z: {:?}", z);

    let success = pederson.verify_add(x, &prover.witness, b_commit, z);

    assert!(success, "𝐶𝑜𝑚(0,𝑧)=𝑥×(𝑊𝐿+𝑊𝑅−𝑊𝑂)+𝐵 fail");


    // 1 = 1 * 1
    let prover = pederson.generate_mul_prover(1, 1, 1);
    println!("prover: {:?}", prover);

    let tuple = pederson.generate_mul_z(x, &prover);

    println!("tuple: {:?}", tuple);

    let commits_mul = match &prover.commit_mul {
        Some(c) => c,
        None => panic!("No commit_mul"),
    };

    let success = pederson.verify_mul(x, &prover.witness, &commits_mul, tuple);

    assert!(success, " 1 = 1 * 1 fail");
}
