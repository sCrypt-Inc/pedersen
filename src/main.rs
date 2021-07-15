use secp256k1zkp::{pedersen::Commitment, ContextFlag, Secp256k1, SecretKey};

use rand::{thread_rng, Rng};


#[allow(non_snake_case)]
#[derive(Debug)]
pub struct PedersenWitness {
    W_L: Commitment,
    W_R: Commitment,
    W_O: Commitment,
}


#[derive(Debug)]
pub struct Prover {
    r_l: SecretKey,
    r_r: SecretKey,
    r_o: SecretKey,
    value_l: SecretKey,
    value_r: SecretKey,
    value_o: SecretKey,
    r_b: SecretKey,
    witness: PedersenWitness,
}


pub struct Pedersen(Secp256k1);


pub fn tou8(value: &u64) -> Vec<u8> {
    let mut v = vec![0u8;24];
    v.extend_from_slice(&value.to_be_bytes());
    v
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



        let mut vec = vec![0u8;24];
        vec.extend_from_slice(&value_l.to_le_bytes());

        Prover {
            r_l: r_l.clone(),
            r_r: r_r.clone(),
            r_o: r_o.clone(),
            value_l: SecretKey::from_slice(&self.0, &tou8(&value_l)).unwrap(),
            value_r: SecretKey::from_slice(&self.0, &tou8(&value_r)).unwrap(),
            value_o: SecretKey::from_slice(&self.0, &tou8(&value_o)).unwrap(),
            r_b,
            witness: PedersenWitness {
                W_L: self.0.commit(value_l, r_l).unwrap(),
                W_R: self.0.commit(value_r, r_r).unwrap(),
                W_O: self.0.commit(value_o, r_o).unwrap(),
            },
        }
    }

    //1. The prover generates a commitment to zero: 𝐵 = 𝐶𝑜𝑚(0,𝑟𝐵), and sends to the verifier.
    pub fn generate_b_commit(&self, prover: &Prover) -> Commitment {
        self.0.commit(0, prover.r_b.clone()).unwrap()
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

        let z = self
            .0
            .blind_sum(vec![z, prover.r_b.clone()], vec![])
            .unwrap();

        z
    }





    pub fn verify_add(&self, x: u64, witness: &PedersenWitness, b_commit: Commitment, z: SecretKey) -> bool {

        let w_sum_tmp = self.0
        .commit_sum(vec![witness.W_L.clone(), witness.W_R.clone()], vec![witness.W_O.clone()])
        .unwrap();

        //TODO: x * w_sum

        let mut i = 1;
        let mut w_sum = w_sum_tmp;
        while i < (x) {
            w_sum = self.0
                .commit_sum(vec![w_sum.clone(), w_sum_tmp.clone()], vec![])
                .unwrap();
            i += 1;
        }

        let w_right = self.0.commit_sum(vec![w_sum, b_commit], vec![]).unwrap();


        let w_left = self.0.commit(0, z.clone()).unwrap();

        w_left == w_right

    }


    pub fn verify_mul(&self) -> bool {

        false
    }



}

fn main() {
    

    let pederson = Pedersen::new();

    let prover = pederson.generate_prover(1, 3, 4);
    println!("prover: {:?}", prover);

    let b_commit = pederson.generate_b_commit(&prover);

    println!("b_commit: {:?}", b_commit);

    // x is challenge
    let x = 20;
    let z = pederson.generate_z(x, &prover);

    println!("z: {:?}", z);

    let success = pederson.verify_add(x, &prover.witness, b_commit, z);

    assert!(success, "𝐶𝑜𝑚(0,𝑧)=𝑥×(𝑊𝐿+𝑊𝑅−𝑊𝑂)+𝐵 fail");
    
}
