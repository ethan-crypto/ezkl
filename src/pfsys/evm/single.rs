use crate::pfsys::evm::YulCode;
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::{plonk::VerifyingKey, poly::kzg::commitment::ParamsKZG};
use halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use snark_verifier::{
    loader::evm::EvmLoader,
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use snark_verifier_bytecode::{
    loader::evm::EvmLoader as EvmLoaderB,
    pcs::kzg::{Gwc19 as Gwc19B, KzgAs as KzgAsB},
    system::halo2::{compile as compileB, transcript::evm::EvmTranscript as EvmTranscriptB, Config as ConfigB},
    verifier::{self as selfB, SnarkVerifier as SnarkVerifierB},
};
use std::rc::Rc;
use thiserror::Error;

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;
type PlonkVerifierB = selfB::plonk::PlonkVerifier<KzgAsB<Bn256, Gwc19B>>;

#[derive(Error, Debug)]
/// Errors related to simple evm verifier generation
pub enum SimpleError {
    /// proof read errors
    #[error("Failed to read proof")]
    ProofRead,
    /// proof verification errors
    #[error("Failed to verify proof")]
    ProofVerify,
}

/// Create EVM verifier yulcode using the yulcode loader
pub fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Result<YulCode, SimpleError> {
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript)
        .map_err(|_| SimpleError::ProofRead)?;
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof)
        .map_err(|_| SimpleError::ProofVerify)?;

    let yul_code = &loader.yul_code();

    Ok(yul_code.clone())
}

/// Create EVM verifier bytecode using the bytecode loader
pub fn gen_evm_verifier_bytecode(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Result<String, SimpleError> {
    let protocol = compileB(
        params,
        vk,
        ConfigB::kzg().with_num_instance(num_instance.clone()),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoaderB::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscriptB::<_, Rc<EvmLoaderB>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifierB::read_proof(&vk, &protocol, &instances, &mut transcript)
        .map_err(|_| SimpleError::ProofRead)?;
    PlonkVerifierB::verify(&vk, &protocol, &instances, &proof)
        .map_err(|_| SimpleError::ProofVerify)?;

    let bytecode = &loader.bytecode();

    Ok(bytecode.clone())
}
