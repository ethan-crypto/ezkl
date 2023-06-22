/// Representations of a computational graph's inputs.
pub mod input;
/// Crate for defining a computational graph and building a ZK-circuit from it.
pub mod model;
/// Representations of a computational graph's modules.
pub mod modules;
/// Inner elements of a computational graph that represent a single operation / constraints.
pub mod node;
/// Helper functions
pub mod utilities;
/// Representations of a computational graph's variables.
pub mod vars;

pub use input::{GraphWitness, DataSource};

use crate::circuit::lookup::LookupOp;
use crate::circuit::modules::ModulePlanner;
use crate::circuit::CheckMode;
use crate::commands::RunArgs;
//use crate::eth::{setup_eth_backend, read_on_chain_inputs, evm_quantize, test_on_chain_data};
#[cfg(not(target_arch = "wasm32"))]
use ethers::types::H160;
use crate::fieldutils::i128_to_felt;
use crate::graph::modules::ModuleInstanceOffset;
use crate::tensor::{Tensor, ValTensor};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Circuit, ConstraintSystem, Error as PlonkError},
};
use halo2curves::bn256::{self, Fr as Fp};
use halo2curves::ff::PrimeField;
use log::{error, info, trace};
pub use model::*;
pub use node::*;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use thiserror::Error;
pub use utilities::*;
pub use vars::*;

use self::modules::{
    GraphModules, ModuleConfigs, ModuleForwardResult, ModuleSettings, ModuleSizes,
};

/// circuit related errors.
#[derive(Debug, Error)]
pub enum GraphError {
    /// The wrong inputs were passed to a lookup node
    #[error("invalid inputs for a lookup node")]
    InvalidLookupInputs,
    /// Shape mismatch in circuit construction
    #[error("invalid dimensions used for node {0} ({1})")]
    InvalidDims(usize, String),
    /// Wrong method was called to configure an op
    #[error("wrong method was called to configure node {0} ({1})")]
    WrongMethod(usize, String),
    /// A requested node is missing in the graph
    #[error("a requested node is missing in the graph: {0}")]
    MissingNode(usize),
    /// The wrong method was called on an operation
    #[error("an unsupported method was called on node {0} ({1})")]
    OpMismatch(usize, String),
    /// This operation is unsupported
    #[error("unsupported operation in graph")]
    UnsupportedOp,
    /// A node has missing parameters
    #[error("a node is missing required params: {0}")]
    MissingParams(String),
    /// A node has missing parameters
    #[error("a node is has misformed params: {0}")]
    MisformedParams(String),
    /// Error in the configuration of the visibility of variables
    #[error("there should be at least one set of public variables")]
    Visibility,
    /// Ezkl only supports divisions by constants
    #[error("ezkl currently only supports division by constants")]
    NonConstantDiv,
    /// Ezkl only supports constant powers
    #[error("ezkl currently only supports constant exponents")]
    NonConstantPower,
    /// Error when attempting to rescale an operation
    #[error("failed to rescale inputs for {0}")]
    RescalingError(String),
    /// Error when attempting to load a model
    #[error("failed to load model")]
    ModelLoad,
    /// Packing exponent is too large
    #[error("largest packing exponent exceeds max. try reducing the scale")]
    PackingExponent,
}

const ASSUMED_BLINDING_FACTORS: usize = 6;

/// 26
const MAX_PUBLIC_SRS: u32 = bn256::Fr::S - 2;

/// Result from a forward pass
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ForwardResult {
    /// The inputs of the forward pass
    pub inputs: Vec<Tensor<i128>>,
    /// The output of the forward pass
    pub outputs: Vec<Tensor<i128>>,
    /// Any hashes of inputs generated during the forward pass
    pub processed_inputs: Option<ModuleForwardResult>,
    /// Any hashes of params generated during the forward pass
    pub processed_params: Option<ModuleForwardResult>,
    /// Any hashes of outputs generated during the forward pass
    pub processed_outputs: Option<ModuleForwardResult>,
    /// max lookup input
    pub max_lookup_input: i128,
}

/// model parameters
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct GraphSettings {
    /// run args
    pub run_args: RunArgs,
    /// the potential number of constraints in the circuit
    pub num_constraints: usize,
    /// the shape of public inputs to the model (in order of appearance)
    pub model_instance_shapes: Vec<Vec<usize>>,
    /// the of instance cells used by modules
    pub module_sizes: ModuleSizes,
    /// required_lookups
    pub required_lookups: Vec<LookupOp>,
    /// check mode
    pub check_mode: CheckMode,
}

impl GraphSettings {
    /// calculate the total number of instances
    pub fn total_instances(&self) -> Vec<usize> {
        let mut instances: Vec<usize> = self
            .model_instance_shapes
            .iter()
            .map(|x| x.iter().product())
            .collect();
        instances.extend(self.module_sizes.num_instances());

        instances
    }

    /// save params to file
    pub fn save(&self, path: &std::path::PathBuf) -> Result<(), std::io::Error> {
        let encoded = serde_json::to_string(&self)?;
        let mut file = std::fs::File::create(path)?;
        file.write_all(encoded.as_bytes())
    }
    /// load params from file
    pub fn load(path: &std::path::PathBuf) -> Result<Self, std::io::Error> {
        let mut file = std::fs::File::open(path)?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;
        let res = serde_json::from_str(&data)?;
        Ok(res)
    }
}

/// Configuration for a computational graph / model loaded from a `.onnx` file.
#[derive(Clone, Debug)]
pub struct GraphConfig {
    model_config: ModelConfig,
    module_configs: ModuleConfigs,
}

/// Defines the circuit for a computational graph / model loaded from a `.onnx` file.
#[derive(Clone, Debug, Default)]
pub struct GraphCircuit {
    /// The model / graph of computations.
    pub model: Model,
    /// Vector of input tensors to the model / graph of computations.
    pub inputs: Vec<Tensor<i128>>,
    /// Vector of input tensors to the model / graph of computations.
    pub outputs: Vec<Tensor<i128>>,
    /// The settings of the model / graph of computations.
    pub settings: GraphSettings,
    /// The settings of the model's modules.
    pub module_settings: ModuleSettings,
}

impl GraphCircuit {
    ///
    pub fn new(
        model: Model,
        run_args: RunArgs,
        check_mode: CheckMode,
    ) -> Result<GraphCircuit, Box<dyn std::error::Error>> {
        // placeholder dummy inputs - must call prepare_public_inputs to load data afterwards
        let mut inputs: Vec<Tensor<i128>> = vec![];
        for shape in model.graph.input_shapes() {
            let t: Tensor<i128> = Tensor::new(None, &shape).unwrap();
            inputs.push(t);
        }

        // dummy module settings, must load from GraphInput after
        let module_settings = ModuleSettings::default();

        let mut settings = model.gen_params(run_args, check_mode)?;

        let mut num_params = 0;
        if !model.const_shapes().is_empty() {
            for shape in model.const_shapes() {
                num_params += shape.iter().product::<usize>();
            }
        }

        let sizes = GraphModules::num_constraints_and_instances(
            model.graph.input_shapes(),
            vec![vec![num_params]],
            model.graph.output_shapes(),
            VarVisibility::from_args(run_args).unwrap(),
        );

        // number of instances used by modules
        settings.module_sizes = sizes.clone();

        // as they occupy independent rows
        settings.num_constraints = std::cmp::max(settings.num_constraints, sizes.max_constraints());

        Ok(GraphCircuit {
            model,
            inputs,
            outputs: vec![],
            settings,
            module_settings,
        })
    }

    ///
    pub fn new_from_settings(
        model: Model,
        mut settings: GraphSettings,
        check_mode: CheckMode,
    ) -> Result<GraphCircuit, Box<dyn std::error::Error>> {
        // placeholder dummy inputs - must call prepare_public_inputs to load data afterwards
        let mut inputs: Vec<Tensor<i128>> = vec![];
        for shape in model.graph.input_shapes() {
            let t: Tensor<i128> = Tensor::new(None, &shape).unwrap();
            inputs.push(t);
        }

        // dummy module settings, must load from GraphInput after
        let module_settings = ModuleSettings::default();

        settings.check_mode = check_mode;

        Ok(GraphCircuit {
            model,
            inputs,
            outputs: vec![],
            settings,
            module_settings,
        })
    }
    #[cfg(not(target_arch = "wasm32"))]
    ///
    pub async fn load_inputs(&mut self, data: &GraphWitness)
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::eth::{setup_eth_backend, read_on_chain_inputs, evm_quantize};
        match &data.input_data {
            DataSource::OnChain(calls_to_accounts, rpc_url) => {
                // Set up anvil instance for reading on-chain data from RPC URL endpoint provided in data
                let (anvil, client) = setup_eth_backend(Some(&rpc_url)).await?;
                let inputs = read_on_chain_inputs(client.clone(), client.address(), &calls_to_accounts).await?;
                drop(anvil);
                // Set up local anvil instance for deploying QuantizeData.sol
                let (anvil, client) = setup_eth_backend(None).await?;
                let quantized_evm_inputs = evm_quantize(
                    client,
                    vec![scale_to_multiplier(self.settings.run_args.scale); inputs.0.len()], 
                    &inputs).await?;
                drop(anvil);
                // on-chain data has already been quantized at this point. Just need to reshape it and push into tensor vector
                let mut inputs: Vec<Tensor<i128>> = vec![];
                for (input, shape) in vec![quantized_evm_inputs].iter().zip(self.model.graph.input_shapes()) {
                    let mut t: Tensor<i128> = input.iter().cloned().collect();
                    t.reshape(&shape);
                    inputs.push(t);
                }
                self.inputs = inputs;
            },
            DataSource::File(file_data) => {
                self.load_file_inputs(file_data);
            },
        };

        Ok(())
    }

    ///
    pub fn load_file_inputs(&mut self, file_data: &Vec<Vec<f32>>) {
        // quantize the supplied data using the provided scale.
        let mut inputs: Vec<Tensor<i128>> = vec![];
        for (input, shape) in file_data.iter().zip(self.model.graph.input_shapes()) {
            let t: Vec<i128> = input
                .par_iter()
                .map(|x| quantize_float(x, 0.0, self.settings.run_args.scale).unwrap())
                .collect();

            let mut t: Tensor<i128> = t.into_iter().into();
            t.reshape(&shape);

            inputs.push(t);
        }
        self.inputs = inputs;
    }
    #[cfg(not(target_arch = "wasm32"))]
    ///
    pub async fn load_outputs(
        &mut self, 
        data: &GraphWitness
    ) -> Result<(), Box<dyn std::error::Error>> {
        let out_scales = self.model.graph.get_output_scales();
        use crate::eth::{setup_eth_backend, read_on_chain_inputs, evm_quantize};
        match &data.output_data {
            DataSource::OnChain(calls_to_accounts, rpc_url) => {
                // Set up anvil instance for reading on-chain data from RPC URL endpoint provided in data
                let (anvil, client) = setup_eth_backend(Some(&rpc_url)).await?;
                let inputs = read_on_chain_inputs(client.clone(), client.address(), &calls_to_accounts).await?;
                drop(anvil);
                // Set up local anvil instance for deploying QuantizeData.sol
                let (anvil, client) = setup_eth_backend(None).await?;
                let quantized_evm_inputs = evm_quantize(
                    client,
                    out_scales.iter().map(|x| scale_to_multiplier(*x)).collect(), 
                    &inputs).await?;
                drop(anvil);
                // on-chain data has already been quantized at this point. Just need to reshape it and push into tensor vector
                let mut inputs: Vec<Tensor<i128>> = vec![];
                for (input, shape) in vec![quantized_evm_inputs].iter().zip(self.model.graph.input_shapes()) {
                    let mut t: Tensor<i128> = input.iter().cloned().collect();
                    t.reshape(&shape);
                    inputs.push(t);
                }
                self.inputs = inputs;
            },
            DataSource::File(output_data) => {
                // quantize the supplied data using the provided scale.
                self.outputs = vec![];
                if self.settings.run_args.output_visibility.is_public() {
                    for (idx, v) in output_data.iter().enumerate() {
                        let t: Vec<i128> = v
                            .par_iter()
                            .map(|x| quantize_float(x, 0.0, out_scales[idx]).unwrap())
                            .collect();
        
                        let t: Tensor<i128> = t.into_iter().into();
        
                        self.outputs.push(t);
                    }
                }
            },
        };

        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    ///
    pub async fn load_test_on_chain_data<M: 'static + ethers::providers::Middleware>(
        &mut self,
        client: std::sync::Arc<M>,
        address: H160,
        data: &Vec<Vec<f32>>,
        scales: Vec<f64>,
    ) -> Result<(Vec<Tensor<i128>>, Vec<input::CallsToAccount>), Box<dyn std::error::Error>> {

        use crate::eth::{test_on_chain_data, read_on_chain_inputs, evm_quantize};
        use log::debug;
        let calls_to_accounts  = test_on_chain_data(client.clone(), data).await?;
        debug!("Calls to accounts: {:?}", calls_to_accounts);
        let inputs = read_on_chain_inputs(client.clone(), address, &calls_to_accounts).await?;
        debug!("Inputs: {:?}", inputs);
        let quantized_evm_inputs = evm_quantize(
            client,
            scales, 
            &inputs
        ).await?;
        // on-chain data has already been quantized at this point. Just need to reshape it and push into tensor vector
        let mut inputs: Vec<Tensor<i128>> = vec![];
        for (input, shape) in vec![quantized_evm_inputs].iter().zip(self.model.graph.input_shapes()) {
            let mut t: Tensor<i128> = input.iter().cloned().collect();
            t.reshape(&shape);
            inputs.push(t);
        }
        Ok((inputs, calls_to_accounts))
    }

    /// Calibrate the circuit to the supplied data.
    pub fn calibrate(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let res = self.forward()?;
        let max_range = 2i128.pow(self.settings.run_args.bits as u32 - 1);
        if res.max_lookup_input > max_range {
            let recommended_bits = (res.max_lookup_input as f64).log2().ceil() as usize + 1;

            if recommended_bits <= (MAX_PUBLIC_SRS - 1) as usize {
                self.settings.run_args.bits = recommended_bits;
                self.settings.run_args.logrows = (recommended_bits + 1) as u32;
                return self.calibrate();
            } else {
                let err_string = format!("No possible value of bits (estimate {}) at scale {} can accomodate this value.", recommended_bits, self.settings.run_args.scale);
                return Err(err_string.into());
            }
        } else {
            let min_bits = (res.max_lookup_input as f64).log2().ceil() as usize + 1;

            let min_rows_from_constraints = (self.settings.num_constraints as f64
                + ASSUMED_BLINDING_FACTORS as f64)
                .log2()
                .ceil() as usize
                + 1;
            let mut logrows = std::cmp::max(min_bits + 1, min_rows_from_constraints);

            // ensure logrows is at least 4
            logrows = std::cmp::max(
                logrows,
                (ASSUMED_BLINDING_FACTORS as f64).ceil() as usize + 1,
            );

            logrows = std::cmp::min(logrows, MAX_PUBLIC_SRS as usize);

            info!(
                "setting bits to: {}, setting logrows to: {}",
                min_bits, logrows
            );
            self.settings.run_args.bits = min_bits;
            self.settings.run_args.logrows = logrows as u32;
        }

        self.settings = GraphCircuit::new(
            self.model.clone(),
            self.settings.run_args,
            self.settings.check_mode,
        )?
        .settings;

        Ok(())
    }

    /// Runs the forward pass of the model / graph of computations and any associated hashing.
    pub fn forward(&self) -> Result<ForwardResult, Box<dyn std::error::Error>> {
        let visibility = VarVisibility::from_args(self.settings.run_args)?;
        let mut processed_inputs = None;
        let mut processed_params = None;
        let mut processed_outputs = None;

        if visibility.input.requires_processing() {
            processed_inputs = Some(GraphModules::forward(&self.inputs, visibility.input)?);
        }

        if visibility.params.requires_processing() {
            let params = self.model.get_all_consts();
            let flattened_params = flatten_valtensors(params)?
                .get_int_evals()?
                .into_iter()
                .into();
            processed_params = Some(GraphModules::forward(
                &[flattened_params],
                visibility.params,
            )?);
        }

        let outputs = self.model.forward(&self.inputs)?;

        if visibility.output.requires_processing() {
            processed_outputs = Some(GraphModules::forward(&outputs.outputs, visibility.output)?);
        }

        Ok(ForwardResult {
            inputs: self.inputs.clone(),
            outputs: outputs.outputs,
            processed_inputs,
            processed_params,
            processed_outputs,
            max_lookup_input: outputs.max_lookup_inputs,
        })
    }

    /// Create a new circuit from a set of input data and [RunArgs].
    pub fn from_run_args(
        run_args: &RunArgs,
        model_path: &std::path::PathBuf,
        check_mode: CheckMode,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let model = Model::from_run_args(run_args, model_path)?;
        Self::new(model, *run_args, check_mode)
    }

    /// Create a new circuit from a set of input data and [GraphSettings].
    pub fn from_settings(
        params: &GraphSettings,
        model_path: &std::path::PathBuf,
        check_mode: CheckMode,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let model = Model::from_run_args(&params.run_args, model_path)?;
        Self::new_from_settings(model, params.clone(), check_mode)
    }
    #[cfg(not(target_arch = "wasm32"))]
    /// Prepare the public inputs for the circuit.
    pub async fn prepare_public_inputs(
        &mut self,
        data: &GraphWitness,
        test_on_chain_data_path: Option<std::path::PathBuf>,
        test_onchain_input: bool,
        test_onchain_output: bool,
    ) -> Result<Vec<Vec<Fp>>, Box<dyn std::error::Error>> {
        let out_scales = self.model.graph.get_output_scales();

        let data = if let Some(test_on_chain_data_path) = test_on_chain_data_path {
            // Set up local anvil instance for reading on-chain data
            let (anvil, client) = crate::eth::setup_eth_backend(None).await?;
            let mut data = data.clone();
            if test_onchain_input {
                let input_data = match data.input_data {
                    DataSource::File(input_data) => input_data,
                    DataSource::OnChain(_, _) => 
                        panic!(
                        "Cannot use on-chain data source as input for on-chain test. 
                        Will manually populate on-chain data from file source instead"
                    )
                };
                let chain_data = self.load_test_on_chain_data(
                    client.clone(), 
                    client.address(), 
                    &input_data,
                    vec![scale_to_multiplier(self.settings.run_args.scale); input_data[0].len()]
                ).await?;
                self.inputs = chain_data.0;
                let calls_to_accounts = chain_data.1;
                // Fill the nput_data field of the GraphInput struct
                data.input_data = DataSource::OnChain(calls_to_accounts.clone(), anvil.endpoint());
            } else if test_onchain_output {
                let output_data = match data.output_data{
                    DataSource::File(output_data) => output_data,
                    DataSource::OnChain(_, _) => 
                        panic!(
                        "Cannot use on-chain data source as output for on-chain test. 
                        Will manually populate on-chain data from file source instead"
                    )
                };
                let chain_data = self.load_test_on_chain_data(
                    client.clone(), 
                    client.address(), 
                    &output_data,
                    out_scales.iter().map(|x| scale_to_multiplier(*x)).collect()
                ).await?;
                self.outputs = chain_data.0;
                let calls_to_accounts = chain_data.1;
                // Fill the on_chain_output_data field of the GraphInput struct
                data.output_data = DataSource::OnChain(calls_to_accounts.clone(), anvil.endpoint());
            } else {
                panic!("Must specify input or output")
            }
            // Drop the anvil
            drop(anvil);
            // Save the updated GraphInput struct to the data_path
            data.save(test_on_chain_data_path)?;
            data
        } else {
            self.load_inputs(data).await?;
            self.load_outputs(data).await?;
            data.clone()
        };

        // load the module settings
        self.module_settings = ModuleSettings::from(&data);

        // quantize the supplied data using the provided scale.
        // the ordering here is important, we want the inputs to come before the outputs
        // as they are configured in that order as Column<Instances>
        let mut public_inputs = vec![];
        if self.settings.run_args.input_visibility.is_public() {
            public_inputs = self.inputs.clone();
        }
        if self.settings.run_args.output_visibility.is_public() {
            public_inputs.extend(self.outputs.clone());
        }
        info!(
            "public inputs lengths: {:?}",
            public_inputs
                .iter()
                .map(|i| i.len())
                .collect::<Vec<usize>>()
        );
        trace!("{:?}", public_inputs);

        let mut pi_inner: Vec<Vec<Fp>> = public_inputs
            .iter()
            .map(|i| {
                i.iter()
                    .map(|e| i128_to_felt::<Fp>(*e))
                    .collect::<Vec<Fp>>()
            })
            .collect::<Vec<Vec<Fp>>>();

        let module_instances =
            GraphModules::public_inputs(&data, VarVisibility::from_args(self.settings.run_args)?);

        if !module_instances.is_empty() {
            pi_inner.extend(module_instances);
        }

        Ok(pi_inner)
    }

    /// Prepare the public inputs for wasm circuit.
    pub fn prepare_file_public_inputs(
        &mut self,
        data: &GraphWitness
    ) -> Result<Vec<Vec<Fp>>, Box<dyn std::error::Error>> {
        let out_scales = self.model.graph.get_output_scales();

        let input_data = match &data.input_data {
            DataSource::File(input_data) => input_data,
            _ => 
                panic!(
                "Cannot use on-chain data source as input for on-chain test. 
                Will manually populate on-chain data from file source instead"
            )
        };
        
        self.load_file_inputs(input_data);
        // load the module settings
        self.module_settings = ModuleSettings::from(data);
        
        // quantize the supplied data using the provided scale.
        // the ordering here is important, we want the inputs to come before the outputs
        // as they are configured in that order as Column<Instances>
        let mut public_inputs = vec![];
        if self.settings.run_args.input_visibility.is_public() {
            public_inputs = self.inputs.clone();
        }
        if self.settings.run_args.output_visibility.is_public() {
            let output_data = match &data.output_data {
                DataSource::File(output_data) => output_data,
                _ => 
                    panic!(
                    "Cannot use on-chain data source as input for on-chain test. 
                    Will manually populate on-chain data from file source instead"
                )
            };
            for (idx, v) in output_data.iter().enumerate() {
                let t: Vec<i128> = v
                    .par_iter()
                    .map(|x| quantize_float(x, 0.0, out_scales[idx]).unwrap())
                    .collect();

                let t: Tensor<i128> = t.into_iter().into();

                public_inputs.push(t);
            }
        }
        info!(
            "public inputs lengths: {:?}",
            public_inputs
                .iter()
                .map(|i| i.len())
                .collect::<Vec<usize>>()
        );
        trace!("{:?}", public_inputs);

        let mut pi_inner: Vec<Vec<Fp>> = public_inputs
            .iter()
            .map(|i| {
                i.iter()
                    .map(|e| i128_to_felt::<Fp>(*e))
                    .collect::<Vec<Fp>>()
            })
            .collect::<Vec<Vec<Fp>>>();

        let module_instances =
            GraphModules::public_inputs(data, VarVisibility::from_args(self.settings.run_args)?);

        if !module_instances.is_empty() {
            pi_inner.extend(module_instances);
        }

        Ok(pi_inner)
    }
}



impl Circuit<Fp> for GraphCircuit {
    type Config = GraphConfig;
    type FloorPlanner = ModulePlanner;
    type Params = GraphSettings;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn params(&self) -> Self::Params {
        // safe to clone because the model is Arc'd
        self.settings.clone()
    }

    fn configure_with_params(cs: &mut ConstraintSystem<Fp>, params: Self::Params) -> Self::Config {
        let visibility = VarVisibility::from_args(params.run_args).unwrap();

        let mut vars = ModelVars::new(
            cs,
            params.run_args.logrows as usize,
            params.num_constraints,
            params.model_instance_shapes.clone(),
            visibility.clone(),
            params.run_args.scale,
        );

        let base = Model::configure(
            cs,
            &mut vars,
            params.run_args.bits,
            params.required_lookups,
            params.check_mode,
        )
        .unwrap();

        let model_config = ModelConfig { base, vars };

        let module_configs = ModuleConfigs::from_visibility(cs, visibility, params.module_sizes);

        GraphConfig {
            model_config,
            module_configs,
        }
    }

    fn configure(_: &mut ConstraintSystem<Fp>) -> Self::Config {
        unimplemented!("you should call configure_with_params instead")
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), PlonkError> {
        trace!("Setting input in synthesize");
        let mut inputs = self
            .inputs
            .iter()
            .map(|i| ValTensor::from(<Tensor<i128> as Into<Tensor<Value<Fp>>>>::into(i.clone())))
            .collect::<Vec<ValTensor<Fp>>>();

        let mut instance_offset = ModuleInstanceOffset::new();
        // we reserve module 0 for poseidon
        // we reserve module 1 for elgamal
        GraphModules::layout(
            &mut layouter,
            &config.module_configs,
            &mut inputs,
            self.settings.run_args.input_visibility,
            &mut instance_offset,
            &self.module_settings.input,
        )?;

        // now we need to flatten the params
        let mut flattened_params = vec![];
        if !self.model.get_all_consts().is_empty() {
            flattened_params =
                vec![
                    flatten_valtensors(self.model.get_all_consts()).map_err(|_| {
                        log::error!("failed to flatten params");
                        PlonkError::Synthesis
                    })?,
                ];
        }

        // now do stuff to the model params
        GraphModules::layout(
            &mut layouter,
            &config.module_configs,
            &mut flattened_params,
            self.settings.run_args.param_visibility,
            &mut instance_offset,
            &self.module_settings.params,
        )?;

        // now we need to assign the flattened params to the model
        let mut model = self.model.clone();
        if !self.model.get_all_consts().is_empty() {
            // now the flattened_params have been assigned to and we-assign them to the model consts such that they are constrained to be equal
            model.replace_consts(
                split_valtensor(flattened_params[0].clone(), self.model.const_shapes()).map_err(
                    |_| {
                        log::error!("failed to replace params");
                        PlonkError::Synthesis
                    },
                )?,
            );
        }

        // create a new module for the model (space 2)
        layouter.assign_region(|| "_new_module", |_| Ok(()))?;
        trace!("Laying out model");
        let mut outputs = model
            .layout(
                config.model_config.clone(),
                &mut layouter,
                &self.settings.run_args,
                &inputs,
                &config.model_config.vars,
            )
            .map_err(|e| {
                log::error!("{}", e);
                PlonkError::Synthesis
            })?;

        // this will re-enter module 0
        GraphModules::layout(
            &mut layouter,
            &config.module_configs,
            &mut outputs,
            self.settings.run_args.output_visibility,
            &mut instance_offset,
            &self.module_settings.output,
        )?;

        Ok(())
    }
}