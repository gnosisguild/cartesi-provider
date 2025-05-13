use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{Address, Bytes},
    providers::fillers::{ChainIdFiller, GasFiller, JoinFill, NonceFiller, WalletFiller},
    providers::{Identity, ProviderBuilder, RootProvider, fillers::FillProvider},
    signers::local::PrivateKeySigner,
    sol,
    transports::BoxTransport,
};
use eyre::Result;
use std::env;
use std::sync::Arc;
use tokio::runtime::Runtime;
use compute_provider::FHEInputs;
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe_traits::{
    Deserialize, DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter,
    Serialize,
};
use hyper::{body, Body, Client, Method, Request};
use rand::thread_rng;
use serde_json::json;
use std::error::Error;

fn create_params() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(2048)
        .set_plaintext_modulus(1_032_193)
        .set_moduli(&[0xffff_ffff_0000_01])
        .build_arc()
        .expect("failed to build params")
}

fn generate_keys(params: &Arc<BfvParameters>) -> (SecretKey, PublicKey) {
    let mut rng = thread_rng();
    let sk = SecretKey::random(params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);
    (sk, pk)
}

fn encrypt_inputs(
    inputs: &[u64],
    pk: &PublicKey,
    params: &Arc<BfvParameters>,
) -> Vec<Ciphertext> {
    let mut rng = thread_rng();
    inputs
        .iter()
        .map(|&x| {
            let pt = Plaintext::try_encode(&[x], Encoding::poly(), params).unwrap();
            pk.try_encrypt(&pt, &mut rng).unwrap()
        })
        .collect()
}

fn generate_inputs() -> (FHEInputs, SecretKey) {
    let params = create_params();
    let (sk, pk) = generate_keys(&params);

    let clear: Vec<u64> = (1..=2).collect(); // demo data 1 + 2
    let enc = encrypt_inputs(&clear, &pk, &params);
    let ciphertexts = enc.into_iter().map(|c| (c.to_bytes(), 1)).collect();

    (
        FHEInputs {
            ciphertexts,
            params: params.to_bytes(),
        },
        sk,
    )
}

fn decrypt_result(ct_bytes: &[u8], params_bytes: &[u8], sk: &SecretKey) -> u64 {
    let params = Arc::new(BfvParameters::try_deserialize(params_bytes).unwrap());
    let ct = Ciphertext::from_bytes(ct_bytes, &params).unwrap();
    let pt = sk.try_decrypt(&ct).unwrap();
    Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap()[0]
}

async fn latest_report(
    client: &Client<hyper::client::HttpConnector>,
    graphql_url: &str,
) -> Result<Option<String>, Box<dyn Error>> {
    let q = json!({
        "query": "query { reports(last:1) { edges { node { payload } } } }"
    })
    .to_string();

    let req = Request::builder()
        .method(Method::POST)
        .uri(graphql_url)
        .header("content-type", "application/json")
        .body(Body::from(q))?;

    let resp = client.request(req).await?;
    let bytes = body::to_bytes(resp).await?;
    let val: serde_json::Value = serde_json::from_slice(&bytes)?;

    Ok(val["data"]["reports"]["edges"]
        .get(0)
        .and_then(|e| e["node"]["payload"].as_str())
        .map(str::to_owned))
}


sol! {
    #[derive(Debug)]
    #[sol(rpc)]
    interface InputBox {
        function addInput(address _dapp, bytes _input) external;
    }
}

type CRISPProvider = FillProvider<
    JoinFill<
        JoinFill<JoinFill<JoinFill<Identity, GasFiller>, NonceFiller>, ChainIdFiller>,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<BoxTransport>,
    BoxTransport,
    Ethereum,
>;

fn main() -> Result<()> {
    let rpc_url = env::var("HTTP_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into());
    let pk = env::var("PRIVATE_KEY").unwrap_or_else(|_| {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into()
    });
    let ib_addr = env::var("INPUTBOX_ADDRESS")
        .unwrap_or_else(|_| "0x59b22D57D4f067708AB0c00552767405926dc768".into());
    let dapp = env::var("DAPP_ADDRESS")
        .unwrap_or_else(|_| "0xab7528bb862fB57E8A2BCd567a2e929a0Be56a5e".into());

    let rt = Runtime::new()?;
    rt.block_on(async move {
        // ───────── provider + wallet ─────────
        let signer: PrivateKeySigner = pk.parse()?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_builtin(&rpc_url)
            .await?;
        let provider = Arc::new(provider) as Arc<CRISPProvider>;

        // ───────── contract handle ─────────
        let ib: Address   = ib_addr.parse()?;
        let dapp: Address = dapp.parse()?;
        let contract = InputBox::new(ib, &provider);

        // ───────── make payload ─────────
        let (fhe_inputs, _) = generate_inputs();
        let payload_json = serde_json::to_vec(&fhe_inputs)?;

        // 🔵 1.  raw bytes, not hex string
        let data: Bytes = payload_json.into();

        // 🔵 2. build call
        let call = contract.addInput(dapp, data);

        //        automatic estimate works again
        // 🔵 3. optional manual cap
        let call = call.gas(20_000_000u64.into());

        // send & wait
        let receipt = call.send().await?
            .get_receipt()
            .await.unwrap();

        println!(
            "✅ tx mined in block {:?}, gas used {}",
            receipt.block_number,
            receipt.gas_used
        );
        Ok(())
    })
}
