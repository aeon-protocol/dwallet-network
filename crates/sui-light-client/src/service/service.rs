use anyhow::{Context, Result};
use axum::{
    routing::{get, post},
    Router,
    Json,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use sui_types::{
    base_types::{ObjectID, ObjectRef, SequenceNumber},
    committee::Committee,
    crypto::AuthorityQuorumSignInfo,
    digests::TransactionDigest,
    effects::{TransactionEffects, TransactionEffectsAPI, TransactionEvents},
    message_envelope::Envelope,
    messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSummary, EndOfEpochData},
    object::{Data, Object},
};

use move_core_types::{
    account_address::AccountAddress, identifier::Identifier, language_storage::StructTag,
};

use std::{error::Error, str::FromStr};
use std::path::Path;
use sui_json_rpc_types::{
    Checkpoint, SuiEvent, SuiObjectDataOptions, SuiRawData, SuiTransactionBlockResponseOptions,
};
use sui_json_rpc_types::{CheckpointId, EventFilter, ObjectChange, SuiParsedData};
use sui_sdk::SuiClientBuilder;

use serde::{Deserialize, Serialize};
use std::{io::Read, sync::Arc};
use std::{fs, io::Write, path::PathBuf};
use anyhow::{anyhow, Ok};

use sui_rest_api::{CheckpointData, Client};
use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
};




#[tokio::main]
async fn main() -> Result<()> {
    let server_url = "0.0.0.0:6920";

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let app = Router::new().route("/gettxdata", get(get_tx_data));
        // .layer(
        //     CorsLayer::new()
        //         .allow_methods(Any)
        //         .allow_origin(Any)
        //         .allow_headers(Any),
        // );

    println!("Starting server on address {}", server_url);

    let handle = tokio::spawn(async move {
        // let listener = tokio::net::TcpListener::bind(&server_url).await.unwrap();

        println!("Listening WS and HTTP on address {}", server_url);
        axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    tokio::join!(handle).0?;
    Ok(())
}


#[derive(Serialize, Deserialize, Clone)]
pub struct TxDataRequest {
    pub tx_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TxDataResponse {
    pub ckp_epoch_id: u64,
    pub checkpoint_summary_bytes: Vec<u8>,
    pub checkpoint_contents_bytes: Vec<u8>,
    pub transaction_bytes: Vec<u8>,
}


pub async fn get_tx_data(payload: Json<TxDataRequest>) -> impl IntoResponse {

    let tid = TransactionDigest::from_str(&payload.tx_id).unwrap();


    // TOOD don't hardcode
    let sui_client: Arc<sui_sdk::SuiClient> = Arc::new(
        SuiClientBuilder::default()
            .build(&"https://fullnode.devnet.sui.io:443")
            .await
            .unwrap(),
    );

    let options = SuiTransactionBlockResponseOptions::new();
    let seq = sui_client.read_api()
        .get_transaction_with_options(tid, options)
        .await
        .unwrap()
        .checkpoint
        .ok_or(anyhow!("Transaction not found")).unwrap();


    let rest_client: Client = Client::new("https://fullnode.devnet.sui.io:443/rest");
    let full_checkpoint = rest_client.get_full_checkpoint(seq).await.unwrap();


    // let ckp_epoch_id = full_checkpoint.checkpoint_summary.data().epoch;



    let (matching_tx, _) = full_checkpoint
        .transactions
        .iter()
        .zip(full_checkpoint.checkpoint_contents.iter())
        // Note that we get the digest of the effects to ensure this is
        // indeed the correct effects that are authenticated in the contents.
        .find(|(tx, digest)| {
            tx.effects.execution_digests() == **digest && digest.transaction == tid
        })
        .ok_or(anyhow!("Transaction not found in checkpoint contents")).unwrap();

    let res = TxDataResponse {
        ckp_epoch_id: full_checkpoint.checkpoint_summary.data().epoch,
        checkpoint_summary_bytes: bcs::to_bytes(&full_checkpoint.checkpoint_summary).unwrap(),
        checkpoint_contents_bytes: bcs::to_bytes(&full_checkpoint.checkpoint_contents).unwrap(),
        transaction_bytes: bcs::to_bytes(&matching_tx).unwrap(),
    };

    (StatusCode::OK, Json(res)).into_response()
}


// import error and result
