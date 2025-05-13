mod processor;

use compute_provider::FHEInputs;
use hex::{decode as hex_decode, encode as hex_encode};
use hyper::{body, Body, Client, Method, Request, StatusCode};
use json::{object, JsonValue};
use processor::fhe_processor;
use std::env;

type HClient = Client<hyper::client::HttpConnector>;

pub async fn handle_advance(
    client: &HClient,
    server_addr: &str,
    request: JsonValue,
) -> Result<&'static str, Box<dyn std::error::Error>> {
    println!("Received advance request data {}", request);

    let payload_hex = request["data"]["payload"]
        .as_str()
        .ok_or("Missing payload")?;
    let payload_bytes = hex_decode(payload_hex.trim_start_matches("0x"))?;

    let fhe_inputs: FHEInputs = serde_json::from_slice(&payload_bytes)?;

    let result_bytes = fhe_processor(&fhe_inputs);

    let report_payload = format!("0x{}", hex_encode(result_bytes));

    let report = object! { "payload" => report_payload };

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{}/report", server_addr))
        .header("content-type", "application/json")
        .body(Body::from(report.dump()))?;

    let resp = client.request(req).await?;
    println!("Sent report ⇒ status {}", resp.status());

    Ok("accept")
}

pub async fn handle_inspect(
    client: &HClient,
    server_addr: &str,
    request: JsonValue,
) -> Result<&'static str, Box<dyn std::error::Error>> {
    println!("Received inspect request data {}", request);

    let payload = request["data"]["payload"].clone();
    let report = object! { "payload" => payload };

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{}/report", server_addr))
        .header("content-type", "application/json")
        .body(Body::from(report.dump()))?;

    client.request(req).await?;
    Ok("accept")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let server_addr = env::var("ROLLUP_HTTP_SERVER_URL")?;

    let mut status = "accept";

    loop {
        let finish_req = object! { "status" => status };
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/finish", server_addr))
            .header("content-type", "application/json")
            .body(Body::from(finish_req.dump()))?;

        let resp = client.request(req).await?;
        println!("Received /finish status {}", resp.status());

        if resp.status() == StatusCode::ACCEPTED {
            println!("No pending rollup request, retrying …");
            continue;
        }

        let body_bytes = body::to_bytes(resp).await?;
        let req_json = json::parse(std::str::from_utf8(&body_bytes)?)?;

        status = match req_json["request_type"]
            .as_str()
            .ok_or("request_type not string")?
        {
            "advance_state" => handle_advance(&client, &server_addr, req_json).await?,
            "inspect_state" => handle_inspect(&client, &server_addr, req_json).await?,
            _ => {
                eprintln!("Unknown request type");
                "reject"
            }
        };
    }
}
