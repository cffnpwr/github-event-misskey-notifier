use anyhow::{anyhow, Ok, Result};
use log::*;
use ring::{
    error::Unspecified,
    hmac::{self, HMAC_SHA256},
};
use std::{env, fs::read_to_string, net::SocketAddr, num::ParseIntError};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct GHUser {
    login: String,
}

#[derive(Serialize, Deserialize)]
struct GHIssue {
    number: i64,
    html_url: String,
    title: String,
    body: String,
}

#[derive(Serialize, Deserialize)]
struct GHIssueComment {
    html_url: String,
    body: String,
    user: GHUser,
}

#[derive(Serialize, Deserialize)]
struct GHRelease {
    tag_name: String,
    html_url: String,
    body: String,
}

#[derive(Serialize, Deserialize)]
struct GHPullRequest {
    number: i64,
    html_url: String,
    title: String,
    body: String,
    user: GHUser,
    merged: bool,
}

#[derive(Serialize, Deserialize)]
struct GHPayload {
    action: String,
    sender: GHUser,
    issue: Option<GHIssue>,
    comment: Option<GHIssueComment>,
    release: Option<GHRelease>,
    pull_request: Option<GHPullRequest>,
}

#[derive(Serialize, Deserialize)]
struct MkNote {
    i: Option<String>,
    cw: Option<String>,
    text: String,
}

#[derive(Clone, Deserialize)]
struct Secret {
    webhook_path: String,
    webhook_secret: String,
    misskey_insrance: String,
    misskey_api_secret: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env::set_var("RUST_LOG", "info");
    env_logger::init();

    let secret_str = read_to_string("./config.toml")?;
    let secret: Secret = toml::from_str(&secret_str)?;

    let server = Router::new()
        .route(&secret.webhook_path, post(handler))
        .with_state(secret);
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    info!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(server.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn handler(
    headers: HeaderMap,
    State(secret): State<Secret>,
    body: String,
) -> (StatusCode, Json<()>) {
    if let Some(hash) = headers.get("X-Hub-Signature-256") {
        if let core::result::Result::Ok(_) = verify_signature(
            &body,
            hash.to_str().unwrap().to_owned(),
            &secret.webhook_secret,
        ) {
            let event = headers.get("X-GitHub-Event").unwrap().to_str().unwrap();
            if let core::result::Result::Ok(payload) = serde_json::from_str(&body) {
                let msg = match event {
                    "issues" => build_issue_event_note(payload),
                    "issue_comment" => build_issue_comment_event_note(payload),
                    "pull_request" => build_pull_request_event_note(payload),
                    "release" => build_release_event_note(payload),
                    _ => return (StatusCode::NO_CONTENT, Json(())),
                };

                match msg {
                    core::result::Result::Ok(body) => match post_note(body, secret).await {
                        core::result::Result::Ok(_) => return (StatusCode::CREATED, Json(())),
                        Err(e) => {
                            error!("{}", e.to_string());

                            return (StatusCode::INTERNAL_SERVER_ERROR, Json(()));
                        }
                    },
                    Err(_) => return (StatusCode::NO_CONTENT, Json(())),
                }
            }
        }

        warn!("Signature unmatch");
    }
    (StatusCode::UNAUTHORIZED, Json(()))
}

fn verify_signature(payload: &String, hash: String, secret: &String) -> Result<(), Unspecified> {
    let key = hmac::Key::new(HMAC_SHA256, secret.as_bytes());

    hmac::verify(
        &key,
        payload.as_bytes(),
        &decode_hex(hash.replace("sha256=", "").as_str()).unwrap(),
    )
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

async fn post_note(mut body: MkNote, secret: Secret) -> Result<()> {
    body.i = Some(secret.misskey_api_secret);

    let client = reqwest::Client::new();
    let status = client
        .post(format!(
            "https://{}/api/notes/create",
            secret.misskey_insrance
        ))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .await?
        .status();

    if let StatusCode::OK = status {
        Ok(())
    } else {
        Err(anyhow!("status: {}", status))
    }
}

fn build_issue_event_note(payload: GHPayload) -> Result<MkNote> {
    let issue = payload.issue.unwrap();

    let title = match payload.action.as_str() {
        "opened" => "🤔 Issue opened",
        "reopened" => "🤯 Issue reopened",
        "closed" => "🫡 Issue closed",
        _ => return Err(anyhow!("")),
    };

    let body = format!(
        "{} [#{}: {}]({})\n{}",
        title, issue.number, issue.title, issue.html_url, issue.body
    );

    Ok(MkNote {
        i: None,
        cw: None,
        text: body,
    })
}

fn build_issue_comment_event_note(payload: GHPayload) -> Result<MkNote> {
    let issue = payload.issue.unwrap();
    let issue_comment = payload.comment.unwrap();

    let title = match payload.action.as_str() {
        "created" => "💭 Issue commented on",
        _ => return Err(anyhow!("")),
    };

    let body = format!(
        "{} [#{}: {}]({})\n{}「{}」",
        title,
        issue.number,
        issue.title,
        issue_comment.html_url,
        issue_comment.user.login,
        issue_comment.body
    );

    Ok(MkNote {
        i: None,
        cw: None,
        text: body,
    })
}

fn build_pull_request_event_note(payload: GHPayload) -> Result<MkNote> {
    let pull_request = payload.pull_request.unwrap();

    let title = match payload.action.as_str() {
        "opened" => "🤓 Pull request opened",
        "reopened" => "🥴 Pull request reopened",
        "closed" => {
            if pull_request.merged {
                "🥰 Pull request merged"
            } else {
                "🤬 Pull request rejected"
            }
        }
        _ => return Err(anyhow!("")),
    };

    let body = format!(
        "{} [#{}: {}]({})\n{}",
        title, pull_request.number, pull_request.title, pull_request.html_url, pull_request.body
    );

    Ok(MkNote {
        i: None,
        cw: None,
        text: body,
    })
}

fn build_release_event_note(payload: GHPayload) -> Result<MkNote> {
    let release = payload.release.unwrap();

    let body = match payload.action.as_str() {
        "published" => format!(
            "🥳 [{}]({}) released!!\n{}",
            release.tag_name, release.html_url, release.body
        ),
        _ => return Err(anyhow!("")),
    };

    Ok(MkNote {
        i: None,
        cw: None,
        text: body,
    })
}
