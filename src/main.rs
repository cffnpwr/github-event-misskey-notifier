use anyhow::{anyhow, Ok, Result};
use log::*;
use ring::{
    error::Unspecified,
    hmac::{self, HMAC_SHA256},
};
use std::{env, fs::read_to_string, net::SocketAddr};

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
    comment: String,
    text: String,
}

#[derive(Clone, Deserialize)]
struct Secret {
    webhook_secret: String,
    misskey_insrance: String,
    misskey_api_secret: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env::set_var("RUST_LOG", "info");
    env_logger::init();

    let secret_str = read_to_string("./config.toml")?;
    let secret = toml::from_str(&secret_str)?;

    let server = Router::new()
        .route("/github/cffnpwr/ghemn/", post(handler))
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
    payload: String,
) -> (StatusCode, Json<()>) {
    if let Some(hash) = headers.get("X-Hub-Signature-256") {
        let payload = serde_json::from_str(&payload).unwrap();

        if let core::result::Result::Ok(_) = verify_signature(
            serde_json::to_string(&payload).unwrap(),
            hash.to_str().unwrap().to_owned(),
            &secret.webhook_secret,
        ) {
            let event = headers.get("X-GitHub-Event").unwrap().to_str().unwrap();

            let msg = match event {
                "issue" => build_issue_event_note(payload),
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

        warn!("Signature unmatch");
    }

    warn!("Don't have \"X-Hub-Signature-256\" header");
    (StatusCode::UNAUTHORIZED, Json(()))
}

fn verify_signature(payload: String, hash: String, secret: &String) -> Result<(), Unspecified> {
    let key = hmac::Key::new(HMAC_SHA256, secret.as_bytes());

    hmac::verify(
        &key,
        payload.as_bytes(),
        hash.replace("sha256=", "").as_bytes(),
    )
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

    if let StatusCode::CREATED = status {
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

    let comment = format!(
        "{} [#{}: {}]({})",
        title, issue.number, issue.title, issue.html_url
    );
    let body = format!("{}", issue.body);

    Ok(MkNote {
        i: None,
        comment,
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

    let comment = format!(
        "{} [#{}: {}]({})",
        title, issue.number, issue.title, issue_comment.html_url
    );
    let body = format!("{}「{}」", issue_comment.user.login, issue_comment.body);

    Ok(MkNote {
        i: None,
        comment,
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

    let comment = format!(
        "{} [#{}: {}]({})",
        title, pull_request.number, pull_request.title, pull_request.html_url
    );
    let body = format!("{}", pull_request.body);

    Ok(MkNote {
        i: None,
        comment,
        text: body,
    })
}

fn build_release_event_note(payload: GHPayload) -> Result<MkNote> {
    let release = payload.release.unwrap();

    let comment = match payload.action.as_str() {
        "published" => format!("🥳 [{}]({}) released!!", release.tag_name, release.html_url),
        _ => return Err(anyhow!("")),
    };
    let body = format!("{}", release.body);

    Ok(MkNote {
        i: None,
        comment,
        text: body,
    })
}
