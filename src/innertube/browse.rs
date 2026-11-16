//! `browse` endpoint: playlist listing.
//!
//! YouTube reshuffles the playlist JSON layout every few months, so instead
//! of modelling every nesting level we walk the response tree and pick out
//! the renderer objects we care about. It is far more resilient than a strict
//! struct hierarchy.

use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::innertube::client::InnerTube;

#[derive(Debug, Clone)]
pub struct PlaylistItem {
    pub video_id: String,
    pub title: String,
    pub index: Option<u64>,
    pub duration_secs: Option<u64>,
}

/// Recursively collect the value of every `key` found in the tree.
fn find_all_by_key<'a>(value: &'a Value, key: &str, out: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            if let Some(inner) = map.get(key) {
                out.push(inner);
            }
            for v in map.values() {
                find_all_by_key(v, key, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                find_all_by_key(v, key, out);
            }
        }
        _ => {}
    }
}

fn find_continuation(value: &Value) -> Option<String> {
    let mut found = Vec::new();
    find_all_by_key(value, "continuationCommand", &mut found);
    for c in found {
        if let Some(token) = c.get("token").and_then(|t| t.as_str()) {
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    // `nextContinuationData` is used on some playlist pages.
    let mut next = Vec::new();
    find_all_by_key(value, "nextContinuationData", &mut next);
    for n in next {
        if let Some(token) = n.get("continuation").and_then(|t| t.as_str()) {
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// List every video in a playlist. Follows continuations until exhausted.
pub async fn playlist(it: &InnerTube, playlist_id: &str) -> Result<Vec<PlaylistItem>> {
    let mut items: Vec<PlaylistItem> = Vec::new();
    let mut continuation: Option<String> = None;
    let mut seen_tokens: Vec<String> = Vec::new();

    loop {
        let mut body = it.context_object().await;
        if let Some(token) = &continuation {
            body["continuation"] = json!(token);
        } else {
            body["browseId"] = json!(format!("VL{playlist_id}"));
        }

        let raw = it.post("browse", body).await?;
        items.extend(collect_items(&raw));

        match find_continuation(&raw) {
            Some(token) if !seen_tokens.contains(&token) => {
                seen_tokens.push(token.clone());
                continuation = Some(token);
            }
            _ => break,
        }
        if items.len() > 10_000 {
            break;
        }
    }

    Ok(items)
}

fn collect_items(raw: &Value) -> Vec<PlaylistItem> {
    let mut renderers = Vec::new();
    find_all_by_key(raw, "playlistVideoRenderer", &mut renderers);

    renderers
        .into_iter()
        .filter_map(|r| {
            let video_id = r.get("videoId")?.as_str()?.to_string();
            let title = r
                .get("title")
                .and_then(|t| {
                    t.get("runs")
                        .and_then(|runs| runs.as_array())
                        .map(|runs| {
                            runs.iter()
                                .filter_map(|x| x.get("text").and_then(|t| t.as_str()))
                                .collect::<String>()
                        })
                })
                .or_else(|| {
                    r.get("title")
                        .and_then(|t| t.get("simpleText"))
                        .and_then(|t| t.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_default();
            let index = r
                .get("index")
                .and_then(|i| i.get("simpleText"))
                .and_then(|t| t.as_str())
                .and_then(|t| t.parse::<u64>().ok());
            let duration_secs = r
                .get("lengthSeconds")
                .and_then(|d| d.as_str())
                .and_then(|d| d.parse::<u64>().ok());
            Some(PlaylistItem {
                video_id,
                title,
                index,
                duration_secs,
            })
        })
        .collect()
}

/// A channel that has been resolved to its id.
#[derive(Debug, Clone)]
pub struct Channel {
    /// The `UC...` id.
    pub id: String,
    /// The tab parameters the resolver handed back.
    pub params: String,
}

/// Resolve a channel URL (`@handle`, `/c/Name`, `/user/Name`, `/channel/UC...`)
/// to its channel id.
pub async fn resolve_channel(it: &InnerTube, url: &str) -> Result<Channel> {
    let mut body = it.context_object().await;
    body["url"] = serde_json::json!(url);

    let raw = it.post("navigation/resolve_url", body).await?;
    let browse_id = raw
        .get("endpoint")
        .and_then(|e| e.get("browseEndpoint"))
        .and_then(|b| b.get("browseId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Unavailable(format!("could not resolve the channel `{url}`")))?
        .to_string();
    let params = raw
        .get("endpoint")
        .and_then(|e| e.get("browseEndpoint"))
        .and_then(|b| b.get("params"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    Ok(Channel { id: browse_id, params })
}

/// The playlist that holds every video a channel uploaded.
///
/// It is the channel id with `UC` swapped for `UU`.
pub fn uploads_playlist_id(channel_id: &str) -> String {
    if let Some(rest) = channel_id.strip_prefix("UC") {
        format!("UU{rest}")
    } else {
        channel_id.to_string()
    }
}

/// The videos of a channel, in the same shape as a playlist.
pub async fn channel_videos(it: &InnerTube, channel_id: &str) -> Result<Vec<PlaylistItem>> {
    let playlist_id = uploads_playlist_id(channel_id);
    playlist(it, &playlist_id).await
}

/// The playlists of a channel.
pub async fn channel_playlists(
    it: &InnerTube,
    channel_id: &str,
    params: &str,
) -> Result<Vec<(String, String)>> {
    let mut body = it.context_object().await;
    body["browseId"] = serde_json::json!(channel_id);
    if !params.is_empty() {
        body["params"] = serde_json::json!(params);
    }

    let raw = it.post("browse", body).await?;
    let mut out = Vec::new();
    collect_playlists(&raw, &mut out);

    if out.is_empty() {
        // The playlists tab needs its own parameters; try the encoded form.
        for candidate in ["EgIQABABGAA", "EgZ2aWRlb3PyBgQKAjIA", "EgIQAg%3D%3D"] {
            let mut body = it.context_object().await;
            body["browseId"] = serde_json::json!(channel_id);
            body["params"] = serde_json::json!(candidate);
            if let Ok(raw) = it.post("browse", body).await {
                collect_playlists(&raw, &mut out);
                if !out.is_empty() {
                    break;
                }
            }
        }
    }

    Ok(out)
}

/// The playlists of a channel, taken from the channel page.
///
/// Browsing a channel page through the API needs a PO token now, so the
/// page itself is parsed instead.
pub fn playlists_from_page(data: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    collect_lockups(data, &mut out);
    out
}

/// Walk the page data looking for the playlist entries.
fn collect_lockups(value: &Value, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            if let Some(id) = map.get("contentId").and_then(|c| c.as_str()) {
                if id.starts_with("PL") {
                    let title = map
                        .get("metadata")
                        .and_then(|m| m.get("lockupMetadataViewModel"))
                        .and_then(|m| m.get("title"))
                        .and_then(|t| t.get("content"))
                        .and_then(|c| c.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if !out.iter().any(|(existing, _)| existing == id) {
                        out.push((id.to_string(), title));
                    }
                }
            }
            for v in map.values() {
                collect_lockups(v, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                collect_lockups(v, out);
            }
        }
        _ => {}
    }
}

/// Pull the playlists out of a browse response.
fn collect_playlists(value: &Value, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            if let Some(renderer) = map.get("playlistRenderer") {
                let id = renderer.get("playlistId").and_then(|v| v.as_str()).unwrap_or("");
                let title = renderer
                    .get("title")
                    .map(|t| {
                        t.get("runs")
                            .and_then(|r| r.as_array())
                            .map(|runs| {
                                runs.iter()
                                    .filter_map(|r| r.get("text").and_then(|t| t.as_str()))
                                    .collect::<String>()
                            })
                            .or_else(|| {
                                t.get("simpleText").and_then(|t| t.as_str()).map(str::to_string)
                            })
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();
                if !id.is_empty() {
                    out.push((id.to_string(), title));
                }
            }
            for v in map.values() {
                collect_playlists(v, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                collect_playlists(v, out);
            }
        }
        _ => {}
    }
}
