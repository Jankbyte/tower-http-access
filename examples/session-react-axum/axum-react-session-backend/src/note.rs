use crate::principal::Principal;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::method_routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http_access_core::authentication::Authenticated;
use user_password_auth::Authority;

pub(crate) mod permissions {
    pub const CREATE_OWN_NOTE: &str = "CreateOwnNote";
    pub const REPLACE_OWN_NOTE: &str = "ReplaceOwnNote";
    pub const READ_OWN_NOTE: &str = "ReadOwnNote";
    pub const DELETE_OWN_NOTE: &str = "DeleteOwnNote";
    pub const READ_ALL_NOTES: &str = "ReadAllNotes";
}

#[derive(Serialize)]
struct NoteCreatedResponse {
    id: u32,
}

#[derive(Serialize)]
struct NoteErrorResponse {
    error: Error,
}

impl From<Error> for NoteErrorResponse {
    fn from(error: Error) -> Self {
        Self { error }
    }
}

impl From<&Error> for StatusCode {
    fn from(error: &Error) -> Self {
        match error {
            Error::NotFound => Self::NOT_FOUND,
        }
    }
}

pub(crate) fn create_notes_router(note_repository: NoteRepository) -> Router<()> {
    Router::new()
        .route("/v1/notes/", post(create_note).get(list_notes))
        .route(
            "/v1/notes/{id}",
            get(read_note_by_id).put(replace_note).delete(delete_note),
        )
        .with_state(note_repository)
}

#[derive(Serialize)]
struct NoteSummary {
    id: u32,
    title: String,
    owner: String,
}

fn has_permission(user: &Principal, permission: &str) -> bool {
    user.authorities.contains(&Authority::new(permission))
}

async fn list_notes(
    State(repo): State<NoteRepository>,
    Authenticated(user): Authenticated<Principal>,
) -> Result<Json<Vec<NoteSummary>>, (StatusCode, Json<NoteErrorResponse>)> {
    let read_all = has_permission(&user, permissions::READ_ALL_NOTES);
    let state = repo.inner.read().await;
    let mut notes: Vec<_> = state
        .1
        .iter()
        .filter(|note| read_all || note.owner == user.username)
        .map(|note| NoteSummary {
            id: note.id,
            title: note.title.clone(),
            owner: note.owner.clone(),
        })
        .collect();
    notes.sort_by_key(|note| note.id);
    Ok(Json(notes))
}

async fn create_note(
    State(note_repo): State<NoteRepository>,
    Authenticated(user): Authenticated<Principal>,
    Json(payload): Json<NoteInput>,
) -> Result<(StatusCode, Json<NoteCreatedResponse>), (StatusCode, Json<NoteErrorResponse>)> {
    let index = note_repo
        .create(Note::new(&payload.title, &payload.content, &user.username))
        .await
        .map_err(|e| (StatusCode::from(&e), Json(NoteErrorResponse::from(e))))?;
    Ok((StatusCode::OK, Json(NoteCreatedResponse { id: index })))
}

async fn delete_note(
    State(note_repo): State<NoteRepository>,
    Path(id): Path<u32>,
    Authenticated(user): Authenticated<Principal>,
) -> Result<StatusCode, (StatusCode, Json<NoteErrorResponse>)> {
    let _ = note_repo
        .delete(id, &user.username)
        .await
        .map_err(|e| (StatusCode::from(&e), Json(NoteErrorResponse::from(e))))?;
    Ok(StatusCode::OK)
}

async fn replace_note(
    State(note_repo): State<NoteRepository>,
    Path(id): Path<u32>,
    Authenticated(user): Authenticated<Principal>,
    Json(payload): Json<NoteInput>,
) -> Result<StatusCode, (StatusCode, Json<NoteErrorResponse>)> {
    let _ = note_repo
        .replace(
            id,
            Note::new(&payload.title, &payload.content, &user.username),
        )
        .await
        .map_err(|e| (StatusCode::from(&e), Json(NoteErrorResponse::from(e))))?;
    Ok(StatusCode::OK)
}

async fn read_note_by_id(
    State(note_repo): State<NoteRepository>,
    Path(id): Path<u32>,
    Authenticated(user): Authenticated<Principal>,
) -> Result<(StatusCode, Json<Note>), (StatusCode, Json<NoteErrorResponse>)> {
    let read_all = has_permission(&user, permissions::READ_ALL_NOTES);
    tracing::info!(note_id = %id, "Getting note");
    simulate_hard_job(3).await;
    let note = note_repo
        .read(id, &user.username, read_all)
        .await
        .map_err(|e| (StatusCode::from(&e), Json(NoteErrorResponse::from(e))))?;
    Ok((StatusCode::OK, Json(note)))
}

#[derive(Deserialize)]
struct NoteInput {
    title: String,
    content: String,
}

#[derive(Clone, Serialize)]
pub(crate) struct Note {
    id: u32,
    owner: String,
    title: String,
    content: String,
}

impl Note {
    pub(crate) fn new(title: &str, content: &str, owner: &str) -> Self {
        Self {
            id: 0,
            owner: owner.to_owned(),
            title: title.to_owned(),
            content: content.to_owned(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct NoteRepository {
    inner: Arc<RwLock<(u32, Vec<Note>)>>,
}

#[derive(Serialize)]
pub(crate) enum Error {
    NotFound,
}

impl NoteRepository {
    pub(crate) fn new(initial_notes: Vec<Note>) -> Self {
        let notes: Vec<_> = initial_notes
            .into_iter()
            .enumerate()
            .map(|(index, mut note)| {
                note.id = u32::try_from(index).unwrap() + 1;
                note
            })
            .collect();
        Self {
            inner: Arc::new(RwLock::new((u32::try_from(notes.len()).unwrap(), notes))),
        }
    }

    pub(crate) async fn create(&self, mut note: Note) -> Result<u32, Error> {
        let mut state = self.inner.write().await;
        state.0 += 1;
        note.id = state.0;
        state.1.push(note);
        Ok(state.0)
    }

    pub(crate) async fn delete(&self, id: u32, owner: &str) -> Result<bool, Error> {
        let notes = &mut self.inner.write().await.1;
        let index = notes
            .iter()
            .position(|note| note.id == id && note.owner == owner)
            .ok_or(Error::NotFound)?;
        notes.remove(index);
        Ok(true)
    }

    pub(crate) async fn replace(&self, id: u32, mut note: Note) -> Result<bool, Error> {
        let mut state = self.inner.write().await;
        let existing = state
            .1
            .iter_mut()
            .find(|existing| existing.id == id && existing.owner == note.owner)
            .ok_or(Error::NotFound)?;
        note.id = existing.id;
        note.owner = existing.owner.clone();
        *existing = note;
        Ok(true)
    }

    pub(crate) async fn read(&self, id: u32, owner: &str, read_all: bool) -> Result<Note, Error> {
        let notes = &self.inner.read().await.1;
        let note = notes
            .iter()
            .find(|note| note.id == id && (read_all || note.owner == owner))
            .ok_or(Error::NotFound)?;
        Ok(note.clone())
    }
}

async fn simulate_hard_job(secs: usize) {
    tokio::time::sleep(std::time::Duration::from_secs(secs.try_into().unwrap())).await;
}
