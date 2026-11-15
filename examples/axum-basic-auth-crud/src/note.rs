use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::method_routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

pub(crate) const NOTES_API_BASE_PATH: &str = "/v1/notes";

#[derive(Serialize)]
struct NoteCreatedResponse {
    id: u32,
}

#[derive(Serialize)]
struct NoteErrorResponse {
    error: Error,
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
        .route("/", post(create_note))
        .route(
            "/{id}",
            get(read_note_by_id).put(replace_note).delete(delete_note),
        )
        .with_state(note_repository)
}

async fn create_note(
    State(note_repo): State<NoteRepository>,
    Json(payload): Json<Note>,
) -> Result<(StatusCode, Json<NoteCreatedResponse>), (StatusCode, Json<NoteErrorResponse>)> {
    let index = note_repo
        .create(payload)
        .await
        .map_err(|e| (StatusCode::from(&e), Json(NoteErrorResponse { error: e })))?;
    Ok((StatusCode::OK, Json(NoteCreatedResponse { id: index })))
}

async fn delete_note(
    State(note_repo): State<NoteRepository>,
    Path(id): Path<u32>,
) -> Result<StatusCode, (StatusCode, Json<NoteErrorResponse>)> {
    let _ = note_repo
        .delete(id)
        .await
        .map_err(|e| (StatusCode::from(&e), Json(NoteErrorResponse { error: e })))?;
    Ok(StatusCode::OK)
}

async fn replace_note(
    State(note_repo): State<NoteRepository>,
    Path(id): Path<u32>,
    Json(payload): Json<Note>,
) -> Result<StatusCode, (StatusCode, Json<NoteErrorResponse>)> {
    let _ = note_repo
        .replace(id, payload)
        .await
        .map_err(|e| (StatusCode::from(&e), Json(NoteErrorResponse { error: e })))?;
    Ok(StatusCode::OK)
}

async fn read_note_by_id(
    State(note_repo): State<NoteRepository>,
    Path(id): Path<u32>,
) -> Result<(StatusCode, Json<Note>), (StatusCode, Json<NoteErrorResponse>)> {
    tracing::info!(note_id = %id, "Getting note");
    simulate_hard_job(3).await;
    let note = note_repo
        .read(id)
        .await
        .map_err(|e| (StatusCode::from(&e), Json(NoteErrorResponse { error: e })))?;
    Ok((StatusCode::OK, Json(note)))
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Note {
    title: String,
    content: String,
}

impl Note {
    pub(crate) fn new(title: &str, content: &str) -> Self {
        Self {
            title: title.to_owned(),
            content: content.to_owned(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct NoteRepository {
    inner: Arc<RwLock<(u32, HashMap<u32, Note>)>>,
}

#[derive(Serialize)]
pub(crate) enum Error {
    NotFound,
}

impl NoteRepository {
    pub(crate) fn new(initial_notes: Vec<Note>) -> Self {
        let mut notes = HashMap::new();
        for (num, note) in initial_notes.into_iter().enumerate() {
            notes.insert(<usize as TryInto<u32>>::try_into(num).unwrap() + 1, note);
        }

        Self {
            inner: Arc::new(RwLock::new((
                <usize as TryInto<u32>>::try_into(notes.len()).unwrap(),
                notes,
            ))),
        }
    }

    pub(crate) async fn create(&self, note: Note) -> Result<u32, Error> {
        let &mut (ref mut index, ref mut notes) = &mut *self.inner.write().await;
        *index += 1;
        notes.insert(*index, note);
        Ok(*index)
    }

    pub(crate) async fn delete(&self, id: u32) -> Result<bool, Error> {
        let notes = &mut self.inner.write().await.1;
        notes.remove(&id);
        Ok(true)
    }

    pub(crate) async fn replace(&self, id: u32, note: Note) -> Result<bool, Error> {
        let notes = &mut self.inner.write().await.1;
        notes.insert(id, note);
        Ok(true)
    }

    pub(crate) async fn read(&self, id: u32) -> Result<Note, Error> {
        let notes = &self.inner.read().await.1;
        let note = notes.get(&id).ok_or(Error::NotFound)?;
        Ok(note.clone())
    }
}

async fn simulate_hard_job(secs: usize) {
    tokio::time::sleep(std::time::Duration::from_secs(secs.try_into().unwrap())).await;
}
