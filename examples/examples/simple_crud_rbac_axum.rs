//! ```not_rust
//! # Start
//! cargo run --example simple_crud_rbac_axum
//! # Get note
//! curl -v -X GET http://127.0.0.1:3000/v1/notes/1
//! # Delete note
//! curl -v -X DELETE http://127.0.0.1:3000/v1/notes/1
//! # Create note as anonymous (401)
//! curl -v -X POST -H "Content-Type: application/json" --data '{"title":"Test","content":"Hello"}' "http://127.0.0.1:3000/v1/notes"
//! # Create note as admin (200)
//! curl -v -X POST -u "admin:admin123" -H "Content-Type: application/json" --data '{"title":"Test","content":"Hello"}' "http://127.0.0.1:3000/v1/notes"
//! # Create note as reader (403)
//! curl -v -X POST -u "onlyreader:onlyreader123" -H "Content-Type: application/json" --data '{"title":"Test","content":"Hello"}' "http://127.0.0.1:3000/v1/notes"
//!
//! ```
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{Method, StatusCode, request::Parts},
    routing::method_routing::{get, post},
};
use axum_auth_chained::{
    SecurityLayerBuilder,
    authentication::{RequestAuthenticator, RequestAuthenticatorExt},
    authorization::{
        AuthenticationEntryPoint, AuthorizationLayer, DefaultAuthorizationFailureHandler,
    },
    basic::{
        Authority, BasicRequestAuthenticator, HasAuthorities, InMemoryUserDetailService,
        PlainHashPasswordManager, RequestAuthorizationProvider, RequestContext, UserDetail,
        UserDetailAuthenticationProvider, request_context_mapper,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let note_repository = NoteRepository::new(vec![
        Note::new("About Rust", "Tech page about rust"),
        Note::new("Prepare to rust interview", "Preparing to rust interview"),
    ]);

    let basic_authenticator = Arc::new(create_basic_authenticator().await);
    let authorization_layer = create_authorization_layer(Arc::clone(&basic_authenticator));

    let security_layer = SecurityLayerBuilder::builder()
        .authenticators(|authenticators| authenticators.shared_authenticator(basic_authenticator))
        .authorization_layer(authorization_layer)
        .build();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    let notes_api = Router::new()
        .route("/", post(create_note))
        .route(
            "/{id}",
            get(read_note_by_id).put(replace_note).delete(delete_note),
        )
        .layer(security_layer) // apply layer only for Notes API
        .with_state(note_repository);

    let app = Router::new().nest("/v1/notes", notes_api);

    let _ = axum::serve(listener, app).await;
}

#[derive(Serialize)]
struct NoteCreatedResponse {
    id: u32,
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
    let note = note_repo
        .read(id)
        .await
        .map_err(|e| (StatusCode::from(&e), Json(NoteErrorResponse { error: e })))?;
    Ok((StatusCode::OK, Json(note)))
}

#[derive(Clone, Serialize, Deserialize)]
struct Note {
    title: String,
    content: String,
}

impl Note {
    fn new(title: &str, content: &str) -> Self {
        Self {
            title: title.to_owned(),
            content: content.to_owned(),
        }
    }
}

#[derive(Clone)]
struct NoteRepository {
    inner: Arc<RwLock<(u32, HashMap<u32, Note>)>>,
}

#[derive(Serialize)]
struct NoteErrorResponse {
    error: NoteError,
}

impl From<&NoteError> for StatusCode {
    fn from(error: &NoteError) -> Self {
        match error {
            NoteError::NotFound => Self::NOT_FOUND,
        }
    }
}

#[derive(Serialize)]
enum NoteError {
    NotFound,
}

impl NoteRepository {
    fn new(initial_notes: Vec<Note>) -> Self {
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

    async fn create(&self, note: Note) -> Result<u32, NoteError> {
        let &mut (ref mut index, ref mut notes) = &mut *self.inner.write().await;
        *index += 1;
        notes.insert(*index, note);
        Ok(*index)
    }

    async fn delete(&self, id: u32) -> Result<bool, NoteError> {
        let notes = &mut self.inner.write().await.1;
        notes.remove(&id);
        Ok(true)
    }

    async fn replace(&self, id: u32, note: Note) -> Result<bool, NoteError> {
        let notes = &mut self.inner.write().await.1;
        notes.insert(id, note);
        Ok(true)
    }

    async fn read(&self, id: u32) -> Result<Note, NoteError> {
        let notes = &self.inner.read().await.1;
        let note = notes.get(&id).ok_or(NoteError::NotFound)?;
        Ok(note.clone())
    }
}

// A local wrapper lets us implement HasAuthorities while sharing the identity on clone.
// We care about this, because user detail is "heavy" struct, that has many allocations on clone.
#[derive(Clone)]
struct SharedUser(Arc<UserDetail>);

impl From<UserDetail> for SharedUser {
    fn from(user_detail: UserDetail) -> Self {
        SharedUser(Arc::new(user_detail))
    }
}

impl HasAuthorities for SharedUser {
    fn has_authority(&self, authority: &str) -> bool {
        self.0.has_authority(authority)
    }
}

async fn create_basic_authenticator()
-> impl RequestAuthenticator<Authentication = SharedUser> + AuthenticationEntryPoint {
    let manager = PlainHashPasswordManager; // DONT use in production

    let create = Authority::new("CreateNote");
    let replace = Authority::new("ReplaceNote");
    let read = Authority::new("ReadNote");
    let delete = Authority::new("DeleteNote");

    let raw_users = vec![
        UserDetail::new(
            "admin",
            "admin123",
            vec![
                create.clone(),
                replace.clone(),
                read.clone(),
                delete.clone(),
            ],
        ),
        UserDetail::new("onlyreader", "onlyreader123", vec![read.clone()]),
    ];

    let user_detail_service = InMemoryUserDetailService::new((&manager, raw_users))
        .await
        .unwrap();
    let provider = UserDetailAuthenticationProvider::new(manager, user_detail_service)
        .await
        .unwrap();

    BasicRequestAuthenticator::new(provider).map(SharedUser::from)
}

type NotesAuthorizationLayer<T> = AuthorizationLayer<
    RequestAuthorizationProvider<SharedUser>,
    fn(&Parts) -> RequestContext,
    DefaultAuthorizationFailureHandler,
    T,
>;

fn create_authorization_layer<T: AuthenticationEntryPoint>(
    authentication_entry_point: T,
) -> NotesAuthorizationLayer<T> {
    let provider = RequestAuthorizationProvider::builder()
        .method_matchers(Method::GET, "/v1/notes/1")
        .permit_all() // any user can read first note
        .method_matchers(Method::GET, "/v1/notes/{id}")
        .has_authority("ReadNote") // other notes can be read only with `ReadNote` rule
        .method_matchers(Method::DELETE, "/v1/notes/{id}")
        .has_authority("DeleteNote")
        .method_matchers(Method::PUT, "/v1/notes/{id}")
        .has_authority("ReplaceNote")
        .method_matchers(Method::POST, "/v1/notes")
        .has_authority("CreateNote")
        .any_request()
        .deny_all()
        .build()
        .expect("build authorization provider");
    AuthorizationLayer::builder(
        provider,
        request_context_mapper as fn(&Parts) -> RequestContext,
    )
    .authentication_entry_point(authentication_entry_point)
    .build()
}
