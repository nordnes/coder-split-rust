//! File upload/download handlers.

use super::*;

pub(crate) const TAR_MIME_TYPE: &str = "application/x-tar";
pub(crate) const ZIP_MIME_TYPE: &str = "application/zip";
pub(crate) const WINDOWS_ZIP_MIME_TYPE: &str = "application/x-zip-compressed";

/// POST /api/v2/files – upload a binary file, deduplicate by SHA-256 hash.
pub(crate) async fn post_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can upload files.
    // In Go, postFile checks rbac.ActionCreate on rbac.ResourceFile at the
    // site level (no org/owner scoping). This intentionally differs from
    // upload_chat_file which uses .with_owner().in_org() because chat file
    // uploads are organization-scoped, while general file uploads (used for
    // template archives) are a site-level operation.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::File),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to upload files.",
        ));
    }

    let raw_content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // Strip optional parameters (e.g. "; charset=binary") before matching.
    let content_type = raw_content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();

    match content_type {
        TAR_MIME_TYPE | ZIP_MIME_TYPE | WINDOWS_ZIP_MIME_TYPE => {}
        _ => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(format!(
                    "Unsupported content type header \"{content_type}\"."
                ))),
            )
                .into_response());
        }
    }

    let data: Vec<u8> = body.to_vec();
    let mimetype = content_type.to_owned();

    // Compute SHA-256 hash of the raw bytes.
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        format!("{:x}", hasher.finalize())
    };

    let file_id = Uuid::new_v4();
    let input = InsertFileInput {
        id: file_id,
        hash,
        created_by: context.user.id,
        mimetype,
        data,
    };

    // INSERT … ON CONFLICT handles the race atomically – if a duplicate
    // exists the DB returns the existing row instead of raising an error.
    let result = state.store.insert_file(input).await?;

    // If the returned id differs from the one we generated, a duplicate
    // already existed and the DB returned the existing row.
    let status = if result.id == file_id {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    Ok((status, Json(UploadFileResponse { id: result.id })).into_response())
}

/// GET /api/v2/files/{fileid} – retrieve a file by UUID.
pub(crate) async fn get_file_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let file = state.store.get_file_by_id(file_id).await?;
    let Some(file) = file else {
        return Ok(resource_not_found_response());
    };

    let content_type = HeaderValue::from_str(&file.mimetype)
        .unwrap_or(HeaderValue::from_static("application/octet-stream"));

    let mut response_headers = HeaderMap::new();
    response_headers.insert(CONTENT_TYPE, content_type);

    Ok((StatusCode::OK, response_headers, file.data).into_response())
}
