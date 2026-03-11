//! Insights and analytics handlers.

use super::*;

#[derive(Debug, Deserialize)]
pub(crate) struct InsightsDausQuery {
    #[serde(default)]
    tz_offset: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InsightsTemplatesQuery {
    start_time: Option<String>,
    end_time: Option<String>,
    #[serde(default)]
    interval: Option<String>,
    #[serde(default)]
    template_ids: Option<String>,
    #[serde(default)]
    sections: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InsightsUserActivityQuery {
    start_time: Option<String>,
    end_time: Option<String>,
    #[serde(default)]
    template_ids: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InsightsUserLatencyQuery {
    start_time: Option<String>,
    end_time: Option<String>,
    #[serde(default)]
    template_ids: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InsightsUserStatusCountsQuery {
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    tz_offset: Option<i32>,
}

pub(crate) async fn insights_daus(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<InsightsDausQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view deployment DAUs.",
        ));
    }

    let tz_offset = query.tz_offset.unwrap_or(0);
    if !(-12..=14).contains(&tz_offset) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok(
                "Invalid tz_offset: must be between -12 and 14.",
            )),
        )
            .into_response());
    }
    let response = state.store.get_deployment_daus(tz_offset).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) fn parse_template_ids(raw: &Option<String>) -> Vec<Uuid> {
    raw.as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| Uuid::from_str(s).ok())
        .collect()
}

pub(crate) fn parse_rfc3339(raw: &Option<String>) -> Option<OffsetDateTime> {
    raw.as_deref()
        .and_then(|s| OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok())
}

pub(crate) async fn insights_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<InsightsTemplatesQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view template insights.",
        ));
    }

    let start_time = match parse_rfc3339(&query.start_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "start_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let end_time = match parse_rfc3339(&query.end_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "end_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let interval = match query.interval.as_deref() {
        Some("week") => InsightsReportInterval::Week,
        None | Some("day") => InsightsReportInterval::Day,
        Some(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "interval must be 'day', 'week', or omitted.",
                )),
            )
                .into_response());
        }
    };
    let template_ids = parse_template_ids(&query.template_ids);

    let sections: Vec<TemplateInsightsSection> = query
        .sections
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.trim() {
            "interval_reports" => Some(TemplateInsightsSection::IntervalReports),
            "report" => Some(TemplateInsightsSection::Report),
            _ => None,
        })
        .collect();

    let mut response = state
        .store
        .get_template_insights(start_time, end_time, interval, template_ids)
        .await?;

    // When the client specifies explicit sections, strip the parts they did
    // not ask for.  An empty `sections` vec means "return everything".
    if !sections.is_empty() {
        if !sections.contains(&TemplateInsightsSection::Report) {
            response.report = None;
        }
        if !sections.contains(&TemplateInsightsSection::IntervalReports) {
            response.interval_reports = Vec::new();
        }
    }

    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn insights_user_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<InsightsUserActivityQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view user activity insights.",
        ));
    }

    let start_time = match parse_rfc3339(&query.start_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "start_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let end_time = match parse_rfc3339(&query.end_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "end_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let template_ids = parse_template_ids(&query.template_ids);

    let response = state
        .store
        .get_user_activity_insights(start_time, end_time, template_ids)
        .await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn insights_user_latency(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<InsightsUserLatencyQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view user latency insights.",
        ));
    }

    let start_time = match parse_rfc3339(&query.start_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "start_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let end_time = match parse_rfc3339(&query.end_time) {
        Some(t) => t,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(
                    "end_time is required and must be RFC 3339.",
                )),
            )
                .into_response());
        }
    };
    let template_ids = parse_template_ids(&query.template_ids);

    let response = state
        .store
        .get_user_latency_insights(start_time, end_time, template_ids)
        .await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn insights_user_status_counts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<InsightsUserStatusCountsQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    if !can_view_operational_data(&context.actor) {
        return Ok(forbidden_response(
            "You are not authorized to view user status counts.",
        ));
    }

    // Resolve timezone from query params, following Go's Etc/GMT±N convention.
    let timezone = match (&query.timezone, query.tz_offset) {
        (Some(tz), _) if !tz.is_empty() => tz.clone(),
        (_, Some(offset)) if !(-12..=14).contains(&offset) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok("tz_offset must be between -12 and 14.")),
            )
                .into_response());
        }
        (_, Some(offset)) if offset > 0 => format!("Etc/GMT-{offset}"),
        (_, Some(offset)) if offset < 0 => {
            let abs = offset.saturating_neg();
            format!("Etc/GMT+{abs}")
        }
        _ => "UTC".to_owned(),
    };

    // Mirror Go's 60-day window: from (next_hour_in_loc - 60 days) to next_hour_in_loc.
    let now = OffsetDateTime::now_utc();
    // Round up to the next whole hour.
    let end_time = now
        .replace_minute(0)
        .and_then(|t| t.replace_second(0))
        .and_then(|t| t.replace_nanosecond(0))
        .map(|t| t + time::Duration::hours(1))
        .unwrap_or(now);
    let start_time = end_time - time::Duration::days(60);

    let response = state
        .store
        .get_user_status_counts(&timezone, start_time, end_time)
        .await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}
