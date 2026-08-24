use axum::extract::State;
use conduwuit::{Err, Result, info};
use ruma::{UserId, api::client::profile::PropagateTo, profile::ProfileFieldValue};
use service::users::HashedPassword;
use service::users::ProfileFieldChange;
use ruminuwuity::admin::continuwuity::users;

use crate::Ruma;

const AUTO_GEN_PASSWORD_LENGTH: usize = 25;

/// # `PUT /_continuwuity/admin/v1/users/{user_id}`
///
/// Create a new local user.
pub(crate) async fn create_user(
	State(services): State<crate::State>,
	body: Ruma<users::create::v1::Request>,
) -> Result<users::create::v1::Response> {
	let sender_user = body.identity.expect_sender_user()?;
	if !services.users.is_admin(sender_user).await {
		return Err!(Request(Forbidden("Only server administrators can use this endpoint")));
	}

	let user_id = &body.user_id;

	if services.users.status(user_id).await.is_active() {
		return Err!(Conflict("User already exists"));
	}

	if !services.globals.user_is_local(user_id) {
		return Err!(Request(InvalidParam("Only local users can be created")));
	}

	let password = body.password.clone().unwrap_or_else(|| conduwuit::utils::random_string(AUTO_GEN_PASSWORD_LENGTH));

	services
		.users
		.create_local_account(user_id, Some(HashedPassword::new(&password)?), None, None, None)
		.await?;

	if let Some(ref displayname) = body.displayname {
		let _ = services
			.users
			.set_profile_field(
				user_id,
				ProfileFieldChange::Set(ProfileFieldValue::DisplayName(displayname.clone())),
				PropagateTo::None,
			)
			.await;
	}

	// First user becomes admin
	services.firstrun.empower_first_user(user_id).await;

	// Auto-join configured rooms
	for room in &services.server.config.auto_join_rooms {
		let Ok(room_id) = services.rooms.alias.resolve(room).await else {
			continue;
		};
		let _ = services.rooms.membership.join_room(user_id, &room_id, None, &[]).await;
	}

	info!(%sender_user, "Created user {user_id}");
	Ok(users::create::v1::Response::new(
		user_id.clone(),
		user_id.server_name().to_string(),
		password,
	))
}
