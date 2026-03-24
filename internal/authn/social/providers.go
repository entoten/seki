package social

import "fmt"

// parseProviderUser extracts user profile fields from the provider's userinfo
// response. Each provider returns data in a different shape.
func parseProviderUser(providerName string, data map[string]interface{}, user *SocialUser) {
	switch providerName {
	case "google":
		user.ProviderID = stringFromMap(data, "sub")
		user.Email = stringFromMap(data, "email")
		user.Name = stringFromMap(data, "name")
		user.AvatarURL = stringFromMap(data, "picture")

	case "microsoft":
		user.ProviderID = stringFromMap(data, "id")
		user.Email = stringFromMap(data, "mail")
		if user.Email == "" {
			user.Email = stringFromMap(data, "userPrincipalName")
		}
		user.Name = stringFromMap(data, "displayName")

	case "apple":
		// Apple returns info in the ID token (parsed during exchange).
		// The userinfo endpoint is not used; data may come from the ID token claims.
		user.ProviderID = stringFromMap(data, "sub")
		user.Email = stringFromMap(data, "email")
		// Apple sends name only on the first sign-in via the form_post response.
		if nameObj, ok := data["name"].(map[string]interface{}); ok {
			first := stringFromMap(nameObj, "firstName")
			last := stringFromMap(nameObj, "lastName")
			user.Name = joinNonEmpty(first, last)
		}

	case "github":
		user.ProviderID = numericIDFromMap(data, "id")
		user.Email = stringFromMap(data, "email")
		user.Name = stringFromMap(data, "name")
		if user.Name == "" {
			user.Name = stringFromMap(data, "login")
		}
		user.AvatarURL = stringFromMap(data, "avatar_url")

	case "gitlab":
		user.ProviderID = numericIDFromMap(data, "id")
		user.Email = stringFromMap(data, "email")
		user.Name = stringFromMap(data, "name")
		if user.Name == "" {
			user.Name = stringFromMap(data, "username")
		}
		user.AvatarURL = stringFromMap(data, "avatar_url")

	case "bitbucket":
		user.ProviderID = stringFromMap(data, "uuid")
		user.Name = stringFromMap(data, "display_name")
		if user.Name == "" {
			user.Name = stringFromMap(data, "username")
		}
		// Bitbucket requires a separate API call for email; fallback to links.
		if links, ok := data["links"].(map[string]interface{}); ok {
			if avatar, ok := links["avatar"].(map[string]interface{}); ok {
				user.AvatarURL = stringFromMap(avatar, "href")
			}
		}

	case "discord":
		user.ProviderID = stringFromMap(data, "id")
		user.Email = stringFromMap(data, "email")
		user.Name = stringFromMap(data, "global_name")
		if user.Name == "" {
			user.Name = stringFromMap(data, "username")
		}
		if avatar := stringFromMap(data, "avatar"); avatar != "" {
			user.AvatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", user.ProviderID, avatar)
		}

	case "slack":
		user.ProviderID = stringFromMap(data, "sub")
		user.Email = stringFromMap(data, "email")
		user.Name = stringFromMap(data, "name")
		user.AvatarURL = stringFromMap(data, "picture")

	case "twitter":
		if d, ok := data["data"].(map[string]interface{}); ok {
			user.ProviderID = stringFromMap(d, "id")
			user.Name = stringFromMap(d, "name")
			if user.Name == "" {
				user.Name = stringFromMap(d, "username")
			}
			user.AvatarURL = stringFromMap(d, "profile_image_url")
		}
		// Twitter doesn't return email via users/me by default.

	case "facebook":
		user.ProviderID = stringFromMap(data, "id")
		user.Email = stringFromMap(data, "email")
		user.Name = stringFromMap(data, "name")
		if pic, ok := data["picture"].(map[string]interface{}); ok {
			if picData, ok := pic["data"].(map[string]interface{}); ok {
				user.AvatarURL = stringFromMap(picData, "url")
			}
		}

	case "line":
		user.ProviderID = stringFromMap(data, "userId")
		user.Name = stringFromMap(data, "displayName")
		user.AvatarURL = stringFromMap(data, "pictureUrl")
		// LINE requires the email scope + OIDC ID token for email.

	case "linkedin":
		user.ProviderID = stringFromMap(data, "sub")
		user.Email = stringFromMap(data, "email")
		user.Name = stringFromMap(data, "name")
		user.AvatarURL = stringFromMap(data, "picture")

	case "amazon":
		user.ProviderID = stringFromMap(data, "user_id")
		user.Email = stringFromMap(data, "email")
		user.Name = stringFromMap(data, "name")

	default:
		// Generic OIDC-style fallback.
		user.ProviderID = stringFromMap(data, "sub")
		if user.ProviderID == "" {
			user.ProviderID = stringFromMap(data, "id")
		}
		user.Email = stringFromMap(data, "email")
		user.Name = stringFromMap(data, "name")
		user.AvatarURL = stringFromMap(data, "picture")
	}
}

// numericIDFromMap extracts a numeric ID as a string.
func numericIDFromMap(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch id := v.(type) {
	case float64:
		return fmt.Sprintf("%.0f", id)
	case string:
		return id
	default:
		return fmt.Sprintf("%v", id)
	}
}

// joinNonEmpty joins non-empty strings with a space.
func joinNonEmpty(parts ...string) string {
	result := ""
	for _, p := range parts {
		if p != "" {
			if result != "" {
				result += " "
			}
			result += p
		}
	}
	return result
}
