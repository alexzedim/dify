# Keycloak Authentication Integration for Dify

This implementation adds Keycloak authentication support to Dify, allowing users to log in using their Keycloak credentials if they have a matching account in Dify.

## Overview

The Keycloak authentication integration consists of:

1. **Backend API endpoint** (`/console/api/keycloak/login`) that handles username/password authentication
2. **Frontend React component** that provides the Keycloak login interface
3. **Configuration system** that enables/disables Keycloak authentication based on environment variables

## How It Works

1. **User Authentication Flow**:
   - User enters Keycloak username/email and password in the frontend form
   - Frontend sends POST request to `/console/api/keycloak/login` endpoint
   - Backend authenticates with Keycloak using the Resource Owner Password Credentials flow
   - Backend retrieves user information from Keycloak userinfo endpoint
   - Backend finds matching Dify user by email address
   - Backend generates Dify session tokens if user is found and returns them

2. **User Matching Logic**:
   - Primary matching: Keycloak email matches Dify user email
   - Fallback matching: If username contains "@", try matching as email
   - **Security**: Only users with exact email matches can authenticate

## Configuration

Add the following environment variables to your `.env` file:

```bash
# Keycloak Authentication configuration
# Set KEYCLOAK_ENABLED=true to enable Keycloak authentication
KEYCLOAK_ENABLED=true
KEYCLOAK_AUTH_SERVER_URL=http://localhost:8080/auth
KEYCLOAK_REALM=your-realm-name
KEYCLOAK_CLIENT_ID=dify-app
KEYCLOAK_CLIENT_SECRET=your-client-secret
```

### Keycloak Client Configuration

In your Keycloak realm, create a confidential client with the following settings:

1. **Client ID**: `dify-app` (or your preferred client ID)
2. **Client Protocol**: `openid-connect`
3. **Access Type**: `confidential`
4. **Standard Flow Enabled**: `ON`
5. **Direct Access Grants Enabled**: `ON` (required for password flow)
6. **Valid Redirect URIs**: Add your Dify console URL (e.g., `http://localhost:3000/*`)

## Files Modified/Created

### Backend (API)
- `api/configs/feature/__init__.py` - Added Keycloak configuration fields
- `api/services/keycloak_auth_service.py` - New service for Keycloak authentication
- `api/controllers/console/auth/oauth.py` - Added Keycloak auth endpoint
- `api/services/feature_service.py` - Added enable_keycloak_auth feature flag
- `api/.env.example` - Added Keycloak configuration examples

### Frontend (Web)
- `web/types/feature.ts` - Added enable_keycloak_auth to SystemFeatures type
- `web/app/signin/components/keycloak-auth.tsx` - New React component for Keycloak auth
- `web/app/signin/assets/keycloak.svg` - Keycloak icon
- `web/app/signin/page.module.css` - CSS for Keycloak icon
- `web/app/signin/normalForm.tsx` - Updated to include Keycloak auth component
- `web/i18n/en-US/login.ts` - Added Keycloak-related translations

## Security Considerations

1. **User Matching**: Only users with exactly matching email addresses between Keycloak and Dify can authenticate
2. **Password Flow**: Uses OAuth2 Resource Owner Password Credentials flow (requires HTTPS in production)
3. **SSL Verification**: Currently disabled for development - **MUST** be enabled in production
4. **Client Secret**: Keep the Keycloak client secret secure and use environment variables

## API Endpoint

### POST `/console/api/keycloak/login`

**Request Body:**
```json
{
  "username": "user@example.com",
  "password": "userpassword"
}
```

**Success Response:**
```json
{
  "access_token": "dify_access_token",
  "refresh_token": "dify_refresh_token",
  "keycloak_tokens": {
    "access_token": "keycloak_access_token",
    "refresh_token": "keycloak_refresh_token",
    "expires_in": 300
  },
  "keycloak_user": {
    "id": "keycloak_user_id",
    "username": "username",
    "email": "user@example.com",
    "first_name": "First",
    "last_name": "Last",
    "roles": ["user"]
  },
  "user": {
    "id": "dify_user_id",
    "email": "user@example.com",
    "name": "User Name"
  }
}
```

**Error Response:**
```json
{
  "error": "Error message describing the authentication failure"
}
```

## Frontend Component

The `KeycloakAuth` component provides:
- Initially shows a "Continue with Keycloak" button
- When clicked, expands to show username/password form
- Handles form submission and error display
- Redirects to `/apps` on successful authentication
- Includes loading states and proper error handling

## Usage

1. Configure your Keycloak server and client
2. Set the required environment variables in your `.env` file
3. Ensure Dify users exist with matching email addresses as your Keycloak users
4. Start your Dify application
5. The Keycloak login option will appear on the signin page if properly configured

## Troubleshooting

1. **Keycloak login button not showing**: Check that all required environment variables are set
2. **Authentication fails**: Verify Keycloak client configuration and credentials
3. **User not found**: Ensure the Keycloak user's email matches a Dify user's email exactly
4. **SSL errors**: For production, ensure proper SSL certificates are configured

## Production Considerations

1. **Enable SSL verification** in the Keycloak service (`verify=True`)
2. **Use HTTPS** for all communications
3. **Secure client secrets** using proper secret management
4. **Monitor authentication logs** for security issues
5. **Consider using Authorization Code flow** instead of password flow for better security

This implementation provides a secure way to integrate Keycloak authentication while maintaining Dify's existing user management system.
