# SSOReady: Overview

**SSOReady** is a developer-friendly platform to add Single Sign-On (SSO) to your app. It supports modern identity standards like SAML and SCIM, and connects your app to multiple enterprise identity providers (IdPs) such as Okta, Azure AD, and Google Workspace.

## Key Concepts

- **SAML (Security Assertion Markup Language):**
  A standard protocol for SSO. Users authenticate with their organization's IdP and access your app without new credentials.

- **IdP (Identity Provider):**
  The external system (e.g., Okta, Azure AD) that authenticates users and provides identity info to your app via SSOReady.

- **SCIM (System for Cross-domain Identity Management):**
  A standard for automating user identity info exchange between IdPs and your app. SCIM enables automatic user and group provisioning/deprovisioning.

## AuthN and AuthZ Flow

- **Authentication (AuthN):**
  The process where a user proves their identity (e.g., via SAML SSO login). SSOReady handles the SAML handshake and provides authenticated user info to your app.

- **Authorization (AuthZ):**
  After authentication, your app decides what the user can access (roles, permissions). SSOReady provides identity and group info; your app enforces access control.

## Multiple IdPs & Organizations

- SSOReady lets you connect multiple organizations, each with their own IdP.
- Your app can dynamically select the correct IdP based on the user's email domain or other logic.

---

**In short:**
SSOReady simplifies SSO integration, supports SAML for authentication, SCIM for user provisioning, and lets you connect multiple IdPs for different organizations. Your app handles authorization using the identity data provided.
