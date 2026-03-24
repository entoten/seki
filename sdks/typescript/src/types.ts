// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

export interface CreateUserInput {
  email: string;
  name?: string;
  metadata?: Record<string, unknown>;
}

export interface UpdateUserInput {
  email?: string;
  name?: string;
  disabled?: boolean;
  metadata?: Record<string, unknown>;
}

export interface CreateOrgInput {
  slug: string;
  name: string;
  domains?: string[];
  metadata?: Record<string, unknown>;
}

export interface UpdateOrgInput {
  name?: string;
  slug?: string;
  domains?: string[];
  metadata?: Record<string, unknown>;
}

export interface AddMemberInput {
  user_id: string;
  role?: string;
}

export interface UpdateMemberRoleInput {
  role: string;
}

export interface CreateRoleInput {
  name: string;
  permissions: string[];
}

export interface UpdateRoleInput {
  permissions: string[];
}

export interface CreateClientInput {
  id: string;
  name: string;
  redirect_uris?: string[];
  grant_types?: string[];
  scopes?: string[];
  pkce_required?: boolean;
}

export interface ImportUserInput {
  email: string;
  display_name?: string;
  password_hash?: string;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

export interface User {
  id: string;
  email: string;
  name: string;
  email_verified: boolean;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface Organization {
  id: string;
  slug: string;
  name: string;
  domains: string[];
  created_at: string;
  updated_at: string;
}

export interface Member {
  user_id: string;
  org_id: string;
  role: string;
  joined_at: string;
}

export interface Role {
  id: string;
  name: string;
  permissions: string[];
}

export interface OAuthClient {
  id: string;
  name: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
  pkce_required: boolean;
  created_at: string;
  updated_at: string;
}

export interface AuditEntry {
  id: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  metadata: Record<string, unknown>;
  timestamp: string;
}

export interface ImportResult {
  created: number;
  skipped: number;
  total: number;
  errors: ImportError[];
}

export interface ImportError {
  line: number;
  email: string;
  error: string;
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

export interface ListOptions {
  cursor?: string;
  limit?: number;
}

export interface ListResult<T> {
  data: T[];
  next_cursor?: string;
}

export interface AuditListOptions extends ListOptions {
  actor_id?: string;
  action?: string;
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export interface ProblemDetail {
  type: string;
  title: string;
  status: number;
  detail: string;
}
