export type {
  CreateUserInput,
  UpdateUserInput,
  CreateOrgInput,
  UpdateOrgInput,
  AddMemberInput,
  UpdateMemberRoleInput,
  CreateRoleInput,
  UpdateRoleInput,
  CreateClientInput,
  ImportUserInput,
  User,
  Organization,
  Member,
  Role,
  OAuthClient,
  AuditEntry,
  ImportResult,
  ImportError,
  ListOptions,
  ListResult,
  AuditListOptions,
  ProblemDetail,
} from "./types";

import type {
  CreateUserInput,
  UpdateUserInput,
  CreateOrgInput,
  UpdateOrgInput,
  AddMemberInput,
  UpdateMemberRoleInput,
  CreateRoleInput,
  UpdateRoleInput,
  CreateClientInput,
  ImportUserInput,
  User,
  Organization,
  Member,
  Role,
  OAuthClient,
  AuditEntry,
  ImportResult,
  ListOptions,
  ListResult,
  AuditListOptions,
  ProblemDetail,
} from "./types";

// ---------------------------------------------------------------------------
// Error class
// ---------------------------------------------------------------------------

/** API error following RFC 7807 Problem Details. */
export class SekiAPIError extends Error {
  public readonly type: string;
  public readonly title: string;
  public readonly status: number;
  public readonly detail: string;

  constructor(problem: ProblemDetail) {
    super(`${problem.title}: ${problem.detail} (HTTP ${problem.status})`);
    this.name = "SekiAPIError";
    this.type = problem.type;
    this.title = problem.title;
    this.status = problem.status;
    this.detail = problem.detail;
  }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export interface SekiClientOptions {
  /** Custom fetch implementation (defaults to globalThis.fetch). */
  fetch?: typeof globalThis.fetch;
}

export class SekiClient {
  private readonly baseURL: string;
  private readonly apiKey: string;
  private readonly fetch: typeof globalThis.fetch;

  constructor(baseURL: string, apiKey: string, opts?: SekiClientOptions) {
    this.baseURL = baseURL.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.fetch = opts?.fetch ?? globalThis.fetch.bind(globalThis);
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private async request<T>(
    method: string,
    path: string,
    opts?: { body?: unknown; query?: Record<string, string> },
  ): Promise<T> {
    let url = `${this.baseURL}${path}`;
    if (opts?.query) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined && v !== "") params.set(k, v);
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
    };
    let bodyStr: string | undefined;
    if (opts?.body !== undefined) {
      headers["Content-Type"] = "application/json";
      bodyStr = JSON.stringify(opts.body);
    }

    const resp = await this.fetch(url, { method, headers, body: bodyStr });

    if (!resp.ok) {
      let problem: ProblemDetail;
      try {
        problem = (await resp.json()) as ProblemDetail;
      } catch {
        problem = {
          type: "about:blank",
          title: resp.statusText,
          status: resp.status,
          detail: "",
        };
      }
      problem.status = resp.status;
      throw new SekiAPIError(problem);
    }

    if (resp.status === 204) return undefined as T;
    return (await resp.json()) as T;
  }

  private listQuery(opts?: ListOptions): Record<string, string> {
    const q: Record<string, string> = {};
    if (opts?.cursor) q.cursor = opts.cursor;
    if (opts?.limit) q.limit = String(opts.limit);
    return q;
  }

  // -----------------------------------------------------------------------
  // Users
  // -----------------------------------------------------------------------

  async createUser(input: CreateUserInput): Promise<User> {
    return this.request<User>("POST", "/api/v1/users", { body: input });
  }

  async getUser(id: string): Promise<User> {
    return this.request<User>("GET", `/api/v1/users/${encodeURIComponent(id)}`);
  }

  async listUsers(opts?: ListOptions): Promise<ListResult<User>> {
    return this.request<ListResult<User>>("GET", "/api/v1/users", {
      query: this.listQuery(opts),
    });
  }

  async updateUser(id: string, input: UpdateUserInput): Promise<User> {
    return this.request<User>(
      "PATCH",
      `/api/v1/users/${encodeURIComponent(id)}`,
      { body: input },
    );
  }

  async deleteUser(id: string): Promise<void> {
    return this.request<void>(
      "DELETE",
      `/api/v1/users/${encodeURIComponent(id)}`,
    );
  }

  // -----------------------------------------------------------------------
  // Organizations
  // -----------------------------------------------------------------------

  async createOrg(input: CreateOrgInput): Promise<Organization> {
    return this.request<Organization>("POST", "/api/v1/orgs", { body: input });
  }

  async getOrg(slug: string): Promise<Organization> {
    return this.request<Organization>(
      "GET",
      `/api/v1/orgs/${encodeURIComponent(slug)}`,
    );
  }

  async listOrgs(opts?: ListOptions): Promise<ListResult<Organization>> {
    return this.request<ListResult<Organization>>("GET", "/api/v1/orgs", {
      query: this.listQuery(opts),
    });
  }

  async updateOrg(
    slug: string,
    input: UpdateOrgInput,
  ): Promise<Organization> {
    return this.request<Organization>(
      "PATCH",
      `/api/v1/orgs/${encodeURIComponent(slug)}`,
      { body: input },
    );
  }

  async deleteOrg(slug: string): Promise<void> {
    return this.request<void>(
      "DELETE",
      `/api/v1/orgs/${encodeURIComponent(slug)}`,
    );
  }

  // -----------------------------------------------------------------------
  // Members
  // -----------------------------------------------------------------------

  async addMember(slug: string, input: AddMemberInput): Promise<Member> {
    return this.request<Member>(
      "POST",
      `/api/v1/orgs/${encodeURIComponent(slug)}/members`,
      { body: input },
    );
  }

  async listMembers(
    slug: string,
    opts?: ListOptions,
  ): Promise<ListResult<Member>> {
    return this.request<ListResult<Member>>(
      "GET",
      `/api/v1/orgs/${encodeURIComponent(slug)}/members`,
      { query: this.listQuery(opts) },
    );
  }

  async updateMemberRole(
    slug: string,
    userId: string,
    input: UpdateMemberRoleInput,
  ): Promise<void> {
    return this.request<void>(
      "PATCH",
      `/api/v1/orgs/${encodeURIComponent(slug)}/members/${encodeURIComponent(userId)}`,
      { body: input },
    );
  }

  async removeMember(slug: string, userId: string): Promise<void> {
    return this.request<void>(
      "DELETE",
      `/api/v1/orgs/${encodeURIComponent(slug)}/members/${encodeURIComponent(userId)}`,
    );
  }

  // -----------------------------------------------------------------------
  // Roles
  // -----------------------------------------------------------------------

  async createRole(slug: string, input: CreateRoleInput): Promise<Role> {
    return this.request<Role>(
      "POST",
      `/api/v1/orgs/${encodeURIComponent(slug)}/roles`,
      { body: input },
    );
  }

  async listRoles(slug: string): Promise<Role[]> {
    const resp = await this.request<{ data: Role[] }>(
      "GET",
      `/api/v1/orgs/${encodeURIComponent(slug)}/roles`,
    );
    return resp.data;
  }

  async updateRole(
    slug: string,
    name: string,
    input: UpdateRoleInput,
  ): Promise<Role> {
    return this.request<Role>(
      "PATCH",
      `/api/v1/orgs/${encodeURIComponent(slug)}/roles/${encodeURIComponent(name)}`,
      { body: input },
    );
  }

  async deleteRole(slug: string, name: string): Promise<void> {
    return this.request<void>(
      "DELETE",
      `/api/v1/orgs/${encodeURIComponent(slug)}/roles/${encodeURIComponent(name)}`,
    );
  }

  // -----------------------------------------------------------------------
  // Audit logs
  // -----------------------------------------------------------------------

  async listAuditLogs(
    opts?: AuditListOptions,
  ): Promise<ListResult<AuditEntry>> {
    const q = this.listQuery(opts);
    if (opts?.actor_id) q.actor_id = opts.actor_id;
    if (opts?.action) q.action = opts.action;
    return this.request<ListResult<AuditEntry>>("GET", "/api/v1/audit-logs", {
      query: q,
    });
  }

  // -----------------------------------------------------------------------
  // OAuth clients
  // -----------------------------------------------------------------------

  async createClient(input: CreateClientInput): Promise<OAuthClient> {
    return this.request<OAuthClient>("POST", "/api/v1/clients", {
      body: input,
    });
  }

  async getClient(id: string): Promise<OAuthClient> {
    return this.request<OAuthClient>(
      "GET",
      `/api/v1/clients/${encodeURIComponent(id)}`,
    );
  }

  async listClients(): Promise<OAuthClient[]> {
    const resp = await this.request<{ data: OAuthClient[] }>(
      "GET",
      "/api/v1/clients",
    );
    return resp.data;
  }

  async deleteClient(id: string): Promise<void> {
    return this.request<void>(
      "DELETE",
      `/api/v1/clients/${encodeURIComponent(id)}`,
    );
  }

  // -----------------------------------------------------------------------
  // Import
  // -----------------------------------------------------------------------

  async importUsers(users: ImportUserInput[]): Promise<ImportResult> {
    return this.request<ImportResult>("POST", "/api/v1/import/users", {
      body: users,
    });
  }
}
