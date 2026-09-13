import { createClient, type Client, type InValue, type Row } from "@libsql/client";
import { BlobNotFoundError, del, get, head, put } from "@vercel/blob";

export type DatabaseResult<T = Record<string, unknown>> = {
  results: T[];
  success: true;
  meta: { changes: number };
};

export class PreparedStatement {
  constructor(public readonly sql: string, public readonly args: InValue[] = []) {}

  bind(...args: unknown[]) {
    return new PreparedStatement(this.sql, args.map(toDatabaseValue));
  }

  async all<T = Record<string, unknown>>(): Promise<DatabaseResult<T>> {
    return result<T>(await databaseClient().execute({ sql: this.sql, args: this.args }));
  }

  async first<T = Record<string, unknown>>(): Promise<T | null> {
    const response = await databaseClient().execute({ sql: this.sql, args: this.args });
    return (response.rows[0] as T | undefined) ?? null;
  }

  async run(): Promise<DatabaseResult> {
    return result(await databaseClient().execute({ sql: this.sql, args: this.args }));
  }
}

function toDatabaseValue(value: unknown): InValue {
  if (value === undefined) return null;
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "bigint" || typeof value === "boolean" || value instanceof Uint8Array || value instanceof Date) return value;
  throw new TypeError("Unsupported database parameter type");
}

export type WhisperDatabase = {
  prepare(sql: string): PreparedStatement;
  batch(statements: PreparedStatement[]): Promise<DatabaseResult[]>;
};

let client: Client | null = null;

function databaseClient() {
  if (client) return client;
  const url = process.env.TURSO_DATABASE_URL?.trim();
  const authToken = process.env.TURSO_AUTH_TOKEN?.trim();
  if (!url) throw new Error("TURSO_DATABASE_URL is not configured");
  client = createClient({ url, authToken });
  return client;
}

function result<T>(response: { rows: Row[]; rowsAffected: number }): DatabaseResult<T> {
  return {
    results: response.rows as T[],
    success: true,
    meta: { changes: response.rowsAffected },
  };
}

export const whisperDatabase: WhisperDatabase = {
  prepare: (sql) => new PreparedStatement(sql),
  async batch(statements) {
    const responses = await databaseClient().batch(
      statements.map(({ sql, args }) => ({ sql, args })),
      "write",
    );
    return responses.map((response) => result(response));
  },
};

export const encryptedMediaStore = {
  async put(pathname: string, body: ReadableStream, metadata?: unknown) {
    void metadata;
    return put(pathname, body, {
      access: "private",
      addRandomSuffix: false,
      allowOverwrite: false,
      contentType: "application/octet-stream",
      cacheControlMaxAge: 60,
    });
  },

  async get(pathname: string) {
    const object = await get(pathname, { access: "private", useCache: false });
    if (!object || object.statusCode !== 200) return null;
    return { body: object.stream, size: object.blob.size };
  },

  async head(pathname: string) {
    try {
      const object = await head(pathname);
      return { size: object.size };
    } catch (error) {
      if (error instanceof BlobNotFoundError) return null;
      throw error;
    }
  },

  async delete(pathname: string) {
    await del(pathname);
  },
};
