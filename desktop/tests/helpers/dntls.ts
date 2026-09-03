import { execFileSync } from "node:child_process";

const DB_HOST = process.env.BUZZ_DB_HOST ?? "127.0.0.1";
const DB_PORT = process.env.BUZZ_DB_PORT ?? "5432";
const DB_USER = process.env.BUZZ_DB_USER ?? "buzz";
const DB_PASS = process.env.BUZZ_DB_PASS ?? "buzz_dev";
const DB_NAME = process.env.BUZZ_DB_NAME ?? "buzz";
const DB_DOCKER_CONTAINER =
  process.env.BUZZ_DB_DOCKER_CONTAINER ?? "buzz-postgres";
const COMMUNITY_HOST = process.env.BUZZ_COMMUNITY_HOST ?? "localhost:3000";

/** Mock IPC names used when joining a `.dntls` community from the desktop. */
export const DNTLS_DESKTOP_COMMANDS = {
  startConnector: "start_dntls_connector",
  credentialsStatus: "dntls_credentials_status",
  importCredentials: "import_dntls_credentials",
  removeCredentials: "remove_dntls_credentials",
} as const;

function runSql(sql: string) {
  const env = { ...process.env, PGPASSWORD: DB_PASS };
  try {
    return execFileSync(
      "psql",
      [
        "-h",
        DB_HOST,
        "-p",
        DB_PORT,
        "-U",
        DB_USER,
        "-d",
        DB_NAME,
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        sql,
      ],
      { env, encoding: "utf8" },
    );
  } catch (psqlError) {
    try {
      return execFileSync(
        "docker",
        [
          "exec",
          "-i",
          "-e",
          `PGPASSWORD=${DB_PASS}`,
          DB_DOCKER_CONTAINER,
          "psql",
          "-U",
          DB_USER,
          "-d",
          DB_NAME,
          "-v",
          "ON_ERROR_STOP=1",
          "-c",
          sql,
        ],
        { encoding: "utf8" },
      );
    } catch (dockerError) {
      const psqlMessage =
        psqlError instanceof Error ? psqlError.message : String(psqlError);
      const dockerMessage =
        dockerError instanceof Error
          ? dockerError.message
          : String(dockerError);
      throw new Error(
        `Failed to seed DNTLS row via psql (${psqlMessage}) or docker (${dockerMessage})`,
      );
    }
  }
}

/**
 * Upsert an approved DNTLS mapping for the e2e community on localhost:3000.
 * Admission happens at AUTH; the desktop only reads this table through
 * GET /api/dntls/names.
 */
export function seedApprovedDntlsName(input: {
  approvedBy: string;
  fqdn: string;
  pubkey: string;
}) {
  const host = COMMUNITY_HOST.replaceAll("'", "''");
  const pubkey = input.pubkey.replaceAll("'", "''");
  const fqdn = input.fqdn.replaceAll("'", "''");
  const approvedBy = input.approvedBy.replaceAll("'", "''");
  runSql(`
INSERT INTO dntls_applications (
  community_id, pubkey, fqdn, status, created_at, approved_at, approved_by
)
SELECT id, '${pubkey}', '${fqdn}', 'approved', now(), now(), '${approvedBy}'
FROM communities
WHERE lower(host) = lower('${host}')
ON CONFLICT (community_id, pubkey) DO UPDATE
SET fqdn = EXCLUDED.fqdn,
    status = 'approved',
    approved_at = EXCLUDED.approved_at,
    approved_by = EXCLUDED.approved_by;
`);
}

/**
 * Grant TEST_IDENTITIES membership on the e2e community so NIP-98 names
 * fetches and channel joins succeed against a membership-gated relay.
 */
export function seedDntlsDemoMembers(input: {
  channelName?: string;
  pubkeys: string[];
}) {
  const host = COMMUNITY_HOST.replaceAll("'", "''");
  const pubkeys = input.pubkeys.map((pubkey) => pubkey.replaceAll("'", "''"));
  const values = pubkeys.map((pubkey) => `('${pubkey}')`).join(", ");
  runSql(`
INSERT INTO relay_members (community_id, pubkey, role)
SELECT c.id, p.pubkey, 'member'
FROM communities c
CROSS JOIN (VALUES ${values}) AS p(pubkey)
WHERE lower(c.host) = lower('${host}')
ON CONFLICT (community_id, pubkey) DO NOTHING;
`);
  const channelName = (input.channelName ?? "dntls-demo").replaceAll("'", "''");
  runSql(`
INSERT INTO channel_members (community_id, channel_id, pubkey, role)
SELECT c.community_id, c.id, decode(p.pubkey, 'hex'), 'member'
FROM channels c
CROSS JOIN (VALUES ${values}) AS p(pubkey)
JOIN communities comm ON comm.id = c.community_id
WHERE lower(comm.host) = lower('${host}')
  AND c.name = '${channelName}'
ON CONFLICT DO NOTHING;
`);
}
